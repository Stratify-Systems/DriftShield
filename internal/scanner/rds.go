package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

var defaultMasterUsernames = map[string]bool{
	"admin": true, "root": true, "master": true,
	"postgres": true, "mysql": true, "oracle": true,
	"sa": true, "dbadmin": true, "administrator": true,
}

func newRDSClient(ctx context.Context) (*rds.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(config.GetRegion()))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return rds.NewFromConfig(cfg), nil
}

// ScanRDS scans all RDS instances for security misconfigurations.
func ScanRDS(ctx context.Context) (*types.RDSScanResults, error) {
	client, err := newRDSClient(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.RDSScanResults{}
	fmt.Printf("Region: %s\n\n", config.GetRegion())

	out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe RDS instances: %w", err)
	}

	fmt.Printf("Found %d RDS instance(s)\n\n", len(out.DBInstances))

	for _, db := range out.DBInstances {
		id := aws.ToString(db.DBInstanceIdentifier)
		instanceFindings := 0

		if aws.ToBool(db.PubliclyAccessible) {
			res.Findings = append(res.Findings, types.RDSFinding{
				Type: "PUBLICLY_ACCESSIBLE", Severity: "HIGH", InstanceID: id,
				Message: fmt.Sprintf("Instance '%s' is publicly accessible", id),
			})
			fmt.Printf("[HIGH]     %s — publicly accessible\n", id)
			instanceFindings++
		}

		if !aws.ToBool(db.StorageEncrypted) {
			res.Findings = append(res.Findings, types.RDSFinding{
				Type: "STORAGE_NOT_ENCRYPTED", Severity: "HIGH", InstanceID: id,
				Message: fmt.Sprintf("Instance '%s' storage is not encrypted", id),
			})
			fmt.Printf("[HIGH]     %s — storage not encrypted\n", id)
			instanceFindings++
		}

		if !aws.ToBool(db.DeletionProtection) {
			res.Findings = append(res.Findings, types.RDSFinding{
				Type: "DELETION_PROTECTION_DISABLED", Severity: "MEDIUM", InstanceID: id,
				Message: fmt.Sprintf("Instance '%s' has deletion protection disabled", id),
			})
			fmt.Printf("[MEDIUM]   %s — deletion protection disabled\n", id)
			instanceFindings++
		}

		masterUser := aws.ToString(db.MasterUsername)
		if defaultMasterUsernames[masterUser] {
			res.Findings = append(res.Findings, types.RDSFinding{
				Type: "DEFAULT_MASTER_USERNAME", Severity: "MEDIUM", InstanceID: id,
				Message: fmt.Sprintf("Instance '%s' uses default master username '%s'", id, masterUser),
			})
			fmt.Printf("[MEDIUM]   %s — default master username '%s'\n", id, masterUser)
			instanceFindings++
		}

		if instanceFindings == 0 {
			fmt.Printf("[SECURE]   %s\n", id)
		}
	}

	return res, nil
}

// GetRDSSnapshot returns a snapshot of all RDS instances for baseline use.
func GetRDSSnapshot(ctx context.Context) (map[string]types.RDSInstanceSnapshot, error) {
	client, err := newRDSClient(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe RDS instances: %w", err)
	}

	snapshots := make(map[string]types.RDSInstanceSnapshot)
	for _, db := range out.DBInstances {
		id := aws.ToString(db.DBInstanceIdentifier)
		snapshots[id] = types.RDSInstanceSnapshot{
			InstanceID:         id,
			Engine:             aws.ToString(db.Engine),
			PubliclyAccessible: aws.ToBool(db.PubliclyAccessible),
			StorageEncrypted:   aws.ToBool(db.StorageEncrypted),
			DeletionProtection: aws.ToBool(db.DeletionProtection),
			MasterUsername:     aws.ToString(db.MasterUsername),
			MultiAZ:            aws.ToBool(db.MultiAZ),
			AutoMinorUpgrade:   aws.ToBool(db.AutoMinorVersionUpgrade),
		}
		fmt.Printf("  Captured: %s (%s)\n", id, aws.ToString(db.Engine))
	}

	return snapshots, nil
}
