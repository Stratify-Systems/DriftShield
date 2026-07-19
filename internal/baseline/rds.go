package baseline

import (
	"context"
	"fmt"
	"github.com/SuryaTK2007/DriftShield/internal/display"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/scanner"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func newRDSClient(ctx context.Context) (*rds.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(config.GetRegion()))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return rds.NewFromConfig(cfg), nil
}

// LoadRDSBaseline loads the RDS baseline from disk.
func LoadRDSBaseline() (*types.RDSBaseline, error) {
	return LoadBaseline[types.RDSBaseline](config.RDSBaselineFile)
}

// SaveRDSBaseline saves the RDS baseline to disk.
func SaveRDSBaseline(bl *types.RDSBaseline) error {
	return SaveBaseline(config.RDSBaselineFile, bl)
}

// CreateRDSBaseline snapshots the current RDS instance configurations.
func CreateRDSBaseline(ctx context.Context) (*types.RDSBaseline, error) {
	now := time.Now().Format(time.RFC3339)
	region := config.GetRegion()
	bl := &types.RDSBaseline{
		CreatedAt: now,
		UpdatedAt: now,
		Region:    region,
		Instances: make(map[string]types.RDSInstanceSnapshot),
	}

	snapshots, err := scanner.GetRDSSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	bl.Instances = snapshots

	if err := SaveRDSBaseline(bl); err != nil {
		return nil, fmt.Errorf("failed to save RDS baseline: %w", err)
	}

	fmt.Printf("Creating RDS baseline for region: %s\n", region)
	fmt.Printf("\nRDS baseline saved to %s\n", config.RDSBaselineFile)
	fmt.Printf("  %d instance(s) captured\n", len(bl.Instances))
	return bl, nil
}

// CompareRDSWithBaseline compares current RDS configs against the baseline.
// Returns (drifts, baselineExists, error).
func CompareRDSWithBaseline(ctx context.Context) ([]types.RDSDrift, bool, error) {
	bl, err := LoadRDSBaseline()
	if err != nil {
		return nil, false, err
	}
	if bl == nil {
		return nil, false, nil
	}

	currentRegion := config.GetRegion()
	if bl.Region != "" && bl.Region != currentRegion {
		return nil, false, fmt.Errorf(
			"[ERROR] Region mismatch: baseline was captured in %q but current region is %q.\n"+
				"  Re-run 'driftshield rds baseline' in region %q, or pass -r %s to use the baseline region",
			bl.Region, currentRegion, currentRegion, bl.Region,
		)
	}

	fmt.Printf("Comparing against RDS baseline...\n\n")
	fmt.Printf("  Baseline created: %s\n", bl.CreatedAt)
	fmt.Printf("  Baseline region:  %s\n\n", bl.Region)

	current, err := scanner.GetRDSSnapshot(ctx)
	if err != nil {
		return nil, true, err
	}

	var drifts []types.RDSDrift

	for id, snap := range current {
		blSnap, exists := bl.Instances[id]
		if !exists {
			drifts = append(drifts, types.RDSDrift{
				Type: "INSTANCE_ADDED", InstanceID: id,
				Message: fmt.Sprintf("Instance '%s' was added since baseline", id),
			})
			fmt.Printf(display.DRIFT()+"Instance '%s' added\n", id)
			continue
		}

		drifted := false

		if snap.PubliclyAccessible != blSnap.PubliclyAccessible {
			drifts = append(drifts, types.RDSDrift{
				Type: "PUBLIC_ACCESS_CHANGED", InstanceID: id,
				Message:  fmt.Sprintf("Instance '%s' publicly accessible changed", id),
				OldValue: fmt.Sprintf("%v", blSnap.PubliclyAccessible),
				NewValue: fmt.Sprintf("%v", snap.PubliclyAccessible),
			})
			fmt.Printf(display.DRIFT()+"'%s' publicly accessible: %v -> %v\n", id, blSnap.PubliclyAccessible, snap.PubliclyAccessible)
			drifted = true
		}

		if snap.StorageEncrypted != blSnap.StorageEncrypted {
			drifts = append(drifts, types.RDSDrift{
				Type: "ENCRYPTION_CHANGED", InstanceID: id,
				Message:  fmt.Sprintf("Instance '%s' storage encryption changed", id),
				OldValue: fmt.Sprintf("%v", blSnap.StorageEncrypted),
				NewValue: fmt.Sprintf("%v", snap.StorageEncrypted),
			})
			fmt.Printf(display.DRIFT()+"'%s' storage encrypted: %v -> %v\n", id, blSnap.StorageEncrypted, snap.StorageEncrypted)
			drifted = true
		}

		if snap.DeletionProtection != blSnap.DeletionProtection {
			drifts = append(drifts, types.RDSDrift{
				Type: "DELETION_PROTECTION_CHANGED", InstanceID: id,
				Message:  fmt.Sprintf("Instance '%s' deletion protection changed", id),
				OldValue: fmt.Sprintf("%v", blSnap.DeletionProtection),
				NewValue: fmt.Sprintf("%v", snap.DeletionProtection),
			})
			fmt.Printf(display.DRIFT()+"'%s' deletion protection: %v -> %v\n", id, blSnap.DeletionProtection, snap.DeletionProtection)
			drifted = true
		}

		if snap.MultiAZ != blSnap.MultiAZ {
			drifts = append(drifts, types.RDSDrift{
				Type: "MULTI_AZ_CHANGED", InstanceID: id,
				Message:  fmt.Sprintf("Instance '%s' Multi-AZ setting changed", id),
				OldValue: fmt.Sprintf("%v", blSnap.MultiAZ),
				NewValue: fmt.Sprintf("%v", snap.MultiAZ),
			})
			fmt.Printf(display.DRIFT()+"'%s' Multi-AZ: %v -> %v\n", id, blSnap.MultiAZ, snap.MultiAZ)
			drifted = true
		}

		if snap.AutoMinorUpgrade != blSnap.AutoMinorUpgrade {
			drifts = append(drifts, types.RDSDrift{
				Type: "AUTO_MINOR_UPGRADE_CHANGED", InstanceID: id,
				Message:  fmt.Sprintf("Instance '%s' auto minor version upgrade changed", id),
				OldValue: fmt.Sprintf("%v", blSnap.AutoMinorUpgrade),
				NewValue: fmt.Sprintf("%v", snap.AutoMinorUpgrade),
			})
			fmt.Printf(display.DRIFT()+"'%s' auto minor upgrade: %v -> %v\n", id, blSnap.AutoMinorUpgrade, snap.AutoMinorUpgrade)
			drifted = true
		}

		if !drifted {
			fmt.Printf(display.OK()+"Instance '%s' unchanged\n", id)
		}
	}

	for id := range bl.Instances {
		if _, exists := current[id]; !exists {
			drifts = append(drifts, types.RDSDrift{
				Type: "INSTANCE_DELETED", InstanceID: id,
				Message: fmt.Sprintf("Instance '%s' was deleted since baseline", id),
			})
			fmt.Printf(display.DRIFT()+"Instance '%s' deleted\n", id)
		}
	}

	return drifts, true, nil
}

// RemediateRDSDrift restores drifted RDS instance settings back to baseline.
func RemediateRDSDrift(ctx context.Context, drifts []types.RDSDrift) (*types.RemediationResults, error) {
	bl, err := LoadRDSBaseline()
	if err != nil || bl == nil {
		return nil, fmt.Errorf("failed to load RDS baseline")
	}

	client, err := newRDSClient(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.RemediationResults{}

	for _, drift := range drifts {
		blSnap, ok := bl.Instances[drift.InstanceID]
		if !ok {
			res.Skipped = append(res.Skipped, types.RemediationItem{
				Name: drift.InstanceID, Type: drift.Type, Reason: "Not in baseline",
			})
			continue
		}

		switch drift.Type {
		case "PUBLIC_ACCESS_CHANGED", "DELETION_PROTECTION_CHANGED", "AUTO_MINOR_UPGRADE_CHANGED":
			input := &rds.ModifyDBInstanceInput{
				DBInstanceIdentifier: aws.String(drift.InstanceID),
				ApplyImmediately:     aws.Bool(true),
			}
			switch drift.Type {
			case "PUBLIC_ACCESS_CHANGED":
				input.PubliclyAccessible = aws.Bool(blSnap.PubliclyAccessible)
			case "DELETION_PROTECTION_CHANGED":
				input.DeletionProtection = aws.Bool(blSnap.DeletionProtection)
			case "AUTO_MINOR_UPGRADE_CHANGED":
				input.AutoMinorVersionUpgrade = aws.Bool(blSnap.AutoMinorUpgrade)
			}
			_, fErr := client.ModifyDBInstance(ctx, input)
			if fErr != nil {
				fmt.Printf(display.FAILED()+"Instance '%s' — could not restore %s: %v\n", drift.InstanceID, drift.Type, fErr)
				res.Failed = append(res.Failed, types.RemediationItem{Name: drift.InstanceID, Type: drift.Type, Error: fErr.Error()})
			} else {
				fmt.Printf(display.FIXED()+"Instance '%s' — %s restored to %s\n", drift.InstanceID, drift.Type, drift.OldValue)
				res.Fixed = append(res.Fixed, types.RemediationItem{Name: drift.InstanceID, Type: drift.Type})
			}

		default:
			msg := "Modifying Encryption, Multi-AZ, or Adding/Deleting instances requires complex orchestration (e.g., snapshot & restore) and is therefore skipped to prevent database downtime. Please resolve manually or update the baseline."
			fmt.Printf(display.SKIP()+"Instance '%s' — drift type '%s'\n          %s\n", drift.InstanceID, drift.Type, msg)
			res.Skipped = append(res.Skipped, types.RemediationItem{
				Name: drift.InstanceID, Type: drift.Type, Reason: msg,
			})
		}
	}

	return res, nil
}
