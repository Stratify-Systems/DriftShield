package baseline

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/scanner"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func newEC2Client(ctx context.Context) (*ec2.Client, error) {
	region := config.GetRegion()
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return ec2.NewFromConfig(cfg), nil
}

// LoadEC2Baseline loads the EC2 baseline from disk.
func LoadEC2Baseline() (*types.EC2Baseline, error) {
	return LoadBaseline[types.EC2Baseline](config.EC2BaselineFile)
}

// SaveEC2Baseline saves the EC2 baseline to disk.
func SaveEC2Baseline(bl *types.EC2Baseline) error {
	return SaveBaseline(config.EC2BaselineFile, bl)
}

// CreateEC2Baseline creates a baseline from current security group configurations.
func CreateEC2Baseline(ctx context.Context) (*types.EC2Baseline, error) {
	client, err := newEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	region := config.GetRegion()

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	now := time.Now().Format(time.RFC3339)
	bl := &types.EC2Baseline{
		CreatedAt:      now,
		UpdatedAt:      now,
		Region:         region,
		SecurityGroups: make(map[string]types.SGConfig),
	}

	fmt.Printf("Creating EC2 baseline for region: %s\n\n", region)

	for _, sg := range out.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)
		fmt.Printf("  Capturing: %s (%s)\n", sgName, sgID)
		bl.SecurityGroups[sgID] = scanner.GetSecurityGroupConfig(sg)
	}

	if err := SaveEC2Baseline(bl); err != nil {
		return nil, fmt.Errorf("failed to save EC2 baseline: %w", err)
	}

	fmt.Printf("\nEC2 Baseline saved to %s\n", config.EC2BaselineFile)
	fmt.Printf("  %d security group(s) captured\n", len(out.SecurityGroups))
	return bl, nil
}

// ruleKey creates a comparable key for an inbound rule (for sorting/diff).
func ruleKey(r types.InboundRule) string {
	src := make([]string, len(r.Sources))
	copy(src, r.Sources)
	sort.Strings(src)
	return fmt.Sprintf("%s|%d|%d|%v", r.Protocol, r.FromPort, r.ToPort, src)
}

// CompareEC2WithBaseline compares current security groups against baseline.
func CompareEC2WithBaseline(ctx context.Context) ([]types.EC2Drift, error) {
	bl, err := LoadEC2Baseline()
	if err != nil {
		return nil, err
	}
	if bl == nil {
		fmt.Println("[WARNING] No EC2 baseline found. Run with 'ec2 baseline' command first.")
		return nil, nil
	}

	currentRegion := config.GetRegion()
	if bl.Region != "" && bl.Region != currentRegion {
		return nil, fmt.Errorf(
			"[ERROR] Region mismatch: baseline was captured in %q but current region is %q.\n"+
				"  Re-run 'driftshield ec2 baseline' in region %q, or pass -r %s to use the baseline region",
			bl.Region, currentRegion, currentRegion, bl.Region,
		)
	}

	client, err := newEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	region := config.GetRegion()

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	fmt.Printf("Comparing against EC2 baseline (region: %s)...\n\n", region)
	fmt.Printf("  Baseline created: %s\n", bl.CreatedAt)
	fmt.Printf("  Baseline region: %s\n\n", bl.Region)

	drifts := make([]types.EC2Drift, 0)

	for _, sg := range out.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)
		display := fmt.Sprintf("%s (%s)", sgName, sgID)

		currentCfg := scanner.GetSecurityGroupConfig(sg)
		blCfg, exists := bl.SecurityGroups[sgID]

		if !exists {
			drifts = append(drifts, types.EC2Drift{
				SecurityGroup: sgID, Name: sgName, Type: "NEW_SECURITY_GROUP",
				Message: "Security group not in baseline (newly created)",
				Current: &currentCfg,
			})
			fmt.Printf("[NEW]      %s\n", display)
			continue
		}

		// Compare rules
		currentKeys := make(map[string]bool)
		for _, r := range currentCfg.InboundRules {
			currentKeys[ruleKey(r)] = true
		}
		baselineKeys := make(map[string]bool)
		for _, r := range blCfg.InboundRules {
			baselineKeys[ruleKey(r)] = true
		}

		var added, removed []types.InboundRule
		for _, r := range currentCfg.InboundRules {
			if !baselineKeys[ruleKey(r)] {
				added = append(added, r)
			}
		}
		for _, r := range blCfg.InboundRules {
			if !currentKeys[ruleKey(r)] {
				removed = append(removed, r)
			}
		}

		if len(added) > 0 || len(removed) > 0 {
			drifts = append(drifts, types.EC2Drift{
				SecurityGroup: sgID, Name: sgName, Type: "RULES_CHANGED",
				Message:    "Inbound rules changed",
				AddedRules: added, RemovedRules: removed,
				Current: &currentCfg, Baseline: &blCfg,
			})
			fmt.Printf("[DRIFT]    %s\n", display)
			if len(added) > 0 {
				fmt.Printf("           + %d rule(s) added\n", len(added))
			}
			if len(removed) > 0 {
				fmt.Printf("           - %d rule(s) removed\n", len(removed))
			}
		} else {
			fmt.Printf("[OK]       %s\n", display)
		}
	}

	// Deleted security groups
	currentIDs := make(map[string]bool)
	for _, sg := range out.SecurityGroups {
		currentIDs[aws.ToString(sg.GroupId)] = true
	}
	for blID, blCfg := range bl.SecurityGroups {
		if !currentIDs[blID] {
			drifts = append(drifts, types.EC2Drift{
				SecurityGroup: blID, Name: blCfg.GroupName, Type: "SECURITY_GROUP_DELETED",
				Message: "Security group was deleted", Baseline: &blCfg,
			})
			fmt.Printf("[DELETED]  %s (%s)\n", blCfg.GroupName, blID)
		}
	}

	return drifts, nil
}
