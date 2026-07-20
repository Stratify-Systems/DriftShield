package baseline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/SuryaTK2007/DriftShield/internal/display"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

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
		displayStr := fmt.Sprintf("%s (%s)", sgName, sgID)

		currentCfg := scanner.GetSecurityGroupConfig(sg)
		blCfg, exists := bl.SecurityGroups[sgID]

		if !exists {
			drifts = append(drifts, types.EC2Drift{
				SecurityGroup: sgID, Name: sgName, Type: "NEW_SECURITY_GROUP",
				Message: "Security group not in baseline (newly created)",
				Current: &currentCfg,
			})
			fmt.Printf(display.NEW()+"%s\n", displayStr)
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
			fmt.Printf(display.DRIFT()+"%s\n", displayStr)
			if len(added) > 0 {
				fmt.Printf("           + %d rule(s) added\n", len(added))
			}
			if len(removed) > 0 {
				fmt.Printf("           - %d rule(s) removed\n", len(removed))
			}
		} else {
			fmt.Printf(display.OK()+"%s\n", displayStr)
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
			fmt.Printf(display.DELETED()+"%s (%s)\n", blCfg.GroupName, blID)
		}
	}

	return drifts, nil
}

// RemediateEC2Drift reverts the actual EC2 security groups back to the state defined in the baseline.
func RemediateEC2Drift(ctx context.Context, drifts []types.EC2Drift, dryRun bool) (*types.RemediationResults, error) {
	if len(drifts) == 0 {
		fmt.Println(display.INFO() + "No drifts to remediate.")
		return &types.RemediationResults{}, nil
	}

	client, err := newEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.RemediationResults{}
	fmt.Println("Starting remediation...")

	for _, d := range drifts {
		sgID := d.SecurityGroup
		sgName := d.Name

		if d.Type == "NEW_SECURITY_GROUP" || d.Type == "SECURITY_GROUP_DELETED" {
			msg := "Creating or deleting security groups is skipped to prevent accidental lockouts or infrastructure disruption. Please resolve manually or update the baseline."
			fmt.Printf(display.SKIP()+"%s (%s) - %s\n          %s\n", sgName, sgID, d.Type, msg)
			res.Skipped = append(res.Skipped, types.RemediationItem{
				SecurityGroup: sgID, Name: sgName, Type: d.Type, Reason: msg,
			})
			continue
		}

		if d.Type == "RULES_CHANGED" {
			// Revoke added rules
			for _, r := range d.AddedRules {
				msg := fmt.Sprintf("Missing rule in baseline (port %v from %v)", r.FromPort, r.Sources)
				if dryRun {
					fmt.Printf("[DRY-RUN] Would revoke: %s (SG: %s)\n", msg, d.SecurityGroup)
					res.Fixed = append(res.Fixed, types.RemediationItem{
						Name:          d.Name,
						SecurityGroup: d.SecurityGroup,
						Type:          "REVOKED_DRIFT_RULE",
					})
				} else {
					perm := buildIpPermission(r)
					_, err := client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
						GroupId:       aws.String(d.SecurityGroup),
						IpPermissions: []ec2types.IpPermission{perm},
					})
					if err != nil {
						fmt.Printf(display.FAILED()+"Failed to revoke: %v\n", err)
						res.Failed = append(res.Failed, types.RemediationItem{
							Name:          d.Name,
							SecurityGroup: d.SecurityGroup,
							Type:          "REVOKE_FAILED",
							Error:         err.Error(),
						})
					} else {
						fmt.Printf(display.FIXED()+"Revoked: %s\n", msg)
						res.Fixed = append(res.Fixed, types.RemediationItem{
							Name:          d.Name,
							SecurityGroup: d.SecurityGroup,
							Type:          "REVOKED_DRIFT_RULE",
						})
					}
				}
			}

			// Authorize removed rules
			for _, r := range d.RemovedRules {
				msg := fmt.Sprintf("Rule missing in AWS but exists in baseline (port %v from %v)", r.FromPort, r.Sources)
				if dryRun {
					fmt.Printf("[DRY-RUN] Would authorize: %s (SG: %s)\n", msg, d.SecurityGroup)
					res.Fixed = append(res.Fixed, types.RemediationItem{
						Name:          d.Name,
						SecurityGroup: d.SecurityGroup,
						Type:          "RESTORED_BASELINE_RULE",
					})
				} else {
					perm := buildIpPermission(r)
					_, err := client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
						GroupId:       aws.String(d.SecurityGroup),
						IpPermissions: []ec2types.IpPermission{perm},
					})
					if err != nil {
						fmt.Printf(display.FAILED()+"Failed to authorize: %v\n", err)
						res.Failed = append(res.Failed, types.RemediationItem{
							Name:          d.Name,
							SecurityGroup: d.SecurityGroup,
							Type:          "AUTHORIZE_FAILED",
							Error:         err.Error(),
						})
					} else {
						fmt.Printf(display.FIXED()+"Restored: %s\n", msg)
						res.Fixed = append(res.Fixed, types.RemediationItem{
							Name:          d.Name,
							SecurityGroup: d.SecurityGroup,
							Type:          "RESTORED_BASELINE_RULE",
						})
					}
				}
			}
		}
	}

	return res, nil
}

func buildIpPermission(rule types.InboundRule) ec2types.IpPermission {
	perm := ec2types.IpPermission{
		IpProtocol: aws.String(rule.Protocol),
		FromPort:   aws.Int32(rule.FromPort),
		ToPort:     aws.Int32(rule.ToPort),
	}
	var ipv4 []ec2types.IpRange
	var ipv6 []ec2types.Ipv6Range
	for _, src := range rule.Sources {
		if strings.Contains(src, ":") {
			ipv6 = append(ipv6, ec2types.Ipv6Range{CidrIpv6: aws.String(src)})
		} else {
			ipv4 = append(ipv4, ec2types.IpRange{CidrIp: aws.String(src)})
		}
	}
	if len(ipv4) > 0 {
		perm.IpRanges = ipv4
	}
	if len(ipv6) > 0 {
		perm.Ipv6Ranges = ipv6
	}
	return perm
}
