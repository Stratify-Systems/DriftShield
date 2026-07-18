package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/scanner"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

// LoadVPCBaseline loads the VPC baseline from disk.
func LoadVPCBaseline() (*types.VPCBaseline, error) {
	if _, err := os.Stat(config.VPCBaselineFile); os.IsNotExist(err) {
		return nil, nil
	}
	data, err := os.ReadFile(config.VPCBaselineFile)
	if err != nil {
		return nil, err
	}
	var bl types.VPCBaseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, err
	}
	return &bl, nil
}

// SaveVPCBaseline saves the VPC baseline to disk.
func SaveVPCBaseline(bl *types.VPCBaseline) error {
	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config.VPCBaselineFile, data, 0644)
}

// CreateVPCBaseline snapshots the current VPC configurations.
func CreateVPCBaseline(ctx context.Context) (*types.VPCBaseline, error) {
	now := time.Now().Format(time.RFC3339)
	region := config.GetRegion()
	bl := &types.VPCBaseline{
		CreatedAt: now,
		UpdatedAt: now,
		Region:    region,
		VPCs:      make(map[string]types.VPCSnapshot),
	}

	snapshots, err := scanner.GetVPCSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	bl.VPCs = snapshots

	if err := SaveVPCBaseline(bl); err != nil {
		return nil, fmt.Errorf("failed to save VPC baseline: %w", err)
	}

	fmt.Printf("Creating VPC baseline for region: %s\n", region)
	fmt.Printf("\nVPC baseline saved to %s\n", config.VPCBaselineFile)
	fmt.Printf("  %d VPC(s) captured\n", len(bl.VPCs))
	return bl, nil
}

// CompareVPCWithBaseline compares current VPC configs against the baseline.
// Returns (drifts, baselineExists, error).
func CompareVPCWithBaseline(ctx context.Context) ([]types.VPCDrift, bool, error) {
	bl, err := LoadVPCBaseline()
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
				"  Re-run 'driftshield vpc baseline' in region %q, or pass -r %s to use the baseline region",
			bl.Region, currentRegion, currentRegion, bl.Region,
		)
	}

	fmt.Printf("Comparing against VPC baseline...\n\n")
	fmt.Printf("  Baseline created: %s\n", bl.CreatedAt)
	fmt.Printf("  Baseline region:  %s\n\n", bl.Region)

	current, err := scanner.GetVPCSnapshot(ctx)
	if err != nil {
		return nil, true, err
	}

	var drifts []types.VPCDrift

	for vpcID, snap := range current {
		blSnap, exists := bl.VPCs[vpcID]
		if !exists {
			drifts = append(drifts, types.VPCDrift{
				Type: "VPC_ADDED", VPCID: vpcID, Resource: vpcID,
				Message: fmt.Sprintf("VPC '%s' was added since baseline", vpcID),
			})
			fmt.Printf("[DRIFT]    VPC %s added\n", vpcID)
			continue
		}

		vpcDrifted := false

		if snap.FlowLogsEnabled != blSnap.FlowLogsEnabled {
			drifts = append(drifts, types.VPCDrift{
				Type: "FLOW_LOGS_CHANGED", VPCID: vpcID, Resource: vpcID,
				Message:  fmt.Sprintf("VPC '%s' flow logs status changed", vpcID),
				OldValue: fmt.Sprintf("%v", blSnap.FlowLogsEnabled),
				NewValue: fmt.Sprintf("%v", snap.FlowLogsEnabled),
			})
			fmt.Printf("[DRIFT]    VPC %s flow logs: %v -> %v\n", vpcID, blSnap.FlowLogsEnabled, snap.FlowLogsEnabled)
			vpcDrifted = true
		}

		for subnetID, subSnap := range snap.Subnets {
			blSub, subExists := blSnap.Subnets[subnetID]
			if !subExists {
				drifts = append(drifts, types.VPCDrift{
					Type: "SUBNET_ADDED", VPCID: vpcID, Resource: subnetID,
					Message: fmt.Sprintf("Subnet '%s' was added since baseline", subnetID),
				})
				fmt.Printf("[DRIFT]    VPC %s — subnet %s added\n", vpcID, subnetID)
				vpcDrifted = true
				continue
			}
			if subSnap.AutoAssignPublicIP != blSub.AutoAssignPublicIP {
				drifts = append(drifts, types.VPCDrift{
					Type: "SUBNET_PUBLIC_IP_CHANGED", VPCID: vpcID, Resource: subnetID,
					Message:  fmt.Sprintf("Subnet '%s' auto-assign public IP changed", subnetID),
					OldValue: fmt.Sprintf("%v", blSub.AutoAssignPublicIP),
					NewValue: fmt.Sprintf("%v", subSnap.AutoAssignPublicIP),
				})
				fmt.Printf("[DRIFT]    VPC %s — subnet %s auto-assign public IP: %v -> %v\n",
					vpcID, subnetID, blSub.AutoAssignPublicIP, subSnap.AutoAssignPublicIP)
				vpcDrifted = true
			}
		}

		for subnetID := range blSnap.Subnets {
			if _, exists := snap.Subnets[subnetID]; !exists {
				drifts = append(drifts, types.VPCDrift{
					Type: "SUBNET_DELETED", VPCID: vpcID, Resource: subnetID,
					Message: fmt.Sprintf("Subnet '%s' was deleted since baseline", subnetID),
				})
				fmt.Printf("[DRIFT]    VPC %s — subnet %s deleted\n", vpcID, subnetID)
				vpcDrifted = true
			}
		}

		if !vpcDrifted {
			fmt.Printf("[OK]       VPC %s unchanged\n", vpcID)
		}
	}

	for vpcID := range bl.VPCs {
		if _, exists := current[vpcID]; !exists {
			drifts = append(drifts, types.VPCDrift{
				Type: "VPC_DELETED", VPCID: vpcID, Resource: vpcID,
				Message: fmt.Sprintf("VPC '%s' was deleted since baseline", vpcID),
			})
			fmt.Printf("[DRIFT]    VPC %s deleted\n", vpcID)
		}
	}

	return drifts, true, nil
}

// RemediateVPCDrift restores drifted VPC subnet settings back to baseline.
func RemediateVPCDrift(ctx context.Context, drifts []types.VPCDrift) (*types.RemediationResults, error) {
	bl, err := LoadVPCBaseline()
	if err != nil || bl == nil {
		return nil, fmt.Errorf("failed to load VPC baseline")
	}

	client, err := newEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.RemediationResults{}

	for _, drift := range drifts {
		switch drift.Type {
		case "SUBNET_PUBLIC_IP_CHANGED":
			blVPC, ok := bl.VPCs[drift.VPCID]
			if !ok {
				continue
			}
			blSub, ok := blVPC.Subnets[drift.Resource]
			if !ok {
				continue
			}
			_, fErr := client.ModifySubnetAttribute(ctx, &ec2.ModifySubnetAttributeInput{
				SubnetId:            aws.String(drift.Resource),
				MapPublicIpOnLaunch: &ec2types.AttributeBooleanValue{Value: aws.Bool(blSub.AutoAssignPublicIP)},
			})
			if fErr != nil {
				fmt.Printf("[FAILED]  Subnet '%s' — could not restore auto-assign public IP: %v\n", drift.Resource, fErr)
				res.Failed = append(res.Failed, types.RemediationItem{Name: drift.Resource, Type: drift.Type, Error: fErr.Error()})
			} else {
				fmt.Printf("[FIXED]   Subnet '%s' — auto-assign public IP restored to %v\n", drift.Resource, blSub.AutoAssignPublicIP)
				res.Fixed = append(res.Fixed, types.RemediationItem{Name: drift.Resource, Type: drift.Type})
			}

		default:
			fmt.Printf("[SKIP]    VPC '%s' — drift type '%s' requires manual action\n", drift.VPCID, drift.Type)
			res.Skipped = append(res.Skipped, types.RemediationItem{
				Name: drift.Resource, Type: drift.Type, Reason: "Manual action required",
			})
		}
	}

	return res, nil
}
