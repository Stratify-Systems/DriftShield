package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

// ScanVPC scans all VPCs for security misconfigurations.
func ScanVPC(ctx context.Context) (*types.VPCScanResults, error) {
	client, err := NewEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.VPCScanResults{}
	region := config.GetRegion()
	fmt.Printf("Region: %s\n\n", region)

	vpcs, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	fmt.Printf("Found %d VPC(s)\n\n", len(vpcs.Vpcs))

	flowLogs, err := client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe flow logs: %w", err)
	}
	vpcFlowLogs := make(map[string]bool)
	for _, fl := range flowLogs.FlowLogs {
		vpcFlowLogs[aws.ToString(fl.ResourceId)] = true
	}

	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		vpcFindings := 0

		if aws.ToBool(vpc.IsDefault) {
			res.Findings = append(res.Findings, types.VPCFinding{
				Type: "DEFAULT_VPC_IN_USE", Severity: "MEDIUM", VPCID: vpcID,
				Resource: vpcID,
				Message:  fmt.Sprintf("Default VPC '%s' is in use — consider deleting it", vpcID),
			})
			fmt.Printf("[MEDIUM]   VPC %s — default VPC in use\n", vpcID)
			vpcFindings++
		}

		if !vpcFlowLogs[vpcID] {
			res.Findings = append(res.Findings, types.VPCFinding{
				Type: "FLOW_LOGS_DISABLED", Severity: "HIGH", VPCID: vpcID,
				Resource: vpcID,
				Message:  fmt.Sprintf("VPC '%s' has no flow logs enabled", vpcID),
			})
			fmt.Printf("[HIGH]     VPC %s — flow logs disabled\n", vpcID)
			vpcFindings++
		}

		// Check NACLs for rules allowing all inbound traffic from internet
		nacls, nerr := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		})
		if nerr == nil {
			for _, nacl := range nacls.NetworkAcls {
				naclID := aws.ToString(nacl.NetworkAclId)
				for _, entry := range nacl.Entries {
					if aws.ToBool(entry.Egress) || string(entry.RuleAction) != "allow" {
						continue
					}
					cidr := aws.ToString(entry.CidrBlock)
					cidr6 := aws.ToString(entry.Ipv6CidrBlock)
					protocol := aws.ToString(entry.Protocol)
					if (cidr == "0.0.0.0/0" || cidr6 == "::/0") && protocol == "-1" {
						res.Findings = append(res.Findings, types.VPCFinding{
							Type: "NACL_ALLOWS_ALL_TRAFFIC", Severity: "HIGH", VPCID: vpcID,
							Resource: naclID,
							Message:  fmt.Sprintf("NACL '%s' allows all inbound traffic from internet", naclID),
						})
						fmt.Printf("[HIGH]     VPC %s — NACL %s allows all inbound traffic\n", vpcID, naclID)
						vpcFindings++
						break
					}
				}
			}
		}

		// Check subnets for auto-assign public IP
		subnets, serr := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		})
		if serr == nil {
			for _, subnet := range subnets.Subnets {
				subnetID := aws.ToString(subnet.SubnetId)
				if aws.ToBool(subnet.MapPublicIpOnLaunch) {
					res.Findings = append(res.Findings, types.VPCFinding{
						Type: "SUBNET_AUTO_ASSIGN_PUBLIC_IP", Severity: "MEDIUM", VPCID: vpcID,
						Resource: subnetID,
						Message:  fmt.Sprintf("Subnet '%s' auto-assigns public IPs on launch", subnetID),
					})
					fmt.Printf("[MEDIUM]   VPC %s — subnet %s auto-assigns public IP\n", vpcID, subnetID)
					vpcFindings++
				}
			}
		}

		if vpcFindings == 0 {
			fmt.Printf("[SECURE]   VPC %s\n", vpcID)
		}
	}

	return res, nil
}

// GetVPCSnapshot returns a snapshot of all VPCs for baseline use.
func GetVPCSnapshot(ctx context.Context) (map[string]types.VPCSnapshot, error) {
	client, err := NewEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	vpcs, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	flowLogs, err := client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe flow logs: %w", err)
	}
	vpcFlowLogs := make(map[string]bool)
	for _, fl := range flowLogs.FlowLogs {
		vpcFlowLogs[aws.ToString(fl.ResourceId)] = true
	}

	snapshots := make(map[string]types.VPCSnapshot)

	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		snap := types.VPCSnapshot{
			VPCID:           vpcID,
			IsDefault:       aws.ToBool(vpc.IsDefault),
			FlowLogsEnabled: vpcFlowLogs[vpcID],
			Subnets:         make(map[string]types.VPCSubnetSnapshot),
		}

		subnets, serr := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		})
		if serr == nil {
			for _, subnet := range subnets.Subnets {
				subnetID := aws.ToString(subnet.SubnetId)
				snap.Subnets[subnetID] = types.VPCSubnetSnapshot{
					SubnetID:           subnetID,
					CIDR:               aws.ToString(subnet.CidrBlock),
					AutoAssignPublicIP: aws.ToBool(subnet.MapPublicIpOnLaunch),
				}
			}
		}

		snapshots[vpcID] = snap
		fmt.Printf("  Captured VPC: %s (default=%v, flowLogs=%v, subnets=%d)\n",
			vpcID, snap.IsDefault, snap.FlowLogsEnabled, len(snap.Subnets))
	}

	return snapshots, nil
}
