package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

// RiskyPorts maps ports considered risky when open to the internet.
var RiskyPorts = map[int32]string{
	22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
	1433: "MSSQL", 1521: "Oracle", 27017: "MongoDB", 6379: "Redis",
	9200: "Elasticsearch", 5900: "VNC", 23: "Telnet", 21: "FTP",
	445: "SMB", 135: "RPC",
}

// OpenCIDRs are CIDR ranges that mean "open to the internet".
var OpenCIDRs = []string{"0.0.0.0/0", "::/0"}

// NewEC2Client creates an EC2 client for the configured region.
func NewEC2Client(ctx context.Context) (*ec2.Client, error) {
	region := config.GetRegion()
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return ec2.NewFromConfig(cfg), nil
}

func isOpenCIDR(cidr string) bool {
	for _, c := range OpenCIDRs {
		if cidr == c {
			return true
		}
	}
	return false
}

func getCIDRs(rule ec2types.IpPermission) []string {
	var cidrs []string
	for _, r := range rule.IpRanges {
		cidrs = append(cidrs, aws.ToString(r.CidrIp))
	}
	for _, r := range rule.Ipv6Ranges {
		cidrs = append(cidrs, aws.ToString(r.CidrIpv6))
	}
	return cidrs
}

// GetSecurityGroupRisks analyses a security group for risky rules.
func GetSecurityGroupRisks(sg ec2types.SecurityGroup) []types.Risk {
	var risks []types.Risk

	for _, rule := range sg.IpPermissions {
		protocol := aws.ToString(rule.IpProtocol)
		fromPort := aws.ToInt32(rule.FromPort)
		toPort := aws.ToInt32(rule.ToPort)
		cidrs := getCIDRs(rule)

		openToInternet := false
		for _, c := range cidrs {
			if isOpenCIDR(c) {
				openToInternet = true
				break
			}
		}
		if !openToInternet {
			continue
		}

		if protocol == "-1" {
			risks = append(risks, types.Risk{
				Type: "ALL_TRAFFIC_OPEN", Severity: "CRITICAL",
				Message: "All traffic allowed from internet",
				Details: fmt.Sprintf("Protocol: ALL, Source: %v", cidrs),
			})
			continue
		}

		if fromPort == 0 && toPort == 65535 {
			risks = append(risks, types.Risk{
				Type: "ALL_PORTS_OPEN", Severity: "CRITICAL",
				Message: fmt.Sprintf("All ports open to internet (%s)", protocol),
				Details: fmt.Sprintf("Ports: 0-65535, Source: %v", cidrs),
			})
			continue
		}

		for port, svc := range RiskyPorts {
			if fromPort <= port && port <= toPort {
				sev := "HIGH"
				if port == 22 || port == 3389 {
					sev = "CRITICAL"
				}
				risks = append(risks, types.Risk{
					Type: fmt.Sprintf("%s_OPEN", svc), Severity: sev, Port: port,
					Message: fmt.Sprintf("%s (port %d) open to internet", svc, port),
					Details: fmt.Sprintf("Source: %v", cidrs),
				})
			}
		}
	}
	return risks
}

// GetSecurityGroupConfig extracts configuration from a security group.
func GetSecurityGroupConfig(sg ec2types.SecurityGroup) types.SGConfig {
	var rules []types.InboundRule
	for _, r := range sg.IpPermissions {
		rules = append(rules, types.InboundRule{
			Protocol: aws.ToString(r.IpProtocol),
			FromPort: aws.ToInt32(r.FromPort),
			ToPort:   aws.ToInt32(r.ToPort),
			Sources:  getCIDRs(r),
		})
	}
	return types.SGConfig{
		GroupID:      aws.ToString(sg.GroupId),
		GroupName:    aws.ToString(sg.GroupName),
		Description:  aws.ToString(sg.Description),
		VpcID:        aws.ToString(sg.VpcId),
		InboundRules: rules,
	}
}

// ScanSecurityGroups scans all security groups for risky configurations.
func ScanSecurityGroups(ctx context.Context) (*types.EC2ScanResults, error) {
	client, err := NewEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	region := config.GetRegion()
	res := &types.EC2ScanResults{Details: make(map[string]*types.SGDetails)}

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	fmt.Printf("Region: %s\n", region)
	fmt.Printf("Found %d security group(s)\n\n", len(out.SecurityGroups))

	for _, sg := range out.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)
		display := fmt.Sprintf("%s (%s)", sgName, sgID)

		risks := GetSecurityGroupRisks(sg)
		cfg := GetSecurityGroupConfig(sg)

		res.Details[sgID] = &types.SGDetails{Config: cfg, Risks: risks}

		if len(risks) > 0 {
			res.AtRisk = append(res.AtRisk, sgID)
			sev := "MEDIUM"
			for _, r := range risks {
				if r.Severity == "CRITICAL" {
					sev = "CRITICAL"
					break
				}
				if r.Severity == "HIGH" {
					sev = "HIGH"
				}
			}
			fmt.Printf("[%s]  %s\n", sev, display)
			for _, r := range risks {
				fmt.Printf("           - %s\n", r.Message)
			}
		} else {
			res.Secure = append(res.Secure, sgID)
			fmt.Printf("[SECURE]   %s\n", display)
		}
	}
	return res, nil
}

// GetAllSecurityGroupConfigs returns configs for all security groups (for baselines).
func GetAllSecurityGroupConfigs(ctx context.Context) (map[string]types.SGConfig, error) {
	client, err := NewEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	configs := make(map[string]types.SGConfig)
	for _, sg := range out.SecurityGroups {
		id := aws.ToString(sg.GroupId)
		configs[id] = GetSecurityGroupConfig(sg)
	}
	return configs, nil
}

// IsRiskyRule checks if a rule should be removed during remediation.
func IsRiskyRule(protocol string, fromPort, toPort int32) bool {
	if protocol == "-1" {
		return true
	}
	if fromPort == 0 && toPort == 65535 {
		return true
	}
	for port := range RiskyPorts {
		if fromPort <= port && port <= toPort {
			return true
		}
	}
	return false
}

// FormatRuleDescription returns a human-readable description of a rule.
func FormatRuleDescription(protocol string, fromPort, toPort int32, source string) string {
	if protocol == "-1" {
		return fmt.Sprintf("All Traffic from %s", source)
	}
	if fromPort == 0 && toPort == 65535 {
		return fmt.Sprintf("All %s Ports (0-65535) from %s", protocol, source)
	}
	if fromPort == toPort {
		if svc, ok := RiskyPorts[fromPort]; ok {
			return fmt.Sprintf("%s (%d) from %s", svc, fromPort, source)
		}
		return fmt.Sprintf("%s Port %d from %s", protocol, fromPort, source)
	}
	return fmt.Sprintf("%s Ports %d-%d from %s", protocol, fromPort, toPort, source)
}

// RemediateEC2Risks removes risky inbound rules from security groups.
func RemediateEC2Risks(ctx context.Context, dryRun bool) (*types.RemediationResults, error) {
	client, err := NewEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	region := config.GetRegion()
	res := &types.RemediationResults{}

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	fmt.Printf("Region: %s\n", region)
	fmt.Printf("Scanning %d security group(s) for risky rules...\n\n", len(out.SecurityGroups))

	for _, sg := range out.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)
		display := fmt.Sprintf("%s (%s)", sgName, sgID)

		if sgName == "default" {
			res.Skipped = append(res.Skipped, types.RemediationItem{
				SecurityGroup: sgID, Name: sgName,
				Reason: "Default security group - manual review recommended",
			})
			fmt.Printf("[SKIP]     %s (default group)\n", display)
			continue
		}

		for _, rule := range sg.IpPermissions {
			protocol := aws.ToString(rule.IpProtocol)
			fromPort := aws.ToInt32(rule.FromPort)
			toPort := aws.ToInt32(rule.ToPort)

			for _, ipr := range rule.IpRanges {
				cidr := aws.ToString(ipr.CidrIp)
				if !isOpenCIDR(cidr) || !IsRiskyRule(protocol, fromPort, toPort) {
					continue
				}
				desc := FormatRuleDescription(protocol, fromPort, toPort, cidr)
				if dryRun {
					fmt.Printf("[DRY-RUN]  %s\n           Would remove: %s\n", display, desc)
					res.Fixed = append(res.Fixed, types.RemediationItem{
						SecurityGroup: sgID, Name: sgName, RuleRemoved: desc, DryRun: true,
					})
				} else {
					perm := ec2types.IpPermission{
						IpProtocol: aws.String(protocol),
						FromPort:   aws.Int32(fromPort),
						ToPort:     aws.Int32(toPort),
						IpRanges:   []ec2types.IpRange{{CidrIp: aws.String(cidr)}},
					}
					_, rErr := client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
						GroupId: aws.String(sgID), IpPermissions: []ec2types.IpPermission{perm},
					})
					if rErr != nil {
						fmt.Printf("[FAILED]   %s\n           Could not remove: %s\n           Error: %v\n", display, desc, rErr)
						res.Failed = append(res.Failed, types.RemediationItem{
							SecurityGroup: sgID, Name: sgName, RuleRemoved: desc, Error: rErr.Error(),
						})
					} else {
						fmt.Printf("[FIXED]    %s\n           Removed: %s\n", display, desc)
						res.Fixed = append(res.Fixed, types.RemediationItem{
							SecurityGroup: sgID, Name: sgName, RuleRemoved: desc,
						})
					}
				}
			}

			for _, ipr := range rule.Ipv6Ranges {
				cidr := aws.ToString(ipr.CidrIpv6)
				if !isOpenCIDR(cidr) || !IsRiskyRule(protocol, fromPort, toPort) {
					continue
				}
				desc := FormatRuleDescription(protocol, fromPort, toPort, cidr)
				if dryRun {
					fmt.Printf("[DRY-RUN]  %s\n           Would remove: %s\n", display, desc)
					res.Fixed = append(res.Fixed, types.RemediationItem{
						SecurityGroup: sgID, Name: sgName, RuleRemoved: desc, DryRun: true,
					})
				} else {
					perm := ec2types.IpPermission{
						IpProtocol: aws.String(protocol),
						FromPort:   aws.Int32(fromPort),
						ToPort:     aws.Int32(toPort),
						Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String(cidr)}},
					}
					_, rErr := client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
						GroupId: aws.String(sgID), IpPermissions: []ec2types.IpPermission{perm},
					})
					if rErr != nil {
						fmt.Printf("[FAILED]   %s\n           Could not remove: %s\n           Error: %v\n", display, desc, rErr)
						res.Failed = append(res.Failed, types.RemediationItem{
							SecurityGroup: sgID, Name: sgName, RuleRemoved: desc, Error: rErr.Error(),
						})
					} else {
						fmt.Printf("[FIXED]    %s\n           Removed: %s\n", display, desc)
						res.Fixed = append(res.Fixed, types.RemediationItem{
							SecurityGroup: sgID, Name: sgName, RuleRemoved: desc,
						})
					}
				}
			}
		}
	}
	return res, nil
}
