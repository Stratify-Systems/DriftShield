package scanner

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestIsOpenCIDR(t *testing.T) {
	tests := []struct {
		cidr     string
		expected bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"10.0.0.0/8", false},
		{"192.168.1.1/32", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.cidr, func(t *testing.T) {
			if got := isOpenCIDR(tc.cidr); got != tc.expected {
				t.Errorf("isOpenCIDR(%q) = %v; want %v", tc.cidr, got, tc.expected)
			}
		})
	}
}

func TestIsRiskyRule(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		fromPort int32
		toPort   int32
		expected bool
	}{
		{"All traffic", "-1", 0, 0, true},
		{"All ports TCP", "tcp", 0, 65535, true},
		{"SSH port", "tcp", 22, 22, true},
		{"RDP port", "tcp", 3389, 3389, true},
		{"MySQL port", "tcp", 3306, 3306, true},
		{"PostgreSQL port", "tcp", 5432, 5432, true},
		{"Range including SSH", "tcp", 20, 25, true},
		{"Safe HTTP port", "tcp", 80, 80, false},
		{"Safe HTTPS port", "tcp", 443, 443, false},
		{"Custom high port", "tcp", 8080, 8080, false},
		{"Range of safe ports", "tcp", 8000, 9000, false},
		{"MongoDB port", "tcp", 27017, 27017, true},
		{"Redis port", "tcp", 6379, 6379, true},
		{"Elasticsearch port", "tcp", 9200, 9200, true},
		{"FTP port", "tcp", 21, 21, true},
		{"Telnet port", "tcp", 23, 23, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRiskyRule(tc.protocol, tc.fromPort, tc.toPort); got != tc.expected {
				t.Errorf("IsRiskyRule(%q, %d, %d) = %v; want %v", tc.protocol, tc.fromPort, tc.toPort, got, tc.expected)
			}
		})
	}
}

func TestFormatRuleDescription(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		fromPort int32
		toPort   int32
		source   string
		expected string
	}{
		{"All traffic", "-1", 0, 0, "0.0.0.0/0", "All Traffic from 0.0.0.0/0"},
		{"All ports", "tcp", 0, 65535, "0.0.0.0/0", "All tcp Ports (0-65535) from 0.0.0.0/0"},
		{"Known risky port (SSH)", "tcp", 22, 22, "0.0.0.0/0", "SSH (22) from 0.0.0.0/0"},
		{"Known risky port (RDP)", "tcp", 3389, 3389, "::/0", "RDP (3389) from ::/0"},
		{"Unknown single port", "tcp", 80, 80, "0.0.0.0/0", "tcp Port 80 from 0.0.0.0/0"},
		{"Port range", "tcp", 8000, 9000, "10.0.0.0/8", "tcp Ports 8000-9000 from 10.0.0.0/8"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatRuleDescription(tc.protocol, tc.fromPort, tc.toPort, tc.source); got != tc.expected {
				t.Errorf("FormatRuleDescription(...) = %q; want %q", got, tc.expected)
			}
		})
	}
}

func TestGetSecurityGroupRisks_NoRisks(t *testing.T) {
	sg := ec2types.SecurityGroup{
		GroupId:   aws.String("sg-safe"),
		GroupName: aws.String("safe-group"),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
		},
	}

	risks := GetSecurityGroupRisks(sg)
	if len(risks) != 0 {
		t.Errorf("expected 0 risks for HTTPS-only SG, got %d: %+v", len(risks), risks)
	}
}

func TestGetSecurityGroupRisks_OpenSSH(t *testing.T) {
	sg := ec2types.SecurityGroup{
		GroupId:   aws.String("sg-risky"),
		GroupName: aws.String("risky-group"),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
		},
	}

	risks := GetSecurityGroupRisks(sg)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	if risks[0].Severity != "CRITICAL" {
		t.Errorf("SSH open to internet should be CRITICAL, got %s", risks[0].Severity)
	}
}

func TestGetSecurityGroupRisks_AllTraffic(t *testing.T) {
	sg := ec2types.SecurityGroup{
		GroupId:   aws.String("sg-all"),
		GroupName: aws.String("all-traffic"),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				FromPort:   aws.Int32(0),
				ToPort:     aws.Int32(0),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
		},
	}

	risks := GetSecurityGroupRisks(sg)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	if risks[0].Type != "ALL_TRAFFIC_OPEN" {
		t.Errorf("expected ALL_TRAFFIC_OPEN, got %s", risks[0].Type)
	}
}

func TestGetSecurityGroupRisks_PrivateOnly(t *testing.T) {
	sg := ec2types.SecurityGroup{
		GroupId:   aws.String("sg-private"),
		GroupName: aws.String("private-ssh"),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
			},
		},
	}

	risks := GetSecurityGroupRisks(sg)
	if len(risks) != 0 {
		t.Errorf("SSH from private CIDR should have 0 risks, got %d", len(risks))
	}
}

func TestGetSecurityGroupConfig(t *testing.T) {
	sg := ec2types.SecurityGroup{
		GroupId:     aws.String("sg-test"),
		GroupName:   aws.String("test-group"),
		Description: aws.String("A test group"),
		VpcId:       aws.String("vpc-123"),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
			},
		},
	}

	cfg := GetSecurityGroupConfig(sg)
	if cfg.GroupID != "sg-test" {
		t.Errorf("GroupID = %q; want sg-test", cfg.GroupID)
	}
	if cfg.GroupName != "test-group" {
		t.Errorf("GroupName = %q; want test-group", cfg.GroupName)
	}
	if len(cfg.InboundRules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.InboundRules))
	}
	if cfg.InboundRules[0].Sources[0] != "0.0.0.0/0" {
		t.Errorf("rule 0 source = %q; want 0.0.0.0/0", cfg.InboundRules[0].Sources[0])
	}
	if cfg.InboundRules[1].Sources[0] != "::/0" {
		t.Errorf("rule 1 source = %q; want ::/0", cfg.InboundRules[1].Sources[0])
	}
}
