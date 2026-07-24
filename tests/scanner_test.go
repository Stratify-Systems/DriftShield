package tests

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/SuryaTK2007/DriftShield/internal/scanner"
)

func TestIsRiskyRule(t *testing.T) {
	if !scanner.IsRiskyRule("tcp", 22, 22) {
		t.Error("SSH port 22 should be flagged as risky")
	}
	if scanner.IsRiskyRule("tcp", 443, 443) {
		t.Error("HTTPS port 443 should not be flagged as risky")
	}
}

func TestFormatRuleDescription(t *testing.T) {
	desc := scanner.FormatRuleDescription("tcp", 22, 22, "0.0.0.0/0")
	if desc != "SSH (22) from 0.0.0.0/0" {
		t.Errorf("FormatRuleDescription = %q; want 'SSH (22) from 0.0.0.0/0'", desc)
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

	risks := scanner.GetSecurityGroupRisks(sg)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	if risks[0].Severity != "CRITICAL" {
		t.Errorf("SSH open to internet should be CRITICAL, got %s", risks[0].Severity)
	}
}
