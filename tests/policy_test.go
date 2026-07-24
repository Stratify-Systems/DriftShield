package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/policy"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func TestDefaultRules(t *testing.T) {
	rules := policy.GetDefaultRules()
	if len(rules) == 0 {
		t.Fatal("expected default policy rules, got 0")
	}

	for _, r := range rules {
		if err := policy.ValidateRule(r); err != nil {
			t.Errorf("default rule %s invalid: %v", r.ID, err)
		}
	}
}

func TestLoadRulesFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	content := `
- id: POL-TEST-001
  name: Test S3 Policy
  service: s3
  severity: HIGH
  description: Test description
  conditions:
    all:
      - field: public_access_block.BlockPublicAcls
        operator: equals
        value: true
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test YAML: %v", err)
	}

	rules, err := policy.LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFromFile failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].ID != "POL-TEST-001" {
		t.Errorf("ID = %q; want POL-TEST-001", rules[0].ID)
	}
}

func TestValidateInvalidRule(t *testing.T) {
	invalidRule := policy.PolicyRule{
		Name:    "Missing ID",
		Service: "s3",
	}

	if err := policy.ValidateRule(invalidRule); err == nil {
		t.Error("expected error when validating rule without ID")
	}
}

func TestEvalS3Rule(t *testing.T) {
	rule := policy.PolicyRule{
		ID:       "POL-S3-001",
		Name:     "Block Public ACLs",
		Service:  "s3",
		Severity: "HIGH",
		Conditions: policy.ConditionGroup{
			All: []policy.Condition{
				{Field: "public_access_block.BlockPublicAcls", Operator: "equals", Value: true},
			},
		},
	}

	secureCfg := types.S3BucketConfig{
		BucketName:        "secure-bucket",
		PublicAccessBlock: map[string]bool{"BlockPublicAcls": true},
	}

	ok, msg := policy.EvalS3BucketConfig(rule, secureCfg)
	if !ok {
		t.Errorf("expected secure bucket to pass policy, got msg: %s", msg)
	}

	insecureCfg := types.S3BucketConfig{
		BucketName:        "insecure-bucket",
		PublicAccessBlock: map[string]bool{"BlockPublicAcls": false},
	}

	ok, msg = policy.EvalS3BucketConfig(rule, insecureCfg)
	if ok {
		t.Error("expected insecure bucket to fail policy")
	}
}

func TestEvalEC2Rule(t *testing.T) {
	rule := policy.PolicyRule{
		ID:       "POL-EC2-001",
		Name:     "No SSH from Internet",
		Service:  "ec2",
		Severity: "CRITICAL",
		Conditions: policy.ConditionGroup{
			NoneRule: &policy.RuleCheck{
				Port:     22,
				Protocol: "tcp",
				Source:   "0.0.0.0/0",
			},
		},
	}

	secureSG := types.SGConfig{
		GroupID:   "sg-safe",
		GroupName: "safe-group",
		InboundRules: []types.InboundRule{
			{Protocol: "tcp", FromPort: 443, ToPort: 443, Sources: []string{"0.0.0.0/0"}},
		},
	}

	ok, _ := policy.EvalSGConfig(rule, secureSG)
	if !ok {
		t.Error("expected HTTPS-only SG to pass SSH policy")
	}

	riskySG := types.SGConfig{
		GroupID:   "sg-risky",
		GroupName: "risky-group",
		InboundRules: []types.InboundRule{
			{Protocol: "tcp", FromPort: 22, ToPort: 22, Sources: []string{"0.0.0.0/0"}},
		},
	}

	ok, msg := policy.EvalSGConfig(rule, riskySG)
	if ok {
		t.Error("expected risky SG with open SSH to fail policy")
	}
	if msg == "" {
		t.Error("expected non-empty error message on failure")
	}
}
