package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func TestLoadBaselineNotFound(t *testing.T) {
	orig := config.BaselineFile
	config.BaselineFile = filepath.Join(t.TempDir(), "nonexistent.json")
	defer func() { config.BaselineFile = orig }()

	bl, err := LoadBaseline[types.S3Baseline](config.BaselineFile)
	if err != nil {
		t.Fatalf("expected nil error for missing baseline, got: %v", err)
	}
	if bl != nil {
		t.Fatal("expected nil baseline for missing file")
	}
}

func TestSaveAndLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_baseline.json")

	bl := &types.S3Baseline{
		CreatedAt: "2025-01-01T00:00:00Z",
		UpdatedAt: "2025-01-01T00:00:00Z",
		Buckets: map[string]types.S3BucketConfig{
			"test-bucket": {
				BucketName: "test-bucket",
				Versioning: "Enabled",
				Encryption: "AES256",
				PublicAccessBlock: map[string]bool{
					"BlockPublicAcls":       true,
					"IgnorePublicAcls":      true,
					"BlockPublicPolicy":     true,
					"RestrictPublicBuckets": true,
				},
			},
		},
	}

	if err := SaveBaseline(path, bl); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	loaded, err := LoadBaseline[types.S3Baseline](path)
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded baseline is nil")
	}
	if loaded.CreatedAt != bl.CreatedAt {
		t.Errorf("CreatedAt = %q; want %q", loaded.CreatedAt, bl.CreatedAt)
	}
	if len(loaded.Buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(loaded.Buckets))
	}
	b, ok := loaded.Buckets["test-bucket"]
	if !ok {
		t.Fatal("test-bucket not found in loaded baseline")
	}
	if b.Versioning != "Enabled" {
		t.Errorf("Versioning = %q; want Enabled", b.Versioning)
	}
}

func TestLoadBaselineInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := LoadBaseline[types.S3Baseline](path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestEC2BaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ec2_baseline.json")

	bl := &types.EC2Baseline{
		CreatedAt: "2025-01-01T00:00:00Z",
		UpdatedAt: "2025-01-01T00:00:00Z",
		Region:    "us-east-1",
		SecurityGroups: map[string]types.SGConfig{
			"sg-123": {
				GroupID: "sg-123", GroupName: "web-sg",
				Description: "Web servers", VpcID: "vpc-abc",
				InboundRules: []types.InboundRule{
					{Protocol: "tcp", FromPort: 443, ToPort: 443, Sources: []string{"0.0.0.0/0"}},
					{Protocol: "tcp", FromPort: 80, ToPort: 80, Sources: []string{"0.0.0.0/0"}},
				},
			},
			"sg-456": {
				GroupID: "sg-456", GroupName: "db-sg",
				Description: "Database", VpcID: "vpc-abc",
				InboundRules: []types.InboundRule{
					{Protocol: "tcp", FromPort: 5432, ToPort: 5432, Sources: []string{"10.0.0.0/8"}},
				},
			},
		},
	}

	if err := SaveBaseline(path, bl); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	loaded, err := LoadBaseline[types.EC2Baseline](path)
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if loaded.Region != "us-east-1" {
		t.Errorf("Region = %q; want us-east-1", loaded.Region)
	}
	if len(loaded.SecurityGroups) != 2 {
		t.Fatalf("expected 2 security groups, got %d", len(loaded.SecurityGroups))
	}
	sg := loaded.SecurityGroups["sg-123"]
	if len(sg.InboundRules) != 2 {
		t.Errorf("sg-123 rules = %d; want 2", len(sg.InboundRules))
	}
}

func TestRuleKey(t *testing.T) {
	r1 := types.InboundRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Sources: []string{"0.0.0.0/0"}}
	r2 := types.InboundRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Sources: []string{"0.0.0.0/0"}}
	r3 := types.InboundRule{Protocol: "tcp", FromPort: 443, ToPort: 443, Sources: []string{"0.0.0.0/0"}}

	if ruleKey(r1) != ruleKey(r2) {
		t.Error("identical rules should have same key")
	}
	if ruleKey(r1) == ruleKey(r3) {
		t.Error("different rules should have different keys")
	}

	// Order-independent sources
	r4 := types.InboundRule{Protocol: "tcp", FromPort: 80, ToPort: 80, Sources: []string{"10.0.0.0/8", "172.16.0.0/12"}}
	r5 := types.InboundRule{Protocol: "tcp", FromPort: 80, ToPort: 80, Sources: []string{"172.16.0.0/12", "10.0.0.0/8"}}
	if ruleKey(r4) != ruleKey(r5) {
		t.Error("rules with same sources in different order should have same key")
	}
}

func TestMapsEqual(t *testing.T) {
	a := map[string]bool{"BlockPublicAcls": true, "IgnorePublicAcls": false}
	b := map[string]bool{"BlockPublicAcls": true, "IgnorePublicAcls": false}
	c := map[string]bool{"BlockPublicAcls": false, "IgnorePublicAcls": false}

	if !mapsEqual(a, b) {
		t.Error("identical maps should be equal")
	}
	if mapsEqual(a, c) {
		t.Error("different maps should not be equal")
	}
	if mapsEqual(a, nil) {
		t.Error("map and nil should not be equal")
	}
}

func TestIAMBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iam.json")

	bl := &types.IAMBaseline{
		CreatedAt: "2025-01-01",
		UpdatedAt: "2025-01-01",
		PasswordPolicy: types.IAMPasswordPolicySnapshot{
			Exists: true, MinimumPasswordLength: 14,
			RequireUppercase: true, RequireLowercase: true,
			RequireNumbers: true, RequireSymbols: true,
		},
		Users: map[string]types.IAMUserSnapshot{
			"admin": {
				Username: "admin", HasConsoleAccess: true,
				MFAEnabled: true, AttachedPolicies: []string{"AdministratorAccess"},
			},
		},
	}

	if err := SaveBaseline(path, bl); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBaseline[types.IAMBaseline](path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PasswordPolicy.Exists {
		t.Error("password policy should exist")
	}
	if loaded.PasswordPolicy.MinimumPasswordLength != 14 {
		t.Errorf("min password length = %d; want 14", loaded.PasswordPolicy.MinimumPasswordLength)
	}
	u, ok := loaded.Users["admin"]
	if !ok {
		t.Fatal("admin user not found")
	}
	if !u.MFAEnabled {
		t.Error("admin MFA should be enabled")
	}
}
