package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/ai"
	"github.com/SuryaTK2007/DriftShield/internal/policy"
)

func TestConstructPolicyPrompt(t *testing.T) {
	requirements := "Framework: SOC2\nAdditional Security Guidelines: Enforce S3 encryption and no open SSH"

	prompt := ai.ConstructPolicyPrompt(requirements)

	expectedSubstrings := []string{
		"SOC2",
		"Enforce S3 encryption and no open SSH",
		"POL-SVC-001",
		"public_access_block.BlockPublicAcls",
		"none_rule",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(prompt, sub) {
			t.Errorf("ConstructPolicyPrompt() missing expected substring %q", sub)
		}
	}
}

func TestExtractYAMLBlock(t *testing.T) {
	markdownInput := `
Here are the generated policy rules:

` + "```yaml" + `
- id: POL-S3-001
  name: Enforce S3 Public Access Block
  service: s3
  severity: HIGH
  description: Block public access
  remediation: Enable public access block
  conditions:
    all:
      - field: public_access_block.BlockPublicAcls
        operator: equals
        value: true
` + "```" + `

Hope this helps!
`

	extracted := ai.ExtractYAMLBlock(markdownInput)
	if !strings.Contains(extracted, "POL-S3-001") {
		t.Errorf("ExtractYAMLBlock() failed to extract YAML code block")
	}
	if strings.Contains(extracted, "Here are the generated") {
		t.Errorf("ExtractYAMLBlock() did not strip leading markdown text")
	}
}

func TestParseAndValidatePolicyYAML(t *testing.T) {
	validYAML := `- id: POL-VALID-001
  name: Valid Policy Rule
  service: s3
  severity: HIGH
  description: Valid rule description
`
	rules, err := ai.ParseAndValidatePolicyYAML(validYAML)
	if err != nil {
		t.Fatalf("ParseAndValidatePolicyYAML failed on valid YAML: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "POL-VALID-001" {
		t.Errorf("unexpected parsed rules: %+v", rules)
	}

	invalidSchemaYAML := `- name: Missing ID Field
  service: s3
`
	_, err = ai.ParseAndValidatePolicyYAML(invalidSchemaYAML)
	if err == nil {
		t.Error("expected error when validating YAML missing required ID field")
	}
}

func TestSavePolicyYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom_policy.yaml")
	content := `- id: POL-TEST-001
  name: Test Policy
  service: s3
  severity: HIGH
  description: Test description
`

	if err := ai.SavePolicyYAML(path, content); err != nil {
		t.Fatalf("SavePolicyYAML failed: %v", err)
	}

	loaded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(loaded) != content {
		t.Errorf("loaded content = %q; want %q", string(loaded), content)
	}

	rules, err := policy.LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFromFile failed on saved YAML: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "POL-TEST-001" {
		t.Errorf("loaded rules mismatch: %+v", rules)
	}
}
