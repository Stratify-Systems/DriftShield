package ai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/SuryaTK2007/DriftShield/internal/policy"
)

const MaxPolicyRetries = 3

// ConstructPolicyPrompt builds the system prompt enforcing the PolicyRule schema.
func ConstructPolicyPrompt(requirements string) string {
	return fmt.Sprintf(`You are a Cloud Security Architect designing declarative Policy-as-Code rules for DriftShield.

User Security Requirements & Compliance Standards:
%s

Generate a list of YAML policy rules following this EXACT schema for each rule:

- id: "POL-SVC-001"
  name: "Short descriptive rule name"
  service: "s3" # Must be one of: s3, ec2, iam, cloudtrail, vpc, rds
  severity: "HIGH" # Must be one of: CRITICAL, HIGH, MEDIUM, LOW
  description: "Detailed explanation of security rule"
  remediation: "Actionable steps to fix policy violation"
  conditions:
    all:
      - field: "public_access_block.BlockPublicAcls" # Supported fields: public_access_block.BlockPublicAcls, public_access_block.BlockPublicPolicy, versioning, encryption, storage_encrypted, publicly_accessible, deletion_protection, flow_logs_enabled, is_logging, mfa_enabled
        operator: "equals" # equals, not_equals, is_true, is_false
        value: true

Or for EC2 firewall rules:
- id: "POL-EC2-001"
  name: "Prohibit Open SSH Access"
  service: "ec2"
  severity: "CRITICAL"
  description: "Security groups must not allow inbound TCP port 22 from 0.0.0.0/0"
  remediation: "Restrict SSH ingress to bastion CIDR ranges"
  conditions:
    none_rule:
      port: 22
      protocol: "tcp"
      source: "0.0.0.0/0"

CRITICAL INSTRUCTIONS:
1. Return ONLY raw YAML inside a single markdown code block labeled '''yaml ... '''.
2. Do not include markdown text or conversational explanations outside the yaml code block.
3. Every rule MUST have id, name, service, severity, description, remediation, and conditions.
`, requirements)
}

// GeneratePolicyRules calls Groq API with an automatic self-healing retry loop (max 3 attempts).
func GeneratePolicyRules(ctx context.Context, requirements string) ([]policy.PolicyRule, string, error) {
	basePrompt := ConstructPolicyPrompt(requirements)
	currentPrompt := basePrompt
	var lastErr error

	for attempt := 1; attempt <= MaxPolicyRetries; attempt++ {
		rawResp, err := CallGroqAPI(ctx, currentPrompt)
		if err != nil {
			return nil, "", fmt.Errorf("failed to call AI (attempt %d/%d): %w", attempt, MaxPolicyRetries, err)
		}

		yamlContent := ExtractYAMLBlock(rawResp)
		if yamlContent == "" {
			lastErr = fmt.Errorf("AI response did not contain a valid YAML code block")
		} else {
			rules, err := ParseAndValidatePolicyYAML(yamlContent)
			if err == nil {
				return rules, yamlContent, nil
			}
			lastErr = err
		}

		if attempt < MaxPolicyRetries {
			fmt.Printf("\n[AI RETRY %d/%d] Generated YAML schema was invalid: %v\nFeeding error back to AI for self-correction...\n", attempt, MaxPolicyRetries, lastErr)
			currentPrompt = fmt.Sprintf("%s\n\nPREVIOUS ATTEMPT FAILED WITH ERROR:\n%v\n\nPlease fix the error and return ONLY valid YAML following the exact PolicyRule schema.", basePrompt, lastErr)
		}
	}

	return nil, "", fmt.Errorf("AI policy generation failed after %d attempts: %w", MaxPolicyRetries, lastErr)
}

// ParseAndValidatePolicyYAML unmarshals and validates policy rules.
func ParseAndValidatePolicyYAML(yamlContent string) ([]policy.PolicyRule, error) {
	var rules []policy.PolicyRule
	if err := yaml.Unmarshal([]byte(yamlContent), &rules); err != nil {
		var single policy.PolicyRule
		if sErr := yaml.Unmarshal([]byte(yamlContent), &single); sErr == nil && single.ID != "" {
			rules = []policy.PolicyRule{single}
		} else {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in YAML")
	}

	for i, r := range rules {
		if err := policy.ValidateRule(r); err != nil {
			return nil, fmt.Errorf("rule #%d is invalid: %w", i+1, err)
		}
	}

	return rules, nil
}

// ExtractYAMLBlock extracts yaml text from markdown fenced code blocks.
func ExtractYAMLBlock(text string) string {
	if strings.Contains(text, "```yaml") {
		parts := strings.Split(text, "```yaml")
		if len(parts) > 1 {
			codePart := strings.Split(parts[1], "```")[0]
			return strings.TrimSpace(codePart)
		}
	} else if strings.Contains(text, "```yml") {
		parts := strings.Split(text, "```yml")
		if len(parts) > 1 {
			codePart := strings.Split(parts[1], "```")[0]
			return strings.TrimSpace(codePart)
		}
	} else if strings.Contains(text, "```") {
		parts := strings.Split(text, "```")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return strings.TrimSpace(text)
}

// SavePolicyYAML saves validated YAML policy rules to disk.
func SavePolicyYAML(path string, yamlContent string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		return fmt.Errorf("failed to save policy YAML to %s: %w", path, err)
	}

	return nil
}
