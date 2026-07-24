package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadRulesFromDir loads all YAML policy rules from the specified directory.
func LoadRulesFromDir(dir string) ([]PolicyRule, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return GetDefaultRules(), nil
	}

	var rules []PolicyRule
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext == ".yaml" || ext == ".yml" {
			path := filepath.Join(dir, entry.Name())
			fileRules, err := LoadRulesFromFile(path)
			if err != nil {
				return nil, err
			}
			rules = append(rules, fileRules...)
		}
	}

	if len(rules) == 0 {
		return GetDefaultRules(), nil
	}

	return rules, nil
}

// LoadRulesFromFile loads policy rules from a single YAML file.
func LoadRulesFromFile(path string) ([]PolicyRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var rules []PolicyRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		// Try unmarshaling single rule
		var singleRule PolicyRule
		if sErr := yaml.Unmarshal(data, &singleRule); sErr == nil && singleRule.ID != "" {
			rules = []PolicyRule{singleRule}
		} else {
			return nil, fmt.Errorf("failed to parse YAML in %s: %w", path, err)
		}
	}

	for _, r := range rules {
		if err := ValidateRule(r); err != nil {
			return nil, fmt.Errorf("invalid rule in %s: %w", path, err)
		}
	}

	return rules, nil
}

// ValidateRule ensures mandatory rule fields are set.
func ValidateRule(r PolicyRule) error {
	if r.ID == "" {
		return fmt.Errorf("rule missing required field 'id'")
	}
	if r.Name == "" {
		return fmt.Errorf("rule '%s' missing required field 'name'", r.ID)
	}
	if r.Service == "" {
		return fmt.Errorf("rule '%s' missing required field 'service'", r.ID)
	}
	return nil
}

// GetDefaultRules returns standard built-in policy rules.
func GetDefaultRules() []PolicyRule {
	return []PolicyRule{
		{
			ID:          "POL-S3-001",
			Name:        "Enforce S3 Public Access Block",
			Service:     "s3",
			Severity:    "HIGH",
			Description: "All S3 buckets must have public access block enabled.",
			Remediation: "Enable BlockPublicAcls and BlockPublicPolicy on the S3 bucket.",
			Conditions: ConditionGroup{
				All: []Condition{
					{Field: "public_access_block.BlockPublicAcls", Operator: "equals", Value: true},
					{Field: "public_access_block.BlockPublicPolicy", Operator: "equals", Value: true},
				},
			},
		},
		{
			ID:          "POL-EC2-001",
			Name:        "Prohibit Open SSH Access",
			Service:     "ec2",
			Severity:    "CRITICAL",
			Description: "Security groups must not allow inbound TCP port 22 from 0.0.0.0/0.",
			Remediation: "Restrict SSH ingress to specific bastion host CIDR ranges.",
			Conditions: ConditionGroup{
				NoneRule: &RuleCheck{
					Port:     22,
					Protocol: "tcp",
					Source:   "0.0.0.0/0",
				},
			},
		},
		{
			ID:          "POL-RDS-001",
			Name:        "Enforce Database Storage Encryption",
			Service:     "rds",
			Severity:    "HIGH",
			Description: "All RDS instances must have storage encryption enabled.",
			Remediation: "Enable storage encryption during RDS instance creation.",
			Conditions: ConditionGroup{
				All: []Condition{
					{Field: "storage_encrypted", Operator: "equals", Value: true},
				},
			},
		},
		{
			ID:          "POL-VPC-001",
			Name:        "Enforce VPC Flow Logs",
			Service:     "vpc",
			Severity:    "HIGH",
			Description: "All VPCs must have flow logs enabled.",
			Remediation: "Enable VPC Flow Logs to record IP traffic.",
			Conditions: ConditionGroup{
				All: []Condition{
					{Field: "flow_logs_enabled", Operator: "equals", Value: true},
				},
			},
		},
		{
			ID:          "POL-CT-001",
			Name:        "Enforce CloudTrail Logging",
			Service:     "cloudtrail",
			Severity:    "CRITICAL",
			Description: "CloudTrail trails must have active logging enabled.",
			Remediation: "Enable logging status on the CloudTrail trail.",
			Conditions: ConditionGroup{
				All: []Condition{
					{Field: "is_logging", Operator: "equals", Value: true},
				},
			},
		},
		{
			ID:          "POL-IAM-001",
			Name:        "Enforce User MFA",
			Service:     "iam",
			Severity:    "HIGH",
			Description: "IAM users with console access must have MFA enabled.",
			Remediation: "Assign an MFA device to the IAM user.",
			Conditions: ConditionGroup{
				All: []Condition{
					{Field: "mfa_enabled", Operator: "equals", Value: true},
				},
			},
		},
	}
}
