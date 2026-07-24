package policy

// PolicyRule represents a declarative security policy rule.
type PolicyRule struct {
	ID          string         `yaml:"id" json:"id"`
	Name        string         `yaml:"name" json:"name"`
	Service     string         `yaml:"service" json:"service"` // s3, ec2, iam, cloudtrail, vpc, rds
	Severity    string         `yaml:"severity" json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Description string         `yaml:"description" json:"description"`
	Remediation string         `yaml:"remediation" json:"remediation"`
	Conditions  ConditionGroup `yaml:"conditions" json:"conditions"`
}

// ConditionGroup specifies matching requirements.
type ConditionGroup struct {
	All      []Condition `yaml:"all,omitempty" json:"all,omitempty"`
	Any      []Condition `yaml:"any,omitempty" json:"any,omitempty"`
	None     []Condition `yaml:"none,omitempty" json:"none,omitempty"`
	NoneRule *RuleCheck  `yaml:"none_rule,omitempty" json:"none_rule,omitempty"`
}

// Condition defines a single property check.
type Condition struct {
	Field    string      `yaml:"field" json:"field"`
	Operator string      `yaml:"operator" json:"operator"` // equals, not_equals, is_true, is_false, contains, not_contains, in, greater_than, less_than
	Value    interface{} `yaml:"value" json:"value"`
}

// RuleCheck matches specific firewall/security group rules.
type RuleCheck struct {
	Port     int32  `yaml:"port,omitempty" json:"port,omitempty"`
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Source   string `yaml:"source,omitempty" json:"source,omitempty"`
}

// PolicyFinding represents a violation of a policy rule by a specific resource.
type PolicyFinding struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Service     string `json:"service"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// PolicyEvaluationResult holds evaluation metrics and findings.
type PolicyEvaluationResult struct {
	TotalRulesEvaluated int
	PassingRules        int
	FailingRules        int
	Findings            []PolicyFinding
}
