// Package types defines shared data structures used across DriftShield.
package types

// InboundRule represents a security group inbound rule.
type InboundRule struct {
	Protocol string   `json:"protocol"`
	FromPort int32    `json:"from_port"`
	ToPort   int32    `json:"to_port"`
	Sources  []string `json:"sources"`
}

// SGConfig represents a security group configuration.
type SGConfig struct {
	GroupID      string        `json:"group_id"`
	GroupName    string        `json:"group_name"`
	Description  string        `json:"description"`
	VpcID        string        `json:"vpc_id"`
	InboundRules []InboundRule `json:"inbound_rules"`
}

// Risk represents a security risk finding.
type Risk struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Port     int32  `json:"port,omitempty"`
	Message  string `json:"message"`
	Details  string `json:"details"`
}

// S3BucketConfig represents an S3 bucket's security configuration.
type S3BucketConfig struct {
	BucketName        string          `json:"bucket_name"`
	PublicAccessBlock map[string]bool `json:"public_access_block"`
	Versioning        string          `json:"versioning"`
	Encryption        string          `json:"encryption"`
}

// S3Drift represents a configuration drift in S3.
type S3Drift struct {
	Bucket   string      `json:"bucket"`
	Type     string      `json:"type"`
	Message  string      `json:"message"`
	Details  []string    `json:"details,omitempty"`
	Current  interface{} `json:"current,omitempty"`
	Baseline interface{} `json:"baseline,omitempty"`
}

// EC2Drift represents a configuration drift in EC2 security groups.
type EC2Drift struct {
	SecurityGroup string        `json:"security_group"`
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	Message       string        `json:"message"`
	AddedRules    []InboundRule `json:"added_rules,omitempty"`
	RemovedRules  []InboundRule `json:"removed_rules,omitempty"`
	Current       *SGConfig     `json:"current,omitempty"`
	Baseline      *SGConfig     `json:"baseline,omitempty"`
}

// S3ScanResults holds results from an S3 security scan.
type S3ScanResults struct {
	Secure []string
	AtRisk []string
}

// EC2ScanResults holds results from an EC2 security scan.
type EC2ScanResults struct {
	Secure  []string
	AtRisk  []string
	Details map[string]*SGDetails
}

// SGDetails holds config and risk info for one security group.
type SGDetails struct {
	Config SGConfig
	Risks  []Risk
}

// RemediationResults holds results from a fix/remediation operation.
type RemediationResults struct {
	Fixed   []RemediationItem
	Failed  []RemediationItem
	Skipped []RemediationItem
}

// RemediationItem represents a single remediation action.
type RemediationItem struct {
	Bucket        string `json:"bucket,omitempty"`
	SecurityGroup string `json:"security_group,omitempty"`
	Name          string `json:"name,omitempty"`
	Type          string `json:"type,omitempty"`
	RuleRemoved   string `json:"rule_removed,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Error         string `json:"error,omitempty"`
	DryRun        bool   `json:"dry_run,omitempty"`
}

// IAMFinding represents a single IAM security finding.
type IAMFinding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
}

// IAMScanResults holds results from an IAM security scan.
type IAMScanResults struct {
	Findings []IAMFinding
}

// CloudTrailFinding represents a single CloudTrail security finding.
type CloudTrailFinding struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	TrailName string `json:"trail_name"`
	Message   string `json:"message"`
}

// TrailSummary holds key attributes of a CloudTrail trail.
type TrailSummary struct {
	Name              string `json:"name"`
	IsLogging         bool   `json:"is_logging"`
	IsMultiRegion     bool   `json:"is_multi_region"`
	LogValidation     bool   `json:"log_validation"`
	S3Bucket          string `json:"s3_bucket"`
	HasCustomEventSel bool   `json:"has_custom_event_selectors"`
}

// CloudTrailScanResults holds results from a CloudTrail security scan.
type CloudTrailScanResults struct {
	Trails   []TrailSummary
	Findings []CloudTrailFinding
}

// IAMUserSnapshot captures the security-relevant state of one IAM user.
type IAMUserSnapshot struct {
	Username         string   `json:"username"`
	HasConsoleAccess bool     `json:"has_console_access"`
	MFAEnabled       bool     `json:"mfa_enabled"`
	AttachedPolicies []string `json:"attached_policies"`
	AccessKeyIDs     []string `json:"access_key_ids"`
}

// IAMPasswordPolicySnapshot captures the account password policy state.
type IAMPasswordPolicySnapshot struct {
	Exists                 bool  `json:"exists"`
	MinimumPasswordLength  int32 `json:"minimum_password_length"`
	RequireUppercase       bool  `json:"require_uppercase"`
	RequireLowercase       bool  `json:"require_lowercase"`
	RequireNumbers         bool  `json:"require_numbers"`
	RequireSymbols         bool  `json:"require_symbols"`
	ExpirePasswords        bool  `json:"expire_passwords"`
	MaxPasswordAge         int32 `json:"max_password_age"`
	PasswordReusePrevention int32 `json:"password_reuse_prevention"`
}

// IAMBaseline represents the stored IAM baseline.
type IAMBaseline struct {
	CreatedAt      string                    `json:"created_at"`
	UpdatedAt      string                    `json:"updated_at"`
	PasswordPolicy IAMPasswordPolicySnapshot `json:"password_policy"`
	Users          map[string]IAMUserSnapshot `json:"users"`
}

// IAMDrift represents a single IAM configuration change since baseline.
type IAMDrift struct {
	Type     string `json:"type"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// CloudTrailTrailSnapshot captures the security-relevant state of one trail.
type CloudTrailTrailSnapshot struct {
	Name             string `json:"name"`
	IsLogging        bool   `json:"is_logging"`
	IsMultiRegion    bool   `json:"is_multi_region"`
	LogValidation    bool   `json:"log_validation"`
	S3Bucket         string `json:"s3_bucket"`
	ReadWriteType    string `json:"read_write_type"`
}

// CloudTrailBaseline represents the stored CloudTrail baseline.
type CloudTrailBaseline struct {
	CreatedAt string                             `json:"created_at"`
	UpdatedAt string                             `json:"updated_at"`
	Trails    map[string]CloudTrailTrailSnapshot `json:"trails"`
}

// CloudTrailDrift represents a single CloudTrail configuration change since baseline.
type CloudTrailDrift struct {
	Type      string `json:"type"`
	TrailName string `json:"trail_name"`
	Message   string `json:"message"`
	OldValue  string `json:"old_value,omitempty"`
	NewValue  string `json:"new_value,omitempty"`
}

// VPCFinding represents a single VPC security finding.
type VPCFinding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	VPCID    string `json:"vpc_id"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
}

// VPCScanResults holds results from a VPC security scan.
type VPCScanResults struct {
	Findings []VPCFinding
}

// VPCSubnetSnapshot captures security-relevant state of a subnet.
type VPCSubnetSnapshot struct {
	SubnetID            string `json:"subnet_id"`
	CIDR                string `json:"cidr"`
	AutoAssignPublicIP  bool   `json:"auto_assign_public_ip"`
}

// VPCSnapshot captures security-relevant state of a VPC.
type VPCSnapshot struct {
	VPCID         string                       `json:"vpc_id"`
	IsDefault     bool                         `json:"is_default"`
	FlowLogsEnabled bool                       `json:"flow_logs_enabled"`
	Subnets       map[string]VPCSubnetSnapshot `json:"subnets"`
}

// VPCBaseline represents the stored VPC baseline.
type VPCBaseline struct {
	CreatedAt string                 `json:"created_at"`
	UpdatedAt string                 `json:"updated_at"`
	VPCs      map[string]VPCSnapshot `json:"vpcs"`
}

// VPCDrift represents a single VPC configuration change since baseline.
type VPCDrift struct {
	Type     string `json:"type"`
	VPCID    string `json:"vpc_id"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// S3Baseline represents the stored S3 baseline.
type S3Baseline struct {
	CreatedAt string                     `json:"created_at"`
	UpdatedAt string                     `json:"updated_at"`
	Buckets   map[string]S3BucketConfig  `json:"buckets"`
}

// EC2Baseline represents the stored EC2 baseline.
type EC2Baseline struct {
	CreatedAt      string              `json:"created_at"`
	UpdatedAt      string              `json:"updated_at"`
	Region         string              `json:"region"`
	SecurityGroups map[string]SGConfig `json:"security_groups"`
}
