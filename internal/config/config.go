// Package config holds DriftShield configuration settings.
package config

// Version of DriftShield.
const Version = "2.0.0"

// Default AWS region.
var (
	AWSRegion     = "ap-south-1"
	CurrentRegion = ""
)

// SESConfig holds AWS SES email settings.
type SESConfig struct {
	Enabled        bool
	Region         string
	SenderEmail    string
	RecipientEmail string
}

// SlackSettings holds Slack webhook settings.
type SlackSettings struct {
	Enabled    bool
	WebhookURL string
}

// AWSSESConfig is the active SES configuration.
var AWSSESConfig = SESConfig{
	Enabled:        true,
	Region:         "ap-south-1",
	SenderEmail:    "tksurya164@gmail.com",
	RecipientEmail: "suryatk2007@gmail.com",
}

// SlackConfig is the active Slack configuration.
var SlackConfig = SlackSettings{
	Enabled:    false,
	WebhookURL: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
}

// SNSSettings holds AWS SNS configuration.
type SNSSettings struct {
	Enabled           bool
	Region            string
	DefaultTopicARN   string
	ServiceTopics     map[string]string // optional per-service topic ARNs
}

// SNSConfig is the active SNS configuration.
// Set DefaultTopicARN to your SNS topic ARN to enable.
// Optionally set ServiceTopics to route per-service alerts to dedicated topics.
// Example ServiceTopics keys: "s3", "ec2", "iam", "cloudtrail", "vpc", "rds"
var SNSConfig = SNSSettings{
	Enabled:         true,
	Region:          "ap-south-1",
	DefaultTopicARN: "arn:aws:sns:ap-south-1:892978324911:driftshield-alerts",
	ServiceTopics:   map[string]string{},
}

// Baseline file paths.
var (
	BaselineFile           = "baselines/s3_baseline.json"
	EC2BaselineFile        = "baselines/ec2_baseline.json"
	IAMBaselineFile        = "baselines/iam_baseline.json"
	CloudTrailBaselineFile = "baselines/cloudtrail_baseline.json"
	VPCBaselineFile        = "baselines/vpc_baseline.json"
	RDSBaselineFile        = "baselines/rds_baseline.json"
)

// GetRegion returns the effective AWS region.
func GetRegion() string {
	if CurrentRegion != "" {
		return CurrentRegion
	}
	return AWSRegion
}
