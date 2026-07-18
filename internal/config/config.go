// Package config holds DriftShield configuration settings.
package config

import "os"

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
	Enabled:        os.Getenv("DRIFTSHIELD_SES_ENABLED") == "true",
	Region:         getEnvOrDefault("DRIFTSHIELD_SES_REGION", "ap-south-1"),
	SenderEmail:    os.Getenv("DRIFTSHIELD_SES_SENDER"),
	RecipientEmail: os.Getenv("DRIFTSHIELD_SES_RECIPIENT"),
}

// SlackConfig is the active Slack configuration.
var SlackConfig = SlackSettings{
	Enabled:    os.Getenv("DRIFTSHIELD_SLACK_ENABLED") == "true",
	WebhookURL: os.Getenv("DRIFTSHIELD_SLACK_WEBHOOK_URL"),
}

// SNSSettings holds AWS SNS configuration.
type SNSSettings struct {
	Enabled         bool
	Region          string
	DefaultTopicARN string
	ServiceTopics   map[string]string // optional per-service topic ARNs
}

// SNSConfig is the active SNS configuration.
// Set DefaultTopicARN to your SNS topic ARN to enable.
// Optionally set ServiceTopics to route per-service alerts to dedicated topics.
// Example ServiceTopics keys: "s3", "ec2", "iam", "cloudtrail", "vpc", "rds"
var SNSConfig = SNSSettings{
	Enabled:         os.Getenv("DRIFTSHIELD_SNS_ENABLED") == "true",
	Region:          getEnvOrDefault("DRIFTSHIELD_SNS_REGION", "ap-south-1"),
	DefaultTopicARN: os.Getenv("DRIFTSHIELD_SNS_TOPIC_ARN"),
	ServiceTopics:   map[string]string{},
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
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
