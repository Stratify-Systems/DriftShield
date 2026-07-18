package alerts

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func newSNSClient(ctx context.Context) (*sns.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(config.SNSConfig.Region))
	if err != nil {
		return nil, err
	}
	return sns.NewFromConfig(cfg), nil
}

// topicARN returns the service-specific topic ARN if configured, otherwise the default.
func topicARN(service string) string {
	if arn, ok := config.SNSConfig.ServiceTopics[service]; ok && arn != "" {
		return arn
	}
	return config.SNSConfig.DefaultTopicARN
}

// strAttr builds a string SNS message attribute.
func strAttr(value string) snstypes.MessageAttributeValue {
	return snstypes.MessageAttributeValue{
		DataType:    aws.String("String"),
		StringValue: aws.String(value),
	}
}

// publishSNS publishes a message to the resolved topic with standard message attributes.
func publishSNS(ctx context.Context, service, alertType, severity, subject, message string) error {
	if !config.SNSConfig.Enabled {
		return nil
	}

	client, err := newSNSClient(ctx)
	if err != nil {
		return err
	}

	out, err := client.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(topicARN(service)),
		Subject:  aws.String(subject),
		Message:  aws.String(message),
		MessageAttributes: map[string]snstypes.MessageAttributeValue{
			"service":   strAttr(service),
			"alertType": strAttr(alertType), // SCAN or DRIFT
			"severity":  strAttr(severity),
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("[SNS] Published to %s topic. MessageID: %s\n", service, aws.ToString(out.MessageId))
	return nil
}

// ── S3 ────────────────────────────────────────────────────────

func SNSPublishS3Alerts(ctx context.Context, atRisk []string) {
	if len(atRisk) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield S3 Alert | %s\n%d at-risk bucket(s) detected with public access risk.\n\nBuckets:\n",
		time.Now().Format("2006-01-02 15:04:05"), len(atRisk))
	for _, b := range atRisk {
		msg += "  - " + b + "\n"
	}
	if err := publishSNS(ctx, "s3", "SCAN", "HIGH",
		fmt.Sprintf("[S3 ALERT] DriftShield: %d At-Risk Bucket(s)", len(atRisk)), msg); err != nil {
		fmt.Printf("[SNS] S3 alert failed: %v\n", err)
	}
}

func SNSPublishS3DriftAlerts(ctx context.Context, drifts []types.S3Drift) {
	if len(drifts) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield S3 Drift | %s\n%d configuration change(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(drifts))
	for _, d := range drifts {
		msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.Bucket, d.Message)
	}
	if err := publishSNS(ctx, "s3", "DRIFT", "MEDIUM",
		fmt.Sprintf("[S3 DRIFT] DriftShield: %d Change(s)", len(drifts)), msg); err != nil {
		fmt.Printf("[SNS] S3 drift alert failed: %v\n", err)
	}
}

// ── EC2 ───────────────────────────────────────────────────────

func SNSPublishEC2Alerts(ctx context.Context, atRisk []string, details map[string]*types.SGDetails) {
	if len(atRisk) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield EC2 Alert | %s\n%d risky security group(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(atRisk))
	for _, sgID := range atRisk {
		d := details[sgID]
		if d == nil {
			continue
		}
		msg += fmt.Sprintf("  - %s (%s)\n", d.Config.GroupName, sgID)
		for _, r := range d.Risks {
			msg += fmt.Sprintf("      [%s] %s\n", r.Severity, r.Message)
		}
	}
	if err := publishSNS(ctx, "ec2", "SCAN", "CRITICAL",
		fmt.Sprintf("[EC2 ALERT] DriftShield: %d Risky Security Group(s)", len(atRisk)), msg); err != nil {
		fmt.Printf("[SNS] EC2 alert failed: %v\n", err)
	}
}

func SNSPublishEC2DriftAlerts(ctx context.Context, drifts []types.EC2Drift) {
	if len(drifts) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield EC2 Drift | %s\n%d security group change(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(drifts))
	for _, d := range drifts {
		msg += fmt.Sprintf("  [%s] %s (%s)\n", d.Type, d.Name, d.SecurityGroup)
	}
	if err := publishSNS(ctx, "ec2", "DRIFT", "MEDIUM",
		fmt.Sprintf("[EC2 DRIFT] DriftShield: %d Change(s)", len(drifts)), msg); err != nil {
		fmt.Printf("[SNS] EC2 drift alert failed: %v\n", err)
	}
}

// ── IAM ───────────────────────────────────────────────────────

func SNSPublishIAMAlerts(ctx context.Context, findings []types.IAMFinding) {
	if len(findings) == 0 {
		return
	}
	severity := "MEDIUM"
	msg := fmt.Sprintf("DriftShield IAM Alert | %s\n%d finding(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(findings))
	for _, f := range findings {
		msg += fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.Resource, f.Message)
		if f.Severity == "CRITICAL" {
			severity = "CRITICAL"
		}
	}
	if err := publishSNS(ctx, "iam", "SCAN", severity,
		fmt.Sprintf("[IAM ALERT] DriftShield: %d Issue(s)", len(findings)), msg); err != nil {
		fmt.Printf("[SNS] IAM alert failed: %v\n", err)
	}
}

func SNSPublishIAMDriftAlerts(ctx context.Context, drifts []types.IAMDrift) {
	if len(drifts) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield IAM Drift | %s\n%d configuration change(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(drifts))
	for _, d := range drifts {
		msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.Resource, d.Message)
		if d.OldValue != "" {
			msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
		}
	}
	if err := publishSNS(ctx, "iam", "DRIFT", "HIGH",
		fmt.Sprintf("[IAM DRIFT] DriftShield: %d Change(s)", len(drifts)), msg); err != nil {
		fmt.Printf("[SNS] IAM drift alert failed: %v\n", err)
	}
}

// ── CloudTrail ────────────────────────────────────────────────

func SNSPublishCloudTrailAlerts(ctx context.Context, findings []types.CloudTrailFinding) {
	if len(findings) == 0 {
		return
	}
	severity := "MEDIUM"
	msg := fmt.Sprintf("DriftShield CloudTrail Alert | %s\n%d finding(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(findings))
	for _, f := range findings {
		msg += fmt.Sprintf("  [%s] Trail '%s': %s\n", f.Severity, f.TrailName, f.Message)
		if f.Severity == "CRITICAL" {
			severity = "CRITICAL"
		}
	}
	if err := publishSNS(ctx, "cloudtrail", "SCAN", severity,
		fmt.Sprintf("[CLOUDTRAIL ALERT] DriftShield: %d Issue(s)", len(findings)), msg); err != nil {
		fmt.Printf("[SNS] CloudTrail alert failed: %v\n", err)
	}
}

func SNSPublishCloudTrailDriftAlerts(ctx context.Context, drifts []types.CloudTrailDrift) {
	if len(drifts) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield CloudTrail Drift | %s\n%d trail change(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(drifts))
	for _, d := range drifts {
		msg += fmt.Sprintf("  [%s] Trail '%s': %s\n", d.Type, d.TrailName, d.Message)
		if d.OldValue != "" {
			msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
		}
	}
	if err := publishSNS(ctx, "cloudtrail", "DRIFT", "HIGH",
		fmt.Sprintf("[CLOUDTRAIL DRIFT] DriftShield: %d Change(s)", len(drifts)), msg); err != nil {
		fmt.Printf("[SNS] CloudTrail drift alert failed: %v\n", err)
	}
}

// ── VPC ───────────────────────────────────────────────────────

func SNSPublishVPCAlerts(ctx context.Context, findings []types.VPCFinding) {
	if len(findings) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield VPC Alert | %s\n%d finding(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(findings))
	for _, f := range findings {
		msg += fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.Resource, f.Message)
	}
	if err := publishSNS(ctx, "vpc", "SCAN", "HIGH",
		fmt.Sprintf("[VPC ALERT] DriftShield: %d Issue(s)", len(findings)), msg); err != nil {
		fmt.Printf("[SNS] VPC alert failed: %v\n", err)
	}
}

func SNSPublishVPCDriftAlerts(ctx context.Context, drifts []types.VPCDrift) {
	if len(drifts) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield VPC Drift | %s\n%d configuration change(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(drifts))
	for _, d := range drifts {
		msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.Resource, d.Message)
		if d.OldValue != "" {
			msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
		}
	}
	if err := publishSNS(ctx, "vpc", "DRIFT", "MEDIUM",
		fmt.Sprintf("[VPC DRIFT] DriftShield: %d Change(s)", len(drifts)), msg); err != nil {
		fmt.Printf("[SNS] VPC drift alert failed: %v\n", err)
	}
}

// ── RDS ───────────────────────────────────────────────────────

func SNSPublishRDSAlerts(ctx context.Context, findings []types.RDSFinding) {
	if len(findings) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield RDS Alert | %s\n%d finding(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(findings))
	for _, f := range findings {
		msg += fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.InstanceID, f.Message)
	}
	if err := publishSNS(ctx, "rds", "SCAN", "HIGH",
		fmt.Sprintf("[RDS ALERT] DriftShield: %d Issue(s)", len(findings)), msg); err != nil {
		fmt.Printf("[SNS] RDS alert failed: %v\n", err)
	}
}

func SNSPublishRDSDriftAlerts(ctx context.Context, drifts []types.RDSDrift) {
	if len(drifts) == 0 {
		return
	}
	msg := fmt.Sprintf("DriftShield RDS Drift | %s\n%d configuration change(s) detected.\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(drifts))
	for _, d := range drifts {
		msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.InstanceID, d.Message)
		if d.OldValue != "" {
			msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
		}
	}
	if err := publishSNS(ctx, "rds", "DRIFT", "MEDIUM",
		fmt.Sprintf("[RDS DRIFT] DriftShield: %d Change(s)", len(drifts)), msg); err != nil {
		fmt.Printf("[SNS] RDS drift alert failed: %v\n", err)
	}
}
