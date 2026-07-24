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
			"alertType": strAttr(alertType),
			"severity":  strAttr(severity),
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("[SNS] Published to %s topic. MessageID: %s\n", service, aws.ToString(out.MessageId))
	return nil
}

// ── Generic scan/drift helpers ───────────────────────────────

// snsPublishScanAlert is a generic helper for scan-type alerts.
func snsPublishScanAlert(ctx context.Context, service, severity string, count int, bodyFn func() string) {
	if count == 0 {
		return
	}
	subject := fmt.Sprintf("[%s ALERT] DriftShield: %d Issue(s)", service, count)
	header := fmt.Sprintf("DriftShield %s Alert | %s\n%d finding(s) detected.\n\n",
		service, time.Now().Format("2006-01-02 15:04:05"), count)
	if err := publishSNS(ctx, service, "SCAN", severity, subject, header+bodyFn()); err != nil {
		fmt.Printf("[SNS] %s alert failed: %v\n", service, err)
	}
}

// snsPublishDriftAlert is a generic helper for drift-type alerts.
func snsPublishDriftAlert(ctx context.Context, service, severity string, count int, bodyFn func() string) {
	if count == 0 {
		return
	}
	subject := fmt.Sprintf("[%s DRIFT] DriftShield: %d Change(s)", service, count)
	header := fmt.Sprintf("DriftShield %s Drift | %s\n%d configuration change(s) detected.\n\n",
		service, time.Now().Format("2006-01-02 15:04:05"), count)
	if err := publishSNS(ctx, service, "DRIFT", severity, subject, header+bodyFn()); err != nil {
		fmt.Printf("[SNS] %s drift alert failed: %v\n", service, err)
	}
}

// ── S3 ────────────────────────────────────────────────────────

func SNSPublishS3Alerts(ctx context.Context, atRisk []string) {
	snsPublishScanAlert(ctx, "s3", "HIGH", len(atRisk), func() string {
		msg := ""
		for _, b := range atRisk {
			msg += "  - " + b + "\n"
		}
		return msg
	})
}

func SNSPublishS3DriftAlerts(ctx context.Context, drifts []types.S3Drift) {
	snsPublishDriftAlert(ctx, "s3", "MEDIUM", len(drifts), func() string {
		msg := ""
		for _, d := range drifts {
			msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.Bucket, d.Message)
		}
		return msg
	})
}

// ── EC2 ───────────────────────────────────────────────────────

func SNSPublishEC2Alerts(ctx context.Context, atRisk []string, details map[string]*types.SGDetails) {
	snsPublishScanAlert(ctx, "ec2", "CRITICAL", len(atRisk), func() string {
		msg := ""
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
		return msg
	})
}

func SNSPublishEC2DriftAlerts(ctx context.Context, drifts []types.EC2Drift) {
	snsPublishDriftAlert(ctx, "ec2", "MEDIUM", len(drifts), func() string {
		msg := ""
		for _, d := range drifts {
			msg += fmt.Sprintf("  [%s] %s (%s)\n", d.Type, d.Name, d.SecurityGroup)
		}
		return msg
	})
}

// ── IAM ───────────────────────────────────────────────────────

func SNSPublishIAMAlerts(ctx context.Context, findings []types.IAMFinding) {
	severity := "MEDIUM"
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			severity = "CRITICAL"
			break
		}
	}
	snsPublishScanAlert(ctx, "iam", severity, len(findings), func() string {
		msg := ""
		for _, f := range findings {
			msg += fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.Resource, f.Message)
		}
		return msg
	})
}

func SNSPublishIAMDriftAlerts(ctx context.Context, drifts []types.IAMDrift) {
	snsPublishDriftAlert(ctx, "iam", "HIGH", len(drifts), func() string {
		msg := ""
		for _, d := range drifts {
			msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.Resource, d.Message)
			if d.OldValue != "" {
				msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		return msg
	})
}

// ── CloudTrail ────────────────────────────────────────────────

func SNSPublishCloudTrailAlerts(ctx context.Context, findings []types.CloudTrailFinding) {
	severity := "MEDIUM"
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			severity = "CRITICAL"
			break
		}
	}
	snsPublishScanAlert(ctx, "cloudtrail", severity, len(findings), func() string {
		msg := ""
		for _, f := range findings {
			msg += fmt.Sprintf("  [%s] Trail '%s': %s\n", f.Severity, f.TrailName, f.Message)
		}
		return msg
	})
}

func SNSPublishCloudTrailDriftAlerts(ctx context.Context, drifts []types.CloudTrailDrift) {
	snsPublishDriftAlert(ctx, "cloudtrail", "HIGH", len(drifts), func() string {
		msg := ""
		for _, d := range drifts {
			msg += fmt.Sprintf("  [%s] Trail '%s': %s\n", d.Type, d.TrailName, d.Message)
			if d.OldValue != "" {
				msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		return msg
	})
}

// ── VPC ───────────────────────────────────────────────────────

func SNSPublishVPCAlerts(ctx context.Context, findings []types.VPCFinding) {
	snsPublishScanAlert(ctx, "vpc", "HIGH", len(findings), func() string {
		msg := ""
		for _, f := range findings {
			msg += fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.Resource, f.Message)
		}
		return msg
	})
}

func SNSPublishVPCDriftAlerts(ctx context.Context, drifts []types.VPCDrift) {
	snsPublishDriftAlert(ctx, "vpc", "MEDIUM", len(drifts), func() string {
		msg := ""
		for _, d := range drifts {
			msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.Resource, d.Message)
			if d.OldValue != "" {
				msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		return msg
	})
}

// ── RDS ───────────────────────────────────────────────────────

func SNSPublishRDSAlerts(ctx context.Context, findings []types.RDSFinding) {
	snsPublishScanAlert(ctx, "rds", "HIGH", len(findings), func() string {
		msg := ""
		for _, f := range findings {
			msg += fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.InstanceID, f.Message)
		}
		return msg
	})
}

func SNSPublishRDSDriftAlerts(ctx context.Context, drifts []types.RDSDrift) {
	snsPublishDriftAlert(ctx, "rds", "MEDIUM", len(drifts), func() string {
		msg := ""
		for _, d := range drifts {
			msg += fmt.Sprintf("  [%s] %s: %s\n", d.Type, d.InstanceID, d.Message)
			if d.OldValue != "" {
				msg += fmt.Sprintf("      Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		return msg
	})
}
