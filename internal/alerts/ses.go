package alerts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	sestypes "github.com/aws/aws-sdk-go-v2/service/ses/types"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/display"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func newSESClient(ctx context.Context) (*ses.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(config.AWSSESConfig.Region))
	if err != nil {
		return nil, err
	}
	return ses.NewFromConfig(cfg), nil
}

func sendEmail(ctx context.Context, subject, textBody, htmlBody string) error {
	client, err := newSESClient(ctx)
	if err != nil {
		return err
	}
	out, err := client.SendEmail(ctx, &ses.SendEmailInput{
		Source:      aws.String(config.AWSSESConfig.SenderEmail),
		Destination: &sestypes.Destination{ToAddresses: []string{config.AWSSESConfig.RecipientEmail}},
		Message: &sestypes.Message{
			Subject: &sestypes.Content{Data: aws.String(subject), Charset: aws.String("UTF-8")},
			Body: &sestypes.Body{
				Text: &sestypes.Content{Data: aws.String(textBody), Charset: aws.String("UTF-8")},
				Html: &sestypes.Content{Data: aws.String(htmlBody), Charset: aws.String("UTF-8")},
			},
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("[EMAIL] Sent successfully. Message ID: %s\n", aws.ToString(out.MessageId))
	return nil
}

// SendS3Alerts sends alerts for at-risk S3 buckets via all configured channels.
func SendS3Alerts(ctx context.Context, atRisk []string) {
	if len(atRisk) == 0 {
		return
	}
	fmt.Printf("\n[ALERT] Sending alerts for %d at-risk bucket(s)...\n\n", len(atRisk))
	SendS3SESAlert(ctx, atRisk)
	SendS3SlackAlert(atRisk)
}

// SendS3SESAlert sends an email alert for at-risk S3 buckets.
func SendS3SESAlert(ctx context.Context, atRisk []string) {
	if !config.AWSSESConfig.Enabled {
		fmt.Println("[EMAIL] AWS SES alerts disabled (enable in config)")
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	var listHTML, listText strings.Builder
	for _, b := range atRisk {
		fmt.Fprintf(&listHTML, "<li>%s</li>", b)
		fmt.Fprintf(&listText, "  - %s\n", b)
	}

	html := fmt.Sprintf(`<html><body>
<h2>DriftShield Security Alert</h2>
<p><strong>Time:</strong> %s</p>
<p><strong>Issue:</strong> S3 buckets detected with public access risk</p>
<h3>At-Risk Buckets:</h3><ul>%s</ul>
<h3>Recommended Actions:</h3><ol>
<li>Review bucket permissions in AWS Console</li>
<li>Enable "Block Public Access" settings</li>
<li>Check for sensitive data exposure</li></ol>
<p>---<br>DriftShield - Cloud Security Monitoring</p>
</body></html>`, now, listHTML.String())

	text := fmt.Sprintf("DriftShield Security Alert\n===========================\nTime: %s\nIssue: S3 buckets with public access risk\n\nAt-Risk Buckets:\n%s\n---\nDriftShield", now, listText.String())

	fmt.Println("[EMAIL] Sending email via AWS SES...")
	if err := sendEmail(ctx, fmt.Sprintf("[ALERT] DriftShield: %d At-Risk S3 Bucket(s)", len(atRisk)), text, html); err != nil {
		fmt.Printf("[EMAIL] Failed: %v\n", err)
	}
}

// SendS3DriftAlerts sends email alerts for S3 configuration drift.
func SendS3DriftAlerts(ctx context.Context, drifts []types.S3Drift) {
	if len(drifts) == 0 || !config.AWSSESConfig.Enabled {
		return
	}
	fmt.Println("\n[ALERT] Sending drift alerts...\n")

	now := time.Now().Format("2006-01-02 15:04:05")
	var rows, textList strings.Builder
	for _, d := range drifts {
		details := strings.Join(d.Details, "<br>")
		if details == "" {
			details = d.Message
		}
		fmt.Fprintf(&rows, `<tr><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td></tr>`, d.Bucket, d.Type, details)
		fmt.Fprintf(&textList, "  - %s: %s\n", d.Bucket, d.Message)
	}

	html := fmt.Sprintf(`<html><body>
<h2>DriftShield - Configuration Drift Detected</h2>
<p><strong>Time:</strong> %s</p>
<h3>Drift Summary (%d change(s)):</h3>
<table style="border-collapse:collapse;width:100%%">
<tr style="background:#f2f2f2"><th style="padding:8px;border:1px solid #ddd">Bucket</th><th style="padding:8px;border:1px solid #ddd">Change Type</th><th style="padding:8px;border:1px solid #ddd">Details</th></tr>%s</table>
<p>---<br>DriftShield - Cloud Security Monitoring</p>
</body></html>`, now, len(drifts), rows.String())

	text := fmt.Sprintf("DriftShield - Drift Detected\nTime: %s\nDrifts (%d):\n%s", now, len(drifts), textList.String())

	fmt.Println("[EMAIL] Sending drift alert...")
	if err := sendEmail(ctx, fmt.Sprintf("[DRIFT] DriftShield: %d Configuration Change(s) Detected", len(drifts)), text, html); err != nil {
		fmt.Printf("[EMAIL] Drift alert failed: %v\n", err)
	}
}

// SendEC2Alerts sends alerts for at-risk EC2 security groups via all channels.
func SendEC2Alerts(ctx context.Context, atRisk []string, details map[string]*types.SGDetails) {
	if len(atRisk) == 0 {
		return
	}
	fmt.Println("\n[ALERT] Sending EC2 security alerts...")
	if config.AWSSESConfig.Enabled {
		sendEC2SESAlert(ctx, atRisk, details)
	}
	if config.SlackConfig.Enabled {
		sendEC2SlackAlert(atRisk, details)
	}
}

func sendEC2SESAlert(ctx context.Context, atRisk []string, details map[string]*types.SGDetails) {
	now := time.Now().Format("2006-01-02 15:04:05")
	var groupsHTML, groupsText strings.Builder

	for _, sgID := range atRisk {
		d := details[sgID]
		if d == nil {
			continue
		}
		var risksHTML, risksText strings.Builder
		for _, r := range d.Risks {
			fmt.Fprintf(&risksHTML, "<li><strong>%s</strong>: %s</li>", r.Severity, r.Message)
			fmt.Fprintf(&risksText, "      - [%s] %s\n", r.Severity, r.Message)
		}
		fmt.Fprintf(&groupsHTML, "<li><strong>%s</strong> (%s)<ul>%s</ul></li>", d.Config.GroupName, sgID, risksHTML.String())
		fmt.Fprintf(&groupsText, "\n  - %s (%s):\n%s", d.Config.GroupName, sgID, risksText.String())
	}

	html := fmt.Sprintf(`<html><body>
<h2>DriftShield EC2 Security Alert</h2>
<p><strong>Time:</strong> %s</p>
<h3>At-Risk Security Groups:</h3><ul>%s</ul>
<h3>Recommended Actions:</h3><ol>
<li>Review inbound rules in AWS Console</li>
<li>Restrict SSH/RDP access to specific IPs</li>
<li>Remove unnecessary open ports</li></ol>
<p>---<br>DriftShield</p></body></html>`, now, groupsHTML.String())

	text := fmt.Sprintf("DriftShield EC2 Alert\nTime: %s\nAt-Risk Groups:%s", now, groupsText.String())

	fmt.Println("[EMAIL] Sending EC2 security alert...")
	if err := sendEmail(ctx, fmt.Sprintf("[ALERT] DriftShield: %d Risky EC2 Security Group(s)", len(atRisk)), text, html); err != nil {
		fmt.Printf("[EMAIL] EC2 alert failed: %v\n", err)
	}
}

// SendIAMAlerts sends email alerts for IAM security findings.
func SendIAMAlerts(ctx context.Context, findings []types.IAMFinding) {
	if len(findings) == 0 || !config.AWSSESConfig.Enabled {
		return
	}
	fmt.Printf("\n[ALERT] Sending IAM alerts for %d finding(s)...\n", len(findings))

	now := time.Now().Format("2006-01-02 15:04:05")
	var rows, textList strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&rows, `<tr><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td></tr>`,
			f.Severity, f.Resource, f.Message)
		fmt.Fprintf(&textList, "  [%s] %s: %s\n", f.Severity, f.Resource, f.Message)
	}

	html := fmt.Sprintf(`<html><body>
<h2>DriftShield IAM Security Alert</h2>
<p><strong>Time:</strong> %s</p>
<h3>Findings (%d):</h3>
<table style="border-collapse:collapse;width:100%%">
<tr style="background:#f2f2f2"><th style="padding:8px;border:1px solid #ddd">Severity</th><th style="padding:8px;border:1px solid #ddd">Resource</th><th style="padding:8px;border:1px solid #ddd">Issue</th></tr>%s</table>
<p>---<br>DriftShield</p></body></html>`, now, len(findings), rows.String())

	text := fmt.Sprintf("DriftShield IAM Alert\nTime: %s\nFindings (%d):\n%s", now, len(findings), textList.String())

	if err := sendEmail(ctx, fmt.Sprintf("[IAM ALERT] DriftShield: %d IAM Security Issue(s)", len(findings)), text, html); err != nil {
		fmt.Printf("[EMAIL] IAM alert failed: %v\n", err)
	}
}

// SendCloudTrailAlerts sends email alerts for CloudTrail security findings.
func SendCloudTrailAlerts(ctx context.Context, findings []types.CloudTrailFinding) {
	if len(findings) == 0 || !config.AWSSESConfig.Enabled {
		return
	}
	fmt.Printf("\n[ALERT] Sending CloudTrail alerts for %d finding(s)...\n", len(findings))

	now := time.Now().Format("2006-01-02 15:04:05")
	var rows, textList strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&rows, `<tr><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td></tr>`,
			f.Severity, f.TrailName, f.Message)
		fmt.Fprintf(&textList, "  [%s] Trail '%s': %s\n", f.Severity, f.TrailName, f.Message)
	}

	html := fmt.Sprintf(`<html><body>
<h2>DriftShield CloudTrail Security Alert</h2>
<p><strong>Time:</strong> %s</p>
<h3>Findings (%d):</h3>
<table style="border-collapse:collapse;width:100%%">
<tr style="background:#f2f2f2"><th style="padding:8px;border:1px solid #ddd">Severity</th><th style="padding:8px;border:1px solid #ddd">Trail</th><th style="padding:8px;border:1px solid #ddd">Issue</th></tr>%s</table>
<p>---<br>DriftShield</p></body></html>`, now, len(findings), rows.String())

	text := fmt.Sprintf("DriftShield CloudTrail Alert\nTime: %s\nFindings (%d):\n%s", now, len(findings), textList.String())

	if err := sendEmail(ctx, fmt.Sprintf("[CLOUDTRAIL ALERT] DriftShield: %d CloudTrail Issue(s)", len(findings)), text, html); err != nil {
		fmt.Printf("[EMAIL] CloudTrail alert failed: %v\n", err)
	}
}

// SendEC2DriftAlerts sends email alerts for EC2 security group drift.
func SendEC2DriftAlerts(ctx context.Context, drifts []types.EC2Drift) {
	if len(drifts) == 0 || !config.AWSSESConfig.Enabled {
		return
	}
	fmt.Println("\n[ALERT] Sending EC2 drift alerts...")

	now := time.Now().Format("2006-01-02 15:04:05")
	var rows, textList strings.Builder

	for _, d := range drifts {
		var detailHTML, detailText string
		switch d.Type {
		case "RULES_CHANGED":
			var buf strings.Builder
			if len(d.AddedRules) > 0 {
				buf.WriteString("<strong>Added:</strong><br>")
				for _, r := range d.AddedRules {
					desc := display.GetPortDescription(r.Protocol, r.FromPort, r.ToPort)
					fmt.Fprintf(&buf, "&nbsp;&nbsp;+ %s from %v<br>", desc, r.Sources)
				}
			}
			if len(d.RemovedRules) > 0 {
				buf.WriteString("<strong>Removed:</strong><br>")
				for _, r := range d.RemovedRules {
					desc := display.GetPortDescription(r.Protocol, r.FromPort, r.ToPort)
					fmt.Fprintf(&buf, "&nbsp;&nbsp;- %s from %v<br>", desc, r.Sources)
				}
			}
			detailHTML = buf.String()
			detailText = fmt.Sprintf("+%d/-%d rules", len(d.AddedRules), len(d.RemovedRules))
		case "NEW_SECURITY_GROUP":
			detailHTML = "New security group (not in baseline)"
			detailText = detailHTML
		case "SECURITY_GROUP_DELETED":
			detailHTML = "Security group was deleted"
			detailText = detailHTML
		}

		fmt.Fprintf(&rows, `<tr><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td><td style="padding:8px;border:1px solid #ddd">%s</td></tr>`,
			d.Name, d.SecurityGroup, d.Type, detailHTML)
		fmt.Fprintf(&textList, "  - %s (%s) - %s: %s\n", d.Name, d.SecurityGroup, d.Type, detailText)
	}

	html := fmt.Sprintf(`<html><body>
<h2>DriftShield - EC2 Security Group Drift Detected</h2>
<p><strong>Time:</strong> %s</p>
<h3>Drift Summary (%d change(s)):</h3>
<table style="border-collapse:collapse;width:100%%">
<tr style="background:#f2f2f2"><th style="padding:8px;border:1px solid #ddd">Name</th><th style="padding:8px;border:1px solid #ddd">Security Group</th><th style="padding:8px;border:1px solid #ddd">Change</th><th style="padding:8px;border:1px solid #ddd">Details</th></tr>%s</table>
<p>---<br>DriftShield</p></body></html>`, now, len(drifts), rows.String())

	text := fmt.Sprintf("EC2 Drift Detected\nTime: %s\nDrifts (%d):\n%s", now, len(drifts), textList.String())

	fmt.Println("[EMAIL] Sending EC2 drift alert...")
	if err := sendEmail(ctx, fmt.Sprintf("[EC2 DRIFT] DriftShield: %d Security Group Change(s) Detected", len(drifts)), text, html); err != nil {
		fmt.Printf("[EMAIL] EC2 drift alert failed: %v\n", err)
	}
}
