package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

type slackBlock struct {
	Type   string      `json:"type"`
	Text   interface{} `json:"text,omitempty"`
	Fields interface{} `json:"fields,omitempty"`
}

type slackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

type slackMessage struct {
	Text   string       `json:"text,omitempty"`
	Blocks []slackBlock `json:"blocks"`
}

func postSlack(msg slackMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	resp, err := http.Post(config.SlackConfig.WebhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}
	return nil
}

// SendS3SlackAlert sends a Slack alert for at-risk S3 buckets.
func SendS3SlackAlert(atRisk []string) {
	if !config.SlackConfig.Enabled {
		fmt.Println("[SLACK] Alerts disabled (enable in config)")
		return
	}

	bucketList := ""
	for _, b := range atRisk {
		bucketList += "- " + b + "\n"
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	msg := slackMessage{
		Blocks: []slackBlock{
			{Type: "header", Text: &slackText{Type: "plain_text", Text: "DriftShield Security Alert"}},
			{Type: "section", Fields: []slackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*At-Risk Buckets:*\n%d", len(atRisk))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Time:*\n%s", now)},
			}},
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("*Buckets with public access risk:*\n%s", bucketList)}},
		},
	}

	if err := postSlack(msg); err != nil {
		fmt.Printf("[SLACK] Failed: %v\n", err)
	} else {
		fmt.Println("[SLACK] Alert sent successfully")
	}
}

// sendEC2SlackAlert sends a Slack alert for at-risk EC2 security groups.
func sendEC2SlackAlert(atRisk []string, details map[string]*types.SGDetails) {
	if !config.SlackConfig.Enabled {
		return
	}

	var blocks []string
	for _, sgID := range atRisk {
		d := details[sgID]
		if d == nil {
			continue
		}
		risksText := ""
		for _, r := range d.Risks {
			risksText += fmt.Sprintf("• [%s] %s\n", r.Severity, r.Message)
		}
		blocks = append(blocks, fmt.Sprintf("*%s* (`%s`)\n%s", d.Config.GroupName, sgID, risksText))
	}

	combined := ""
	for _, b := range blocks {
		combined += b + "\n\n"
	}

	msg := slackMessage{
		Text: fmt.Sprintf("EC2 Security Alert: %d risky security group(s)", len(atRisk)),
		Blocks: []slackBlock{
			{Type: "header", Text: &slackText{Type: "plain_text", Text: "DriftShield EC2 Alert"}},
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: combined}},
		},
	}

	if err := postSlack(msg); err != nil {
		fmt.Printf("[SLACK] EC2 alert failed: %v\n", err)
	} else {
		fmt.Println("[SLACK] EC2 alert sent successfully")
	}
}
