package tests

import (
	"context"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/alerts"
	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func TestSendS3SlackAlertDisabled(t *testing.T) {
	orig := config.SlackConfig.Enabled
	config.SlackConfig.Enabled = false
	defer func() { config.SlackConfig.Enabled = orig }()

	alerts.SendS3SlackAlert([]string{"my-bucket"})
}

func TestSendSESAlertsDisabled(t *testing.T) {
	orig := config.AWSSESConfig.Enabled
	config.AWSSESConfig.Enabled = false
	defer func() { config.AWSSESConfig.Enabled = orig }()

	ctx := context.Background()

	alerts.SendS3SESAlert(ctx, []string{"bucket-1"})
	alerts.SendS3DriftAlerts(ctx, []types.S3Drift{{Bucket: "b1", Type: "VERSIONING_CHANGED"}})
	alerts.SendIAMAlerts(ctx, []types.IAMFinding{{Severity: "HIGH", Resource: "user1"}})
	alerts.SendCloudTrailAlerts(ctx, []types.CloudTrailFinding{{Severity: "HIGH", TrailName: "trail1"}})
	alerts.SendIAMDriftAlerts(ctx, []types.IAMDrift{{Resource: "user1", Type: "POLICY_ADDED"}})
	alerts.SendCloudTrailDriftAlerts(ctx, []types.CloudTrailDrift{{TrailName: "trail1", Type: "LOGGING_STOPPED"}})
	alerts.SendVPCAlerts(ctx, []types.VPCFinding{{Severity: "HIGH", Resource: "vpc-1"}})
	alerts.SendVPCDriftAlerts(ctx, []types.VPCDrift{{Resource: "vpc-1", Type: "FLOW_LOGS_DISABLED"}})
	alerts.SendRDSAlerts(ctx, []types.RDSFinding{{Severity: "HIGH", InstanceID: "db-1"}})
	alerts.SendRDSDriftAlerts(ctx, []types.RDSDrift{{InstanceID: "db-1", Type: "PUBLIC_ACCESSIBLE_CHANGED"}})
	alerts.SendEC2DriftAlerts(ctx, []types.EC2Drift{{SecurityGroup: "sg-1", Type: "RULES_CHANGED"}})
}

func TestSNSPublishDisabled(t *testing.T) {
	orig := config.SNSConfig.Enabled
	config.SNSConfig.Enabled = false
	defer func() { config.SNSConfig.Enabled = orig }()

	ctx := context.Background()

	alerts.SNSPublishS3Alerts(ctx, []string{"b1"})
	alerts.SNSPublishS3DriftAlerts(ctx, []types.S3Drift{{Bucket: "b1"}})
	alerts.SNSPublishEC2Alerts(ctx, []string{"sg-1"}, nil)
	alerts.SNSPublishEC2DriftAlerts(ctx, []types.EC2Drift{{SecurityGroup: "sg-1"}})
	alerts.SNSPublishIAMAlerts(ctx, []types.IAMFinding{{Resource: "user1"}})
	alerts.SNSPublishIAMDriftAlerts(ctx, []types.IAMDrift{{Resource: "user1"}})
	alerts.SNSPublishCloudTrailAlerts(ctx, []types.CloudTrailFinding{{TrailName: "t1"}})
	alerts.SNSPublishCloudTrailDriftAlerts(ctx, []types.CloudTrailDrift{{TrailName: "t1"}})
	alerts.SNSPublishVPCAlerts(ctx, []types.VPCFinding{{Resource: "vpc-1"}})
	alerts.SNSPublishVPCDriftAlerts(ctx, []types.VPCDrift{{Resource: "vpc-1"}})
	alerts.SNSPublishRDSAlerts(ctx, []types.RDSFinding{{InstanceID: "db-1"}})
	alerts.SNSPublishRDSDriftAlerts(ctx, []types.RDSDrift{{InstanceID: "db-1"}})
}
