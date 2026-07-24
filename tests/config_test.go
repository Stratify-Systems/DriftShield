package tests

import (
	"os"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/config"
)

func TestGetRegion(t *testing.T) {
	origCurrent := config.CurrentRegion
	origAWS := config.AWSRegion
	defer func() {
		config.CurrentRegion = origCurrent
		config.AWSRegion = origAWS
	}()

	config.AWSRegion = "us-west-2"
	config.CurrentRegion = ""

	if got := config.GetRegion(); got != "us-west-2" {
		t.Errorf("GetRegion() when CurrentRegion is empty = %q; want us-west-2", got)
	}

	config.CurrentRegion = "eu-central-1"
	if got := config.GetRegion(); got != "eu-central-1" {
		t.Errorf("GetRegion() when CurrentRegion is set = %q; want eu-central-1", got)
	}
}

func TestGetEnvOrDefault(t *testing.T) {
	testKey := "DRIFTSHIELD_TEST_ENV_KEY_12345"
	os.Unsetenv(testKey)
	defer os.Unsetenv(testKey)

	if got := config.GetEnvOrDefault(testKey, "default_val"); got != "default_val" {
		t.Errorf("GetEnvOrDefault() unset = %q; want default_val", got)
	}

	os.Setenv(testKey, "custom_val")
	if got := config.GetEnvOrDefault(testKey, "default_val"); got != "custom_val" {
		t.Errorf("GetEnvOrDefault() set = %q; want custom_val", got)
	}
}

func TestDefaultBaselineFiles(t *testing.T) {
	if config.BaselineFile == "" {
		t.Error("BaselineFile should not be empty")
	}
	if config.EC2BaselineFile == "" {
		t.Error("EC2BaselineFile should not be empty")
	}
	if config.IAMBaselineFile == "" {
		t.Error("IAMBaselineFile should not be empty")
	}
	if config.CloudTrailBaselineFile == "" {
		t.Error("CloudTrailBaselineFile should not be empty")
	}
	if config.VPCBaselineFile == "" {
		t.Error("VPCBaselineFile should not be empty")
	}
	if config.RDSBaselineFile == "" {
		t.Error("RDSBaselineFile should not be empty")
	}
}

func TestVersionConstant(t *testing.T) {
	if config.Version == "" {
		t.Error("Version should not be empty")
	}
}
