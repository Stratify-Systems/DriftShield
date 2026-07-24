package tests

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/baseline"
	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func TestSaveAndLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_baseline.json")

	bl := &types.S3Baseline{
		CreatedAt: "2025-01-01T00:00:00Z",
		UpdatedAt: "2025-01-01T00:00:00Z",
		Buckets: map[string]types.S3BucketConfig{
			"test-bucket": {
				BucketName: "test-bucket",
				Versioning: "Enabled",
				Encryption: "AES256",
			},
		},
	}

	if err := baseline.SaveBaseline(path, bl); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	loaded, err := baseline.LoadBaseline[types.S3Baseline](path)
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if loaded == nil || len(loaded.Buckets) != 1 {
		t.Fatal("loaded baseline invalid")
	}
}

func TestBuildIpPermission(t *testing.T) {
	rule := types.InboundRule{
		Protocol: "tcp",
		FromPort: 22,
		ToPort:   22,
		Sources:  []string{"0.0.0.0/0", "::/0"},
	}

	perm := baseline.BuildIpPermission(rule)
	if perm.IpProtocol == nil || *perm.IpProtocol != "tcp" {
		t.Errorf("Protocol = %v; want tcp", perm.IpProtocol)
	}
}

func TestRemediateS3DriftDryRun(t *testing.T) {
	orig := config.BaselineFile
	dir := t.TempDir()
	config.BaselineFile = filepath.Join(dir, "s3_baseline.json")
	defer func() { config.BaselineFile = orig }()

	bl := &types.S3Baseline{
		CreatedAt: "2025-01-01T00:00:00Z",
		Buckets: map[string]types.S3BucketConfig{
			"my-bucket": {
				BucketName: "my-bucket",
				Versioning: "Enabled",
				Encryption: "AES256",
			},
		},
	}
	_ = baseline.SaveBaseline(config.BaselineFile, bl)

	drifts := []types.S3Drift{
		{Bucket: "my-bucket", Type: "PUBLIC_ACCESS_CHANGED"},
		{Bucket: "my-bucket", Type: "VERSIONING_CHANGED"},
	}

	res, err := baseline.RemediateS3Drift(context.Background(), drifts, true)
	if err != nil {
		t.Fatalf("RemediateS3Drift dry-run failed: %v", err)
	}

	if len(res.Fixed) != 2 {
		t.Fatalf("expected 2 fixed items in dry-run, got %d", len(res.Fixed))
	}
}
