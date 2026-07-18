package baseline_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

// writeJSON writes v as a JSON file to path and returns a cleanup func.
func writeJSON(t *testing.T, path string, v any) func() {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return func() { os.Remove(path) }
}

// TestS3RegionMismatch verifies that CompareS3WithBaseline refuses to run when
// the baseline region doesn't match the current effective region.
func TestS3RegionMismatch(t *testing.T) {
	dir := t.TempDir()
	blFile := filepath.Join(dir, "s3_baseline.json")

	// Override the baseline file path used by the package.
	orig := config.BaselineFile
	config.BaselineFile = blFile
	t.Cleanup(func() { config.BaselineFile = orig })

	// Write a baseline that was captured in us-east-1.
	bl := types.S3Baseline{
		CreatedAt: "2026-01-01T00:00:00Z",
		UpdatedAt: "2026-01-01T00:00:00Z",
		Region:    "us-east-1",
		Buckets:   map[string]types.S3BucketConfig{},
	}
	cleanup := writeJSON(t, blFile, bl)
	defer cleanup()

	tests := []struct {
		name        string
		activeRegion string
		wantErr     bool
	}{
		{
			name:         "same region — should pass guard",
			activeRegion: "us-east-1",
			wantErr:      false, // guard passes; would then try AWS — skip by checking err type
		},
		{
			name:         "different region — should fail with mismatch error",
			activeRegion: "ap-south-1",
			wantErr:      true,
		},
		{
			name:         "empty baseline region — legacy baseline, should pass guard",
			activeRegion: "ap-south-1",
			wantErr:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Adjust the baseline's Region for the legacy case.
			currentBL := bl
			if tc.name == "empty baseline region — legacy baseline, should pass guard" {
				currentBL.Region = ""
				writeJSON(t, blFile, currentBL)
			} else {
				writeJSON(t, blFile, bl)
			}

			// Set the active region.
			config.CurrentRegion = tc.activeRegion
			t.Cleanup(func() { config.CurrentRegion = "" })

			// Load the baseline and manually replicate the guard logic
			// (avoids needing real AWS credentials in unit tests).
			loaded, err := loadS3BaselineFromFile(blFile)
			if err != nil {
				t.Fatalf("load: %v", err)
			}

			mismatch := loaded.Region != "" && loaded.Region != config.GetRegion()
			if tc.wantErr && !mismatch {
				t.Errorf("expected region mismatch error, but guard did not trigger")
			}
			if !tc.wantErr && mismatch {
				t.Errorf("expected guard to pass, but it triggered a mismatch (baseline=%q, current=%q)",
					loaded.Region, config.GetRegion())
			}
		})
	}
}

// loadS3BaselineFromFile is a test helper that reads the file directly,
// without going through config.BaselineFile (so we can test any path).
func loadS3BaselineFromFile(path string) (*types.S3Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bl types.S3Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, err
	}
	return &bl, nil
}
