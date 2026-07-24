package tests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/ai"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func TestConstructPrompt(t *testing.T) {
	uctx := &ai.UserContext{
		AppType:          "REST API",
		Environment:      "Production",
		PublicS3:         false,
		UserUploads:      true,
		NeedSSH:          false,
		UseSSM:           true,
		RequireMFA:       true,
		PublicRDS:        false,
		StrictCloudTrail: true,
		VPCFlowLogs:      true,
		Compliance:       "SOC2",
		ExtraDetails:     "Strict security posture",
		Existing: &ai.ExistingResources{
			S3Buckets:      []string{"my-api-bucket"},
			SecurityGroups: []string{"sg-12345 (api-sg)"},
			IAMUsers:       []string{"admin"},
			CloudTrails:    []string{"main-trail"},
			VPCs:           []string{"vpc-98765"},
			RDSInstances:   []string{"db-prod"},
		},
	}

	prompt := ai.ConstructPrompt(uctx)

	expectedSubstrings := []string{
		"REST API",
		"Production",
		"SOC2",
		"Strict security posture",
		"my-api-bucket",
		"sg-12345 (api-sg)",
		"admin",
		"main-trail",
		"vpc-98765",
		"db-prod",
		"AWS Cloud Security Architect",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(prompt, sub) {
			t.Errorf("ConstructPrompt() missing expected substring %q", sub)
		}
	}
}

func TestParseGeneratedResponse(t *testing.T) {
	validJSON := []byte(`{
		"recommendations": [
			{"action": "Block Public S3", "explanation": "Prevent public data leaks"}
		],
		"baseline": {
			"s3": {
				"createdAt": "2025-01-01T00:00:00Z",
				"updatedAt": "2025-01-01T00:00:00Z",
				"buckets": {}
			}
		}
	}`)

	resp, err := ai.ParseGeneratedResponse(validJSON)
	if err != nil {
		t.Fatalf("ParseGeneratedResponse failed on valid JSON: %v", err)
	}

	if len(resp.Recommendations) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(resp.Recommendations))
	}
	if resp.Recommendations[0].Action != "Block Public S3" {
		t.Errorf("Action = %q; want 'Block Public S3'", resp.Recommendations[0].Action)
	}
	if resp.Baseline.S3 == nil {
		t.Error("Baseline.S3 is nil")
	}

	invalidJSON := []byte(`not json`)
	_, err = ai.ParseGeneratedResponse(invalidJSON)
	if err == nil {
		t.Error("expected error when parsing invalid JSON")
	}
}

func TestGeneratedRecommendationsSchema(t *testing.T) {
	recs := ai.GeneratedRecommendations{
		Recommendations: []ai.Recommendation{
			{Action: "Enable MFA", Explanation: "MFA is required for security"},
		},
		Baseline: ai.GeneratedBaseline{
			S3: &types.S3Baseline{
				CreatedAt: "2025-01-01T00:00:00Z",
			},
		},
	}

	data, err := json.Marshal(recs)
	if err != nil {
		t.Fatalf("Failed to marshal GeneratedRecommendations: %v", err)
	}

	var unmarshaled ai.GeneratedRecommendations
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal GeneratedRecommendations: %v", err)
	}

	if len(unmarshaled.Recommendations) != 1 {
		t.Fatalf("Expected 1 recommendation, got %d", len(unmarshaled.Recommendations))
	}
	if unmarshaled.Baseline.S3 == nil {
		t.Fatal("S3 baseline is nil after unmarshal")
	}
}
