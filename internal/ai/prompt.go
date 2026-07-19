package ai

import (
	"encoding/json"
	"fmt"
)

// ConstructPrompt builds the textual prompt for the LLM.
func ConstructPrompt(uctx *UserContext) string {
	prompt := fmt.Sprintf(`You are an expert AWS Cloud Security Architect.
Your task is to generate a highly secure AWS configuration baseline for the user's specific application.
You must return your response in strictly structured JSON matching the provided schema.

USER REQUIREMENTS:
- Application Type: %s
- Environment: %s
- Requires Public S3 Buckets: %v
- Has User File Uploads: %v
- Requires SSH/RDP Access (Port 22/3389): %v
- Uses AWS SSM Session Manager: %v
- Strict MFA Required: %v
- Compliance Requirements: %s
- Additional Details: %s

INSTRUCTIONS:
1. Provide a list of "recommendations" that explain your security decisions based on the user's answers. Explain WHY.
2. Generate the "baseline" configuration mimicking the exact structure of the AWS components (S3, EC2, IAM, CloudTrail, etc.).
3. If the user requires public S3 access, ensure the S3 baseline reflects BlockPublicAcls=false for necessary buckets (you can invent a bucket name like "public-assets-bucket") while keeping others restricted.
4. If the user uses SSM instead of SSH, ensure EC2 inbound rules strictly block port 22.
5. If Strict MFA is required, ensure the IAM password policy is extremely strong and requires MFA.
6. Make up realistic resource IDs (e.g., sg-0abcdef1234567890) where necessary.
7. YOUR ENTIRE RESPONSE MUST BE A VALID JSON OBJECT MATCHING THIS SCHEMA EXACTLY:
{
  "recommendations": [
    { "action": "string", "explanation": "string" }
  ],
  "baseline": {
    "s3": {
      "createdAt": "string",
      "updatedAt": "string",
      "buckets": {
        "bucket-name": {
          "name": "string",
          "versioning": "Enabled",
          "publicAccessBlock": {
            "blockPublicAcls": true, "ignorePublicAcls": true, "blockPublicPolicy": true, "restrictPublicBuckets": true
          }
        }
      }
    },
    "ec2": {
      "createdAt": "string",
      "updatedAt": "string",
      "securityGroups": {
        "sg-0abcdef": {
          "groupID": "string",
          "groupName": "string",
          "description": "string",
          "vpcID": "string",
          "inboundRules": [
            { "protocol": "tcp", "fromPort": 22, "toPort": 22, "sources": ["0.0.0.0/0"] }
          ]
        }
      }
    },
    "iam": {
      "createdAt": "string",
      "updatedAt": "string",
      "passwordPolicy": {
        "minimumPasswordLength": 14,
        "requireSymbols": true,
        "requireNumbers": true,
        "requireUppercase": true,
        "requireLowercase": true,
        "allowUsersToChangePassword": true,
        "expirePasswords": true,
        "maxPasswordAge": 90,
        "passwordReusePrevention": 24
      }
    }
  }
}
`,
		uctx.AppType, uctx.Environment, uctx.PublicS3, uctx.UserUploads,
		uctx.NeedSSH, uctx.UseSSM, uctx.RequireMFA, uctx.Compliance, uctx.ExtraDetails)

	return prompt
}

func parseGeneratedResponse(data []byte) (*GeneratedRecommendations, error) {
	var resp GeneratedRecommendations
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}
	return &resp, nil
}
