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
- Requires Public RDS Databases: %v
- Enforce Strict CloudTrail Logging: %v
- Enforce VPC Flow Logs: %v
- Compliance Requirements: %s
- Additional Details: %s
EXISTING AWS RESOURCES:
- S3 Buckets: %v
- EC2 Security Groups: %v
- IAM Users: %v
- CloudTrails: %v
- VPCs: %v
- RDS Instances: %v

INSTRUCTIONS:
1. Provide a list of "recommendations" that explain your security decisions based on the user's answers. Explain WHY.
2. Generate the "baseline" configuration mimicking the exact structure of the AWS components (S3, EC2, IAM, CloudTrail, etc.).
3. Use the ACTUAL EXISTING AWS RESOURCES listed above. Do not invent bucket names or security group IDs if existing ones are provided. Configure the existing resources securely.
4. If the user requires public S3 access, ensure the S3 baseline reflects BlockPublicAcls=false for necessary buckets while keeping others restricted.
5. If the user uses SSM instead of SSH, ensure EC2 inbound rules strictly block port 22 on all existing security groups.
6. If Strict MFA is required, ensure the IAM password policy is extremely strong and requires MFA.
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
        "existing-bucket-name": {
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
    },
    "cloudtrail": {
      "createdAt": "string",
      "updatedAt": "string",
      "region": "string",
      "trails": {
        "existing-trail-name": {
          "name": "string",
          "is_logging": true,
          "is_multi_region": true,
          "log_validation": true,
          "s3_bucket": "string",
          "read_write_type": "All"
        }
      }
    },
    "vpc": {
      "createdAt": "string",
      "updatedAt": "string",
      "region": "string",
      "vpcs": {
        "existing-vpc-id": {
          "vpc_id": "string",
          "is_default": false,
          "flow_logs_enabled": true,
          "subnets": {
            "subnet-123": {
              "subnet_id": "string",
              "cidr": "string",
              "auto_assign_public_ip": false
            }
          }
        }
      }
    },
    "rds": {
      "createdAt": "string",
      "updatedAt": "string",
      "region": "string",
      "instances": {
        "existing-db-instance-id": {
          "instance_id": "string",
          "engine": "postgres",
          "publicly_accessible": false,
          "storage_encrypted": true,
          "deletion_protection": true,
          "master_username": "string",
          "multi_az": true,
          "auto_minor_upgrade": true
        }
      }
    }
  }
}
`,
		uctx.AppType, uctx.Environment, uctx.PublicS3, uctx.UserUploads,
		uctx.NeedSSH, uctx.UseSSM, uctx.RequireMFA, uctx.PublicRDS, uctx.StrictCloudTrail, uctx.VPCFlowLogs, uctx.Compliance, uctx.ExtraDetails,
		uctx.Existing.S3Buckets, uctx.Existing.SecurityGroups, uctx.Existing.IAMUsers,
		uctx.Existing.CloudTrails, uctx.Existing.VPCs, uctx.Existing.RDSInstances)

	return prompt
}

func parseGeneratedResponse(data []byte) (*GeneratedRecommendations, error) {
	var resp GeneratedRecommendations
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}
	return &resp, nil
}
