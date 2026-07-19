package ai

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
)

// UserContext contains the answers gathered from the user.
type UserContext struct {
	AppType          string
	Environment      string
	PublicS3         bool
	UserUploads      bool
	NeedSSH          bool
	UseSSM           bool
	RequireMFA       bool
	PublicRDS        bool
	StrictCloudTrail bool
	VPCFlowLogs      bool
	Compliance       string
	ExtraDetails     string
	Existing         *ExistingResources
}

// ExistingResources holds the names/IDs of resources currently existing in the user's AWS account.
type ExistingResources struct {
	S3Buckets      []string
	SecurityGroups []string
	IAMUsers       []string
	CloudTrails    []string
	VPCs           []string
	RDSInstances   []string
}

// GatherUserContext starts an interactive CLI session to understand the user's needs.
func GatherUserContext() (*UserContext, error) {
	fmt.Println("🚀 Welcome to the DriftShield AI Baseline Designer")
	fmt.Println("Let's define a secure architecture tailored to your needs.")

	var qs = []*survey.Question{
		{
			Name: "AppType",
			Prompt: &survey.Select{
				Message: "What type of application are you deploying?",
				Options: []string{"Static website", "REST API", "E-commerce", "SaaS", "Internal application", "Data pipeline", "Other"},
				Default: "REST API",
			},
		},
		{
			Name: "Environment",
			Prompt: &survey.Select{
				Message: "Is this for Production or Development?",
				Options: []string{"Production", "Development", "Staging"},
				Default: "Production",
			},
		},
		{
			Name: "PublicS3",
			Prompt: &survey.Confirm{
				Message: "Do you have any S3 buckets that MUST be accessible to the public internet (e.g., website hosting, public images)?",
				Default: false,
			},
		},
		{
			Name: "UserUploads",
			Prompt: &survey.Confirm{
				Message: "Will your application allow users to upload files to S3? (Impacts S3 bucket policies)",
				Default: false,
			},
		},
		{
			Name: "NeedSSH",
			Prompt: &survey.Confirm{
				Message: "Do you require direct SSH (Linux) or RDP (Windows) access to your EC2 instances from the internet?",
				Default: false,
			},
		},
		{
			Name: "UseSSM",
			Prompt: &survey.Confirm{
				Message: "Do you plan to use AWS SSM Session Manager for secure instance access instead of opening SSH/RDP ports?",
				Default: true,
			},
		},
		{
			Name: "RequireMFA",
			Prompt: &survey.Confirm{
				Message: "Should we enforce strict Multi-Factor Authentication (MFA) for all IAM users?",
				Default: true,
			},
		},
		{
			Name: "PublicRDS",
			Prompt: &survey.Confirm{
				Message: "Do any of your RDS databases need to be publicly accessible from the internet?",
				Default: false,
			},
		},
		{
			Name: "StrictCloudTrail",
			Prompt: &survey.Confirm{
				Message: "Do you want to enforce strict CloudTrail logging (multi-region, log file validation) on all trails?",
				Default: true,
			},
		},
		{
			Name: "VPCFlowLogs",
			Prompt: &survey.Confirm{
				Message: "Do you want to enforce VPC Flow Logs on all your VPCs to track network traffic?",
				Default: true,
			},
		},
		{
			Name: "Compliance",
			Prompt: &survey.Select{
				Message: "Do you have specific compliance requirements? (Select None if unsure)",
				Options: []string{"None", "SOC2", "HIPAA", "PCI-DSS", "GDPR"},
				Default: "None",
			},
		},
		{
			Name: "ExtraDetails",
			Prompt: &survey.Input{
				Message: "Any other architectural details we should know about? (Optional)",
			},
		},
	}

	answers := UserContext{}
	err := survey.Ask(qs, &answers)
	if err != nil {
		return nil, fmt.Errorf("failed to gather user context: %w", err)
	}

	return &answers, nil
}
