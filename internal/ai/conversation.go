package ai

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
)

// UserContext contains the answers gathered from the user.
type UserContext struct {
	AppType      string
	Environment  string
	PublicS3     bool
	UserUploads  bool
	NeedSSH      bool
	UseSSM       bool
	RequireMFA   bool
	Compliance   string
	ExtraDetails string
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
				Message: "Do you need any S3 buckets to be publicly accessible (e.g. for static assets)?",
				Default: false,
			},
		},
		{
			Name: "UserUploads",
			Prompt: &survey.Confirm{
				Message: "Will users upload files directly to your application or S3?",
				Default: false,
			},
		},
		{
			Name: "NeedSSH",
			Prompt: &survey.Confirm{
				Message: "Do you need SSH (port 22) or RDP (port 3389) access to your EC2 instances?",
				Default: false,
			},
		},
		{
			Name: "UseSSM",
			Prompt: &survey.Confirm{
				Message: "Will you use AWS Systems Manager (SSM) Session Manager for instance access instead?",
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
			Name: "Compliance",
			Prompt: &survey.Select{
				Message: "Do you have specific compliance requirements?",
				Options: []string{"None", "SOC2", "HIPAA", "PCI-DSS", "GDPR"},
				Default: "None",
			},
		},
		{
			Name: "ExtraDetails",
			Prompt: &survey.Input{
				Message: "Any other details about your architecture? (Optional)",
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
