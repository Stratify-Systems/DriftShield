package ai

import (
	"context"
	"fmt"

	"github.com/AlecAivazis/survey/v2"

	"github.com/SuryaTK2007/DriftShield/internal/display"
)

// RunPolicyDesigner runs an interactive CLI session to generate AI policy rules.
func RunPolicyDesigner(ctx context.Context) error {
	display.PrintBanner("AI POLICY GENERATOR")
	fmt.Println("🚀 Welcome to the DriftShield AI Policy Generator")
	fmt.Println("Describe your security guidelines or compliance standards (e.g. SOC2, HIPAA, PCI-DSS).")
	fmt.Println()

	var framework string
	var extraRules string

	err := survey.AskOne(&survey.Select{
		Message: "Select a primary compliance framework (or select Custom):",
		Options: []string{"SOC2", "HIPAA", "PCI-DSS", "GDPR", "Custom / Company Standards"},
		Default: "SOC2",
	}, &framework)
	if err != nil {
		return err
	}

	err = survey.AskOne(&survey.Input{
		Message: "Describe any additional security rules or guidelines (e.g., 'no open SSH, S3 encryption required'):",
	}, &extraRules)
	if err != nil {
		return err
	}

	requirements := fmt.Sprintf("Framework: %s\nAdditional Security Guidelines: %s", framework, extraRules)

	fmt.Println("\n🧠 AI (Groq LLaMA 3) is analyzing your security requirements and generating policy rules...")

	rules, yamlContent, err := GeneratePolicyRules(ctx, requirements)
	if err != nil {
		return fmt.Errorf("policy rule generation failed: %w", err)
	}

	fmt.Println("\n==========================================")
	fmt.Println("🛡️  PROPOSED AI POLICY RULES FOR REVIEW")
	fmt.Println("==========================================")

	for i, r := range rules {
		fmt.Printf("\n [%d] [%s] %s (Service: %s, Severity: %s)\n", i+1, r.ID, r.Name, r.Service, r.Severity)
		fmt.Printf("     Description: %s\n", r.Description)
		if r.Remediation != "" {
			fmt.Printf("     Fix:         %s\n", r.Remediation)
		}
	}

	fmt.Println("\n==========================================")

	var approve bool
	err = survey.AskOne(&survey.Confirm{
		Message: "Do you approve these policy rules and want to save them to policies/custom_policy.yaml?",
		Default: true,
	}, &approve)
	if err != nil {
		return err
	}

	if !approve {
		fmt.Println("[CANCELLED] Policy generation cancelled. No files were written.")
		return nil
	}

	outputPath := "policies/custom_policy.yaml"
	if err := SavePolicyYAML(outputPath, yamlContent); err != nil {
		return err
	}

	fmt.Printf("\n[SUCCESS] Custom policy rules saved successfully to '%s'!\n", outputPath)
	fmt.Println("You can now evaluate your live AWS resources against these rules by running:")
	fmt.Println("  driftshield policy scan")

	return nil
}
