package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/AlecAivazis/survey/v2"

	"github.com/SuryaTK2007/DriftShield/internal/baseline"
	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/display"
)

// RunDesigner starts the interactive AI Baseline Designer flow.
func RunDesigner(ctx context.Context) error {
	display.PrintBanner("AI BASELINE DESIGNER")

	uctx, err := GatherUserContext()
	if err != nil {
		return err
	}

	result, err := GenerateBaselineFromAI(ctx, uctx)
	if err != nil {
		return err
	}

	fmt.Println("\n==========================================")
	fmt.Println("🛡️  AI SECURITY RECOMMENDATIONS")
	fmt.Println("==========================================")

	for i, rec := range result.Recommendations {
		fmt.Printf(" [%d] %s\n", i+1, rec.Action)
		fmt.Printf("     %s\n\n", rec.Explanation)
	}

	fmt.Println("==========================================")

	approve := false
	prompt := &survey.Confirm{
		Message: "Do you approve these recommendations and want to generate the baseline files?",
		Default: true,
	}
	if err := survey.AskOne(prompt, &approve); err != nil {
		return err
	}

	if !approve {
		fmt.Println("\n[INFO] Baseline generation cancelled by user.")
		return nil
	}

	fmt.Println("\nSaving generated baselines...")

	now := time.Now().Format(time.RFC3339)

	// S3
	if result.Baseline.S3 != nil {
		result.Baseline.S3.CreatedAt = now
		result.Baseline.S3.UpdatedAt = now
		if err := baseline.SaveBaseline(config.BaselineFile, result.Baseline.S3); err != nil {
			fmt.Printf("[ERROR] Failed to save S3 baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved S3 baseline to %s\n", config.BaselineFile)
		}
	}

	// EC2
	if result.Baseline.EC2 != nil {
		result.Baseline.EC2.CreatedAt = now
		result.Baseline.EC2.UpdatedAt = now
		if err := baseline.SaveBaseline(config.EC2BaselineFile, result.Baseline.EC2); err != nil {
			fmt.Printf("[ERROR] Failed to save EC2 baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved EC2 baseline to %s\n", config.EC2BaselineFile)
		}
	}

	// IAM
	if result.Baseline.IAM != nil {
		result.Baseline.IAM.CreatedAt = now
		result.Baseline.IAM.UpdatedAt = now
		if err := baseline.SaveBaseline(config.IAMBaselineFile, result.Baseline.IAM); err != nil {
			fmt.Printf("[ERROR] Failed to save IAM baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved IAM baseline to %s\n", config.IAMBaselineFile)
		}
	}

	// CloudTrail
	if result.Baseline.CloudTrail != nil {
		result.Baseline.CloudTrail.CreatedAt = now
		result.Baseline.CloudTrail.UpdatedAt = now
		if err := baseline.SaveBaseline(config.CloudTrailBaselineFile, result.Baseline.CloudTrail); err != nil {
			fmt.Printf("[ERROR] Failed to save CloudTrail baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved CloudTrail baseline to %s\n", config.CloudTrailBaselineFile)
		}
	}

	// VPC
	if result.Baseline.VPC != nil {
		result.Baseline.VPC.CreatedAt = now
		result.Baseline.VPC.UpdatedAt = now
		if err := baseline.SaveBaseline(config.VPCBaselineFile, result.Baseline.VPC); err != nil {
			fmt.Printf("[ERROR] Failed to save VPC baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved VPC baseline to %s\n", config.VPCBaselineFile)
		}
	}

	// RDS
	if result.Baseline.RDS != nil {
		result.Baseline.RDS.CreatedAt = now
		result.Baseline.RDS.UpdatedAt = now
		if err := baseline.SaveBaseline(config.RDSBaselineFile, result.Baseline.RDS); err != nil {
			fmt.Printf("[ERROR] Failed to save RDS baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved RDS baseline to %s\n", config.RDSBaselineFile)
		}
	}

	fmt.Println("\n[SUCCESS] AI Baseline generated successfully!")
	fmt.Println("Run 'driftshield all drift' to enforce your new security posture.")
	return nil
}
