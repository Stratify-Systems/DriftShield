package ai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AlecAivazis/survey/v2"

	"github.com/SuryaTK2007/DriftShield/internal/baseline"
	"github.com/SuryaTK2007/DriftShield/internal/display"
)

// RunDesigner starts the interactive AI Baseline Designer flow.
func RunDesigner(ctx context.Context) error {
	display.PrintBanner("AI BASELINE DESIGNER")

	uctx, err := GatherUserContext()
	if err != nil {
		return err
	}

	fmt.Println("\n🔍 Scanning current AWS environment to find existing resources...")
	existing := &ExistingResources{
		S3Buckets:      []string{},
		SecurityGroups: []string{},
		IAMUsers:       []string{},
		CloudTrails:    []string{},
		VPCs:           []string{},
		RDSInstances:   []string{},
	}

	if s3b, err := baseline.CreateS3Baseline(ctx); err == nil && s3b != nil {
		for bucketName := range s3b.Buckets {
			existing.S3Buckets = append(existing.S3Buckets, bucketName)
		}
	}
	if ec2b, err := baseline.CreateEC2Baseline(ctx); err == nil && ec2b != nil {
		for sgID, sg := range ec2b.SecurityGroups {
			existing.SecurityGroups = append(existing.SecurityGroups, fmt.Sprintf("%s (%s)", sgID, sg.GroupName))
		}
	}
	if iamb, err := baseline.CreateIAMBaseline(ctx); err == nil && iamb != nil {
		for user := range iamb.Users {
			existing.IAMUsers = append(existing.IAMUsers, user)
		}
	}
	if ctb, err := baseline.CreateCloudTrailBaseline(ctx); err == nil && ctb != nil {
		for trail := range ctb.Trails {
			existing.CloudTrails = append(existing.CloudTrails, trail)
		}
	}
	if vpcb, err := baseline.CreateVPCBaseline(ctx); err == nil && vpcb != nil {
		for vpcID := range vpcb.VPCs {
			existing.VPCs = append(existing.VPCs, vpcID)
		}
	}
	if rdsb, err := baseline.CreateRDSBaseline(ctx); err == nil && rdsb != nil {
		for id := range rdsb.Instances {
			existing.RDSInstances = append(existing.RDSInstances, id)
		}
	}
	uctx.Existing = existing

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

	outDir := "ai-baselines"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", outDir, err)
	}

	now := time.Now().Format(time.RFC3339)

	// S3
	if result.Baseline.S3 != nil {
		result.Baseline.S3.CreatedAt = now
		result.Baseline.S3.UpdatedAt = now
		path := filepath.Join(outDir, "s3_baseline.json")
		if err := baseline.SaveBaseline(path, result.Baseline.S3); err != nil {
			fmt.Printf("[ERROR] Failed to save S3 baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved S3 baseline to %s\n", path)
		}
	}

	// EC2
	if result.Baseline.EC2 != nil {
		result.Baseline.EC2.CreatedAt = now
		result.Baseline.EC2.UpdatedAt = now
		path := filepath.Join(outDir, "ec2_baseline.json")
		if err := baseline.SaveBaseline(path, result.Baseline.EC2); err != nil {
			fmt.Printf("[ERROR] Failed to save EC2 baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved EC2 baseline to %s\n", path)
		}
	}

	// IAM
	if result.Baseline.IAM != nil {
		result.Baseline.IAM.CreatedAt = now
		result.Baseline.IAM.UpdatedAt = now
		path := filepath.Join(outDir, "iam_baseline.json")
		if err := baseline.SaveBaseline(path, result.Baseline.IAM); err != nil {
			fmt.Printf("[ERROR] Failed to save IAM baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved IAM baseline to %s\n", path)
		}
	}

	// CloudTrail
	if result.Baseline.CloudTrail != nil {
		result.Baseline.CloudTrail.CreatedAt = now
		result.Baseline.CloudTrail.UpdatedAt = now
		path := filepath.Join(outDir, "cloudtrail_baseline.json")
		if err := baseline.SaveBaseline(path, result.Baseline.CloudTrail); err != nil {
			fmt.Printf("[ERROR] Failed to save CloudTrail baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved CloudTrail baseline to %s\n", path)
		}
	}

	// VPC
	if result.Baseline.VPC != nil {
		result.Baseline.VPC.CreatedAt = now
		result.Baseline.VPC.UpdatedAt = now
		path := filepath.Join(outDir, "vpc_baseline.json")
		if err := baseline.SaveBaseline(path, result.Baseline.VPC); err != nil {
			fmt.Printf("[ERROR] Failed to save VPC baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved VPC baseline to %s\n", path)
		}
	}

	// RDS
	if result.Baseline.RDS != nil {
		result.Baseline.RDS.CreatedAt = now
		result.Baseline.RDS.UpdatedAt = now
		path := filepath.Join(outDir, "rds_baseline.json")
		if err := baseline.SaveBaseline(path, result.Baseline.RDS); err != nil {
			fmt.Printf("[ERROR] Failed to save RDS baseline: %v\n", err)
		} else {
			fmt.Printf("[OK] Saved RDS baseline to %s\n", path)
		}
	}

	fmt.Println("\n[SUCCESS] AI Baseline generated successfully!")
	fmt.Println("Review the baselines in the 'ai-baselines/' directory.")
	fmt.Println("To apply them, copy the files to the 'baselines/' directory, then run 'driftshield all drift'.")
	return nil
}
