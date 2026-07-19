// DriftShield — Cloud security scanner and configuration drift detection tool.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/SuryaTK2007/DriftShield/internal/ai"
	"github.com/SuryaTK2007/DriftShield/internal/alerts"
	"github.com/SuryaTK2007/DriftShield/internal/baseline"
	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/display"
	"github.com/SuryaTK2007/DriftShield/internal/scanner"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ──────────────────────────────────────────────────────────────
// Root command
// ──────────────────────────────────────────────────────────────

var rootCmd = &cobra.Command{
	Use:   "driftshield",
	Short: "Cloud security scanner and drift detection",
	Long: `DriftShield - A cloud security tool that detects S3 and EC2
misconfigurations and monitors configuration drift against a secure baseline.`,
	Version: config.Version,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&config.CurrentRegion, "region", "r", "", "AWS region (e.g., us-east-1)")

	// S3 commands
	s3Cmd := &cobra.Command{
		Use:   "s3",
		Short: "Run S3 security scan",
		Run:   func(cmd *cobra.Command, args []string) { runS3Scan() },
	}
	s3Cmd.AddCommand(
		&cobra.Command{Use: "baseline", Short: "Create S3 baseline", Run: func(cmd *cobra.Command, args []string) { runS3Baseline() }},
		&cobra.Command{Use: "drift", Short: "Detect S3 configuration drift", Run: func(cmd *cobra.Command, args []string) { runS3Drift() }},
		&cobra.Command{Use: "fix", Short: "Fix drifted S3 configurations", Run: func(cmd *cobra.Command, args []string) { runS3Fix() }},
	)

	// EC2 commands
	ec2Cmd := &cobra.Command{
		Use:   "ec2",
		Short: "Run EC2 security group scan",
		Run:   func(cmd *cobra.Command, args []string) { runEC2Scan() },
	}
	ec2Cmd.AddCommand(
		&cobra.Command{Use: "baseline", Short: "Create EC2 baseline", Run: func(cmd *cobra.Command, args []string) { runEC2Baseline() }},
		&cobra.Command{Use: "drift", Short: "Detect EC2 configuration drift", Run: func(cmd *cobra.Command, args []string) { runEC2Drift() }},
		&cobra.Command{Use: "fix", Short: "Fix risky EC2 security group rules", Run: func(cmd *cobra.Command, args []string) { runEC2Fix() }},
	)

	// IAM command
	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "Run IAM security scan",
		Run:   func(cmd *cobra.Command, args []string) { runIAMScan() },
	}
	iamCmd.AddCommand(
		&cobra.Command{Use: "baseline", Short: "Create IAM baseline", Run: func(cmd *cobra.Command, args []string) { runIAMBaseline() }},
		&cobra.Command{Use: "drift", Short: "Detect IAM configuration drift", Run: func(cmd *cobra.Command, args []string) { runIAMDrift() }},
		&cobra.Command{Use: "fix", Short: "Show manual remediation steps for IAM findings", Run: func(cmd *cobra.Command, args []string) { runIAMFix() }},
	)

	// CloudTrail command
	cloudtrailCmd := &cobra.Command{
		Use:   "cloudtrail",
		Short: "Run CloudTrail security scan",
		Run:   func(cmd *cobra.Command, args []string) { runCloudTrailScan() },
	}
	cloudtrailCmd.AddCommand(
		&cobra.Command{Use: "baseline", Short: "Create CloudTrail baseline", Run: func(cmd *cobra.Command, args []string) { runCloudTrailBaseline() }},
		&cobra.Command{Use: "drift", Short: "Detect CloudTrail configuration drift", Run: func(cmd *cobra.Command, args []string) { runCloudTrailDrift() }},
		&cobra.Command{Use: "fix", Short: "Fix drifted CloudTrail configurations", Run: func(cmd *cobra.Command, args []string) { runCloudTrailFix() }},
	)

	// RDS command
	rdsCmd := &cobra.Command{
		Use:   "rds",
		Short: "Run RDS security scan",
		Run:   func(cmd *cobra.Command, args []string) { runRDSScan() },
	}
	rdsCmd.AddCommand(
		&cobra.Command{Use: "baseline", Short: "Create RDS baseline", Run: func(cmd *cobra.Command, args []string) { runRDSBaseline() }},
		&cobra.Command{Use: "drift", Short: "Detect RDS configuration drift", Run: func(cmd *cobra.Command, args []string) { runRDSDrift() }},
		&cobra.Command{Use: "fix", Short: "Fix drifted RDS configurations", Run: func(cmd *cobra.Command, args []string) { runRDSFix() }},
	)

	// VPC command
	vpcCmd := &cobra.Command{
		Use:   "vpc",
		Short: "Run VPC security scan",
		Run:   func(cmd *cobra.Command, args []string) { runVPCScan() },
	}
	vpcCmd.AddCommand(
		&cobra.Command{Use: "baseline", Short: "Create VPC baseline", Run: func(cmd *cobra.Command, args []string) { runVPCBaseline() }},
		&cobra.Command{Use: "drift", Short: "Detect VPC configuration drift", Run: func(cmd *cobra.Command, args []string) { runVPCDrift() }},
		&cobra.Command{Use: "fix", Short: "Fix drifted VPC configurations", Run: func(cmd *cobra.Command, args []string) { runVPCFix() }},
	)

	// All command
	allCmd := &cobra.Command{
		Use:   "all",
		Short: "Run S3, EC2, IAM, and CloudTrail scans",
		Run:   func(cmd *cobra.Command, args []string) { runAllScans() },
	}

	// AI command
	aiCmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-powered utilities",
	}
	aiCmd.AddCommand(
		&cobra.Command{
			Use:   "baseline",
			Short: "Generate secure baselines interactively using AI",
			Run: func(cmd *cobra.Command, args []string) {
				ctx := context.Background()
				if err := ai.RunDesigner(ctx); err != nil {
					fmt.Printf("\n[ERROR] %v\n", err)
				}
			},
		},
	)

	rootCmd.AddCommand(s3Cmd, ec2Cmd, iamCmd, cloudtrailCmd, rdsCmd, vpcCmd, allCmd, aiCmd)
}

// ──────────────────────────────────────────────────────────────
// S3 handlers
// ──────────────────────────────────────────────────────────────

func runS3Scan() {
	ctx := context.Background()
	display.PrintBanner("SECURITY SCAN")
	fmt.Printf("Scan started at: %s\n\n", now())

	results, err := scanner.ScanAllBuckets(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("SCAN RESULTS", []string{
		fmt.Sprintf("Secure buckets:    %d", len(results.Secure)),
		fmt.Sprintf("At-risk buckets:   %d", len(results.AtRisk)),
	})

	if len(results.AtRisk) > 0 {
		fmt.Println("\n[!] ACTION REQUIRED - Review these buckets:")
		for _, b := range results.AtRisk {
			fmt.Printf("    - %s\n", b)
		}
		alerts.SendS3Alerts(ctx, results.AtRisk)
	} else {
		fmt.Println("\n[+] All buckets are secure. No action required.")
	}
}

func runS3Baseline() {
	ctx := context.Background()
	display.PrintBanner("CREATE BASELINE")
	fmt.Printf("Started at: %s\n\n", now())

	if _, err := baseline.CreateS3Baseline(ctx); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
	}
}

func runS3Drift() {
	ctx := context.Background()
	display.PrintBanner("DRIFT DETECTION")
	fmt.Printf("Scan started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareS3WithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No baseline found.")
		fmt.Println("    Run 'driftshield s3 baseline' first to create one.")
		return
	}
	if len(drifts) > 0 {
		printBox("DRIFT DETECTION RESULTS", []string{
			fmt.Sprintf("Configuration drifts found: %d", len(drifts)),
		})
		alerts.SendS3DriftAlerts(ctx, drifts)
	} else {
		fmt.Println("\n[+] All configurations match baseline. No drift detected.")
	}
}

func runS3Fix() {
	ctx := context.Background()
	display.PrintBanner("REMEDIATION")
	fmt.Printf("Started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareS3WithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No baseline found.")
		fmt.Println("    Run 'driftshield s3 baseline' first to create one.")
		return
	}
	if len(drifts) == 0 {
		fmt.Println("\n[+] No drifts detected. Nothing to fix.")
		return
	}

	fmt.Printf("\nFound %d drift(s). Starting remediation...\n\n", len(drifts))

	results, err := baseline.RemediateS3Drift(ctx, drifts)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("REMEDIATION RESULTS", []string{
		fmt.Sprintf("Fixed:    %d", len(results.Fixed)),
		fmt.Sprintf("Failed:   %d", len(results.Failed)),
		fmt.Sprintf("Skipped:  %d", len(results.Skipped)),
	})
}

// ──────────────────────────────────────────────────────────────
// EC2 handlers
// ──────────────────────────────────────────────────────────────

func runEC2Scan() {
	ctx := context.Background()
	display.PrintBanner("EC2 SECURITY SCAN")
	fmt.Printf("Scan started at: %s\n\n", now())

	results, err := scanner.ScanSecurityGroups(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("EC2 SCAN RESULTS", []string{
		fmt.Sprintf("Secure groups:    %d", len(results.Secure)),
		fmt.Sprintf("At-risk groups:   %d", len(results.AtRisk)),
	})

	if len(results.AtRisk) > 0 {
		fmt.Println("\n[!] ACTION REQUIRED - Review these security groups:")
		for _, sgID := range results.AtRisk {
			d := results.Details[sgID]
			if d != nil {
				fmt.Printf("    - %s (%s)\n", d.Config.GroupName, sgID)
			}
		}
		alerts.SendEC2Alerts(ctx, results.AtRisk, results.Details)
	} else {
		fmt.Println("\n[+] All security groups are secure. No action required.")
	}
}

func runEC2Baseline() {
	ctx := context.Background()
	display.PrintBanner("CREATE EC2 BASELINE")
	fmt.Printf("Started at: %s\n\n", now())

	if _, err := baseline.CreateEC2Baseline(ctx); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
	}
}

func runEC2Drift() {
	ctx := context.Background()
	display.PrintBanner("EC2 DRIFT DETECTION")
	fmt.Printf("Scan started at: %s\n\n", now())

	drifts, err := baseline.CompareEC2WithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if drifts == nil {
		fmt.Println("\n[!] No EC2 baseline found.")
		fmt.Println("    Run 'driftshield ec2 baseline' first to create one.")
		return
	}
	if len(drifts) > 0 {
		printBox("EC2 DRIFT DETECTION RESULTS", []string{
			fmt.Sprintf("Configuration drifts found: %d", len(drifts)),
		})
		// Show drift details
		fmt.Println("\nDRIFT DETAILS:")
		fmt.Println(strings.Repeat("-", 60))
		for _, d := range drifts {
			fmt.Printf("\n  %s (%s)\n  Type: %s\n", d.Name, d.SecurityGroup, d.Type)
			if d.Type == "RULES_CHANGED" {
				if len(d.AddedRules) > 0 {
					fmt.Println("  Rules ADDED:")
					for _, r := range d.AddedRules {
						fmt.Printf("    + %s from %v\n", display.GetPortDescription(r.Protocol, r.FromPort, r.ToPort), r.Sources)
					}
				}
				if len(d.RemovedRules) > 0 {
					fmt.Println("  Rules REMOVED:")
					for _, r := range d.RemovedRules {
						fmt.Printf("    - %s from %v\n", display.GetPortDescription(r.Protocol, r.FromPort, r.ToPort), r.Sources)
					}
				}
			} else if d.Type == "NEW_SECURITY_GROUP" {
				fmt.Println("  Status: New security group (not in baseline)")
			} else if d.Type == "SECURITY_GROUP_DELETED" {
				fmt.Println("  Status: Security group was deleted")
			}
		}
		fmt.Println("\n" + strings.Repeat("-", 60))
		alerts.SendEC2DriftAlerts(ctx, drifts)
	} else {
		fmt.Println("\n[+] All EC2 configurations match baseline. No drift detected.")
	}
}

func runEC2Fix() {
	ctx := context.Background()
	display.PrintBanner("EC2 AUTO-FIX")
	fmt.Printf("Started at: %s\n\n", now())
	fmt.Println("This will REMOVE risky inbound rules that allow access from 0.0.0.0/0:")
	fmt.Println("  - SSH (22), RDP (3389)")
	fmt.Println("  - Database ports (MySQL, PostgreSQL, MongoDB, Redis, etc.)")
	fmt.Println("  - All traffic / All ports")
	fmt.Printf("\n%s\n\n", strings.Repeat("-", 60))
	fmt.Println("[!] WARNING: This will modify your security groups!")
	fmt.Print("    Continue? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))

	if resp != "yes" && resp != "y" {
		fmt.Println("\n[CANCELLED] No changes made.")
		return
	}

	fmt.Println("\nScanning and fixing risky rules...")

	results, err := scanner.RemediateEC2Risks(ctx, false)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("EC2 REMEDIATION RESULTS", []string{
		fmt.Sprintf("Fixed:    %d", len(results.Fixed)),
		fmt.Sprintf("Failed:   %d", len(results.Failed)),
		fmt.Sprintf("Skipped:  %d", len(results.Skipped)),
	})

	if len(results.Fixed) > 0 {
		fmt.Println("\n[+] Risky rules removed. Run 'driftshield ec2' to verify.")
	}
	if len(results.Failed) > 0 {
		fmt.Println("\n[!] Some fixes failed. Check IAM permissions:")
		fmt.Println("    - ec2:RevokeSecurityGroupIngress")
	}
	if len(results.Skipped) > 0 {
		fmt.Println("\n[!] Skipped security groups (manual review recommended):")
		for _, item := range results.Skipped {
			fmt.Printf("    - %s (%s): %s\n", item.Name, item.SecurityGroup, item.Reason)
		}
	}
}

// ──────────────────────────────────────────────────────────────
// IAM handlers
// ──────────────────────────────────────────────────────────────

func runIAMScan() {
	ctx := context.Background()
	display.PrintBanner("IAM SECURITY SCAN")
	fmt.Printf("Scan started at: %s\n\n", now())

	results, err := scanner.ScanIAM(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	critical, high, medium, low := countIAMSeverities(results.Findings)
	printBox("IAM SCAN RESULTS", []string{
		fmt.Sprintf("Total findings:  %d", len(results.Findings)),
		fmt.Sprintf("Critical: %d  High: %d  Medium: %d  Low: %d", critical, high, medium, low),
	})

	if len(results.Findings) > 0 {
		fmt.Println("\n[!] ACTION REQUIRED - IAM issues detected")
		alerts.SendIAMAlerts(ctx, results.Findings)
	} else {
		fmt.Println("\n[+] No IAM issues found.")
	}
}

func runIAMBaseline() {
	ctx := context.Background()
	display.PrintBanner("CREATE IAM BASELINE")
	fmt.Printf("Started at: %s\n\n", now())

	if _, err := baseline.CreateIAMBaseline(ctx); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
	}
}

func runIAMDrift() {
	ctx := context.Background()
	display.PrintBanner("IAM DRIFT DETECTION")
	fmt.Printf("Scan started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareIAMWithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No IAM baseline found.")
		fmt.Println("    Run 'driftshield iam baseline' first to create one.")
		return
	}
	if len(drifts) > 0 {
		printBox("IAM DRIFT DETECTION RESULTS", []string{
			fmt.Sprintf("Configuration drifts found: %d", len(drifts)),
		})
		fmt.Println("\nDRIFT DETAILS:")
		fmt.Println(strings.Repeat("-", 60))
		for _, d := range drifts {
			fmt.Printf("\n  [%s] %s\n  %s\n", d.Type, d.Resource, d.Message)
			if d.OldValue != "" || d.NewValue != "" {
				fmt.Printf("  Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		fmt.Println("\n" + strings.Repeat("-", 60))
		alerts.SendIAMDriftAlerts(ctx, drifts)
	} else {
		fmt.Println("\n[+] IAM configuration matches baseline. No drift detected.")
	}
}

func runIAMFix() {
	display.PrintBanner("IAM REMEDIATION GUIDE")
	fmt.Println("IAM changes are not auto-remediated — they can lock out users or break applications.")
	fmt.Println("\nReview the findings from 'driftshield iam' and take these manual actions:")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("  ROOT_MFA_DISABLED        → Enable MFA on root account in AWS Console")
	fmt.Println("  ROOT_ACCESS_KEY_EXISTS   → Delete root access keys in IAM > Security credentials")
	fmt.Println("  USER_MFA_DISABLED        → Enable MFA for the user in IAM > Users > Security credentials")
	fmt.Println("  ADMIN_POLICY_ATTACHED    → Detach AdministratorAccess, apply least-privilege policy")
	fmt.Println("  WILDCARD_ACTION_POLICY   → Edit inline policy to restrict Action to specific services")
	fmt.Println("  STALE_ACCESS_KEY         → Deactivate or delete the key in IAM > Users > Security credentials")
	fmt.Println("  NO_PASSWORD_POLICY       → Set account password policy in IAM > Account settings")
	fmt.Println("  WEAK_PASSWORD_*          → Update password policy: min 14 chars, complexity, expiry")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("\nRun 'driftshield iam' to see current findings.")
}

func countIAMSeverities(findings []types.IAMFinding) (critical, high, medium, low int) {
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}
	return
}

// ──────────────────────────────────────────────────────────────
// CloudTrail handlers
// ──────────────────────────────────────────────────────────────

func runCloudTrailScan() {
	ctx := context.Background()
	display.PrintBanner("CLOUDTRAIL SECURITY SCAN")
	fmt.Printf("Scan started at: %s\n\n", now())

	results, err := scanner.ScanCloudTrail(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("CLOUDTRAIL SCAN RESULTS", []string{
		fmt.Sprintf("Trails scanned:  %d", len(results.Trails)),
		fmt.Sprintf("Findings:        %d", len(results.Findings)),
	})

	if len(results.Findings) > 0 {
		fmt.Println("\n[!] ACTION REQUIRED - CloudTrail issues detected")
		alerts.SendCloudTrailAlerts(ctx, results.Findings)
	} else {
		fmt.Println("\n[+] CloudTrail configuration looks secure.")
	}
}

func runCloudTrailBaseline() {
	ctx := context.Background()
	display.PrintBanner("CREATE CLOUDTRAIL BASELINE")
	fmt.Printf("Started at: %s\n\n", now())

	if _, err := baseline.CreateCloudTrailBaseline(ctx); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
	}
}

func runCloudTrailDrift() {
	ctx := context.Background()
	display.PrintBanner("CLOUDTRAIL DRIFT DETECTION")
	fmt.Printf("Scan started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareCloudTrailWithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No CloudTrail baseline found.")
		fmt.Println("    Run 'driftshield cloudtrail baseline' first to create one.")
		return
	}
	if len(drifts) > 0 {
		printBox("CLOUDTRAIL DRIFT DETECTION RESULTS", []string{
			fmt.Sprintf("Configuration drifts found: %d", len(drifts)),
		})
		fmt.Println("\nDRIFT DETAILS:")
		fmt.Println(strings.Repeat("-", 60))
		for _, d := range drifts {
			fmt.Printf("\n  [%s] Trail: %s\n  %s\n", d.Type, d.TrailName, d.Message)
			if d.OldValue != "" || d.NewValue != "" {
				fmt.Printf("  Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		fmt.Println("\n" + strings.Repeat("-", 60))
		alerts.SendCloudTrailDriftAlerts(ctx, drifts)
	} else {
		fmt.Println("\n[+] CloudTrail configuration matches baseline. No drift detected.")
	}
}

func runCloudTrailFix() {
	ctx := context.Background()
	display.PrintBanner("CLOUDTRAIL AUTO-FIX")
	fmt.Printf("Started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareCloudTrailWithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No CloudTrail baseline found.")
		fmt.Println("    Run 'driftshield cloudtrail baseline' first to create one.")
		return
	}
	if len(drifts) == 0 {
		fmt.Println("\n[+] No drifts detected. Nothing to fix.")
		return
	}

	fmt.Printf("Found %d drift(s). The following changes will be made:\n\n", len(drifts))
	for _, d := range drifts {
		switch d.Type {
		case "LOGGING_STATUS_CHANGED":
			fmt.Printf("  - Trail '%s': restore logging to %s\n", d.TrailName, d.OldValue)
		case "LOG_VALIDATION_CHANGED":
			fmt.Printf("  - Trail '%s': restore log file validation to %s\n", d.TrailName, d.OldValue)
		default:
			fmt.Printf("  - Trail '%s': [%s] requires manual action\n", d.TrailName, d.Type)
		}
	}

	fmt.Printf("\n%s\n\n", strings.Repeat("-", 60))
	fmt.Println("[!] WARNING: This will modify your CloudTrail configuration!")
	fmt.Print("    Continue? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "yes" && resp != "y" {
		fmt.Println("\n[CANCELLED] No changes made.")
		return
	}

	fmt.Println()
	results, err := baseline.RemediateCloudTrailDrift(ctx, drifts)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("CLOUDTRAIL REMEDIATION RESULTS", []string{
		fmt.Sprintf("Fixed:    %d", len(results.Fixed)),
		fmt.Sprintf("Failed:   %d", len(results.Failed)),
		fmt.Sprintf("Skipped:  %d", len(results.Skipped)),
	})

	if len(results.Fixed) > 0 {
		fmt.Println("\n[+] Trails restored. Run 'driftshield cloudtrail' to verify.")
	}
	if len(results.Skipped) > 0 {
		fmt.Println("\n[!] Some changes require manual action (trail added/deleted/S3 bucket changed).")
	}
}

// ──────────────────────────────────────────────────────────────
// RDS handlers
// ──────────────────────────────────────────────────────────────

func runRDSScan() {
	ctx := context.Background()
	display.PrintBanner("RDS SECURITY SCAN")
	fmt.Printf("Scan started at: %s\n\n", now())

	results, err := scanner.ScanRDS(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("RDS SCAN RESULTS", []string{
		fmt.Sprintf("Findings: %d", len(results.Findings)),
	})

	if len(results.Findings) > 0 {
		fmt.Println("\n[!] ACTION REQUIRED - RDS issues detected")
		alerts.SendRDSAlerts(ctx, results.Findings)
	} else {
		fmt.Println("\n[+] All RDS instances look secure.")
	}
}

func runRDSBaseline() {
	ctx := context.Background()
	display.PrintBanner("CREATE RDS BASELINE")
	fmt.Printf("Started at: %s\n\n", now())

	if _, err := baseline.CreateRDSBaseline(ctx); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
	}
}

func runRDSDrift() {
	ctx := context.Background()
	display.PrintBanner("RDS DRIFT DETECTION")
	fmt.Printf("Scan started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareRDSWithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No RDS baseline found.")
		fmt.Println("    Run 'driftshield rds baseline' first to create one.")
		return
	}
	if len(drifts) > 0 {
		printBox("RDS DRIFT DETECTION RESULTS", []string{
			fmt.Sprintf("Configuration drifts found: %d", len(drifts)),
		})
		fmt.Println("\nDRIFT DETAILS:")
		fmt.Println(strings.Repeat("-", 60))
		for _, d := range drifts {
			fmt.Printf("\n  [%s] %s\n  %s\n", d.Type, d.InstanceID, d.Message)
			if d.OldValue != "" || d.NewValue != "" {
				fmt.Printf("  Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		fmt.Println("\n" + strings.Repeat("-", 60))
		alerts.SendRDSDriftAlerts(ctx, drifts)
	} else {
		fmt.Println("\n[+] RDS configuration matches baseline. No drift detected.")
	}
}

func runRDSFix() {
	ctx := context.Background()
	display.PrintBanner("RDS AUTO-FIX")
	fmt.Printf("Started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareRDSWithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No RDS baseline found.")
		fmt.Println("    Run 'driftshield rds baseline' first to create one.")
		return
	}
	if len(drifts) == 0 {
		fmt.Println("\n[+] No drifts detected. Nothing to fix.")
		return
	}

	fmt.Printf("Found %d drift(s). The following changes will be made:\n\n", len(drifts))
	for _, d := range drifts {
		switch d.Type {
		case "PUBLIC_ACCESS_CHANGED":
			fmt.Printf("  - Instance '%s': restore publicly accessible to %s\n", d.InstanceID, d.OldValue)
		case "DELETION_PROTECTION_CHANGED":
			fmt.Printf("  - Instance '%s': restore deletion protection to %s\n", d.InstanceID, d.OldValue)
		case "AUTO_MINOR_UPGRADE_CHANGED":
			fmt.Printf("  - Instance '%s': restore auto minor upgrade to %s\n", d.InstanceID, d.OldValue)
		default:
			fmt.Printf("  - Instance '%s': [%s] requires manual action\n", d.InstanceID, d.Type)
		}
	}

	fmt.Printf("\n%s\n\n", strings.Repeat("-", 60))
	fmt.Println("[!] WARNING: This will modify your RDS instances!")
	fmt.Print("    Continue? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "yes" && resp != "y" {
		fmt.Println("\n[CANCELLED] No changes made.")
		return
	}

	fmt.Println()
	results, err := baseline.RemediateRDSDrift(ctx, drifts)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("RDS REMEDIATION RESULTS", []string{
		fmt.Sprintf("Fixed:    %d", len(results.Fixed)),
		fmt.Sprintf("Failed:   %d", len(results.Failed)),
		fmt.Sprintf("Skipped:  %d", len(results.Skipped)),
	})

	if len(results.Fixed) > 0 {
		fmt.Println("\n[+] Instances restored. Run 'driftshield rds' to verify.")
	}
	if len(results.Skipped) > 0 {
		fmt.Println("\n[!] Some changes require manual action (encryption, master username).")
	}
}

// ──────────────────────────────────────────────────────────────
// VPC handlers
// ──────────────────────────────────────────────────────────────

func runVPCScan() {
	ctx := context.Background()
	display.PrintBanner("VPC SECURITY SCAN")
	fmt.Printf("Scan started at: %s\n\n", now())

	results, err := scanner.ScanVPC(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("VPC SCAN RESULTS", []string{
		fmt.Sprintf("Findings: %d", len(results.Findings)),
	})

	if len(results.Findings) > 0 {
		fmt.Println("\n[!] ACTION REQUIRED - VPC issues detected")
		alerts.SendVPCAlerts(ctx, results.Findings)
	} else {
		fmt.Println("\n[+] All VPC configurations look secure.")
	}
}

func runVPCBaseline() {
	ctx := context.Background()
	display.PrintBanner("CREATE VPC BASELINE")
	fmt.Printf("Started at: %s\n\n", now())

	if _, err := baseline.CreateVPCBaseline(ctx); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
	}
}

func runVPCDrift() {
	ctx := context.Background()
	display.PrintBanner("VPC DRIFT DETECTION")
	fmt.Printf("Scan started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareVPCWithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No VPC baseline found.")
		fmt.Println("    Run 'driftshield vpc baseline' first to create one.")
		return
	}
	if len(drifts) > 0 {
		printBox("VPC DRIFT DETECTION RESULTS", []string{
			fmt.Sprintf("Configuration drifts found: %d", len(drifts)),
		})
		fmt.Println("\nDRIFT DETAILS:")
		fmt.Println(strings.Repeat("-", 60))
		for _, d := range drifts {
			fmt.Printf("\n  [%s] %s\n  %s\n", d.Type, d.Resource, d.Message)
			if d.OldValue != "" || d.NewValue != "" {
				fmt.Printf("  Change: %s -> %s\n", d.OldValue, d.NewValue)
			}
		}
		fmt.Println("\n" + strings.Repeat("-", 60))
		alerts.SendVPCDriftAlerts(ctx, drifts)
	} else {
		fmt.Println("\n[+] VPC configuration matches baseline. No drift detected.")
	}
}

func runVPCFix() {
	ctx := context.Background()
	display.PrintBanner("VPC AUTO-FIX")
	fmt.Printf("Started at: %s\n\n", now())

	drifts, exists, err := baseline.CompareVPCWithBaseline(ctx)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if !exists {
		fmt.Println("\n[!] No VPC baseline found.")
		fmt.Println("    Run 'driftshield vpc baseline' first to create one.")
		return
	}
	if len(drifts) == 0 {
		fmt.Println("\n[+] No drifts detected. Nothing to fix.")
		return
	}

	fmt.Printf("Found %d drift(s). The following changes will be made:\n\n", len(drifts))
	for _, d := range drifts {
		switch d.Type {
		case "SUBNET_PUBLIC_IP_CHANGED":
			fmt.Printf("  - Subnet '%s': restore auto-assign public IP to %s\n", d.Resource, d.OldValue)
		default:
			fmt.Printf("  - VPC '%s': [%s] requires manual action\n", d.VPCID, d.Type)
		}
	}

	fmt.Printf("\n%s\n\n", strings.Repeat("-", 60))
	fmt.Println("[!] WARNING: This will modify your VPC configuration!")
	fmt.Print("    Continue? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "yes" && resp != "y" {
		fmt.Println("\n[CANCELLED] No changes made.")
		return
	}

	fmt.Println()
	results, err := baseline.RemediateVPCDrift(ctx, drifts)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	printBox("VPC REMEDIATION RESULTS", []string{
		fmt.Sprintf("Fixed:    %d", len(results.Fixed)),
		fmt.Sprintf("Failed:   %d", len(results.Failed)),
		fmt.Sprintf("Skipped:  %d", len(results.Skipped)),
	})

	if len(results.Fixed) > 0 {
		fmt.Println("\n[+] VPC settings restored. Run 'driftshield vpc' to verify.")
	}
	if len(results.Skipped) > 0 {
		fmt.Println("\n[!] Some changes require manual action (VPC added/deleted, flow logs).")
	}
}

// ──────────────────────────────────────────────────────────────
// All scans
// ──────────────────────────────────────────────────────────────

func runAllScans() {
	ctx := context.Background()
	display.PrintBanner("FULL SECURITY SCAN")
	fmt.Printf("Scan started at: %s\n", now())
	fmt.Printf("Region:          %s\n\n", config.GetRegion())

	// S3
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  S3 BUCKET SCAN")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	s3Results, s3Err := scanner.ScanAllBuckets(ctx)

	// EC2
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  EC2 SECURITY GROUP SCAN")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	ec2Results, ec2Err := scanner.ScanSecurityGroups(ctx)

	// IAM
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  IAM SECURITY SCAN")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	iamResults, iamErr := scanner.ScanIAM(ctx)

	// CloudTrail
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  CLOUDTRAIL SECURITY SCAN")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	ctResults, ctErr := scanner.ScanCloudTrail(ctx)

	// RDS
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  RDS SECURITY SCAN")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	rdsResults, rdsErr := scanner.ScanRDS(ctx)

	// VPC
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  VPC SECURITY SCAN")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	vpcResults, vpcErr := scanner.ScanVPC(ctx)

	s3Secure, s3Risk := 0, 0
	if s3Err == nil {
		s3Secure = len(s3Results.Secure)
		s3Risk = len(s3Results.AtRisk)
	}
	ec2Secure, ec2Risk := 0, 0
	if ec2Err == nil {
		ec2Secure = len(ec2Results.Secure)
		ec2Risk = len(ec2Results.AtRisk)
	}
	iamFindings := 0
	if iamErr == nil {
		iamFindings = len(iamResults.Findings)
	}
	ctFindings := 0
	if ctErr == nil {
		ctFindings = len(ctResults.Findings)
	}
	rdsFindings := 0
	if rdsErr == nil {
		rdsFindings = len(rdsResults.Findings)
	}
	vpcFindings := 0
	if vpcErr == nil {
		vpcFindings = len(vpcResults.Findings)
	}

	printBox("FULL SCAN RESULTS", []string{
		"S3 Buckets:",
		fmt.Sprintf("  Secure: %d, At-risk: %d", s3Secure, s3Risk),
		"EC2 Security Groups:",
		fmt.Sprintf("  Secure: %d, At-risk: %d", ec2Secure, ec2Risk),
		"IAM:",
		fmt.Sprintf("  Findings: %d", iamFindings),
		"CloudTrail:",
		fmt.Sprintf("  Findings: %d", ctFindings),
		"RDS:",
		fmt.Sprintf("  Findings: %d", rdsFindings),
		"VPC:",
		fmt.Sprintf("  Findings: %d", vpcFindings),
	})

	total := s3Risk + ec2Risk + iamFindings + ctFindings + rdsFindings + vpcFindings
	if total > 0 {
		fmt.Printf("\n[!] Total issues found: %d\n", total)
	} else {
		fmt.Println("\n[+] All resources are secure!")
	}
}

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────

func now() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func printBox(title string, lines []string) {
	fmt.Println()
	fmt.Println("+" + strings.Repeat("-", 58) + "+")
	fmt.Printf("|  %-56s|\n", title)
	fmt.Println("+" + strings.Repeat("-", 58) + "+")
	for _, l := range lines {
		fmt.Printf("|  %-56s|\n", l)
	}
	fmt.Println("+" + strings.Repeat("-", 58) + "+")
}
