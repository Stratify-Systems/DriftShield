package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func NewCloudTrailClient(ctx context.Context) (*cloudtrail.Client, error) {
	region := config.GetRegion()
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return cloudtrail.NewFromConfig(cfg), nil
}

// ScanCloudTrail checks CloudTrail configuration for security issues.
func ScanCloudTrail(ctx context.Context) (*types.CloudTrailScanResults, error) {
	client, err := NewCloudTrailClient(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.CloudTrailScanResults{}

	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe trails: %w", err)
	}

	region := config.GetRegion()
	fmt.Printf("Region: %s\n", region)
	fmt.Printf("Found %d trail(s)\n\n", len(out.TrailList))

	if len(out.TrailList) == 0 {
		res.Findings = append(res.Findings, types.CloudTrailFinding{
			Type: "NO_TRAILS", Severity: "CRITICAL",
			TrailName: "N/A",
			Message:   "No CloudTrail trails found — all API activity is unlogged",
		})
		fmt.Println("[CRITICAL] No CloudTrail trails configured")
		return res, nil
	}

	hasMultiRegion := false

	for _, trail := range out.TrailList {
		name := aws.ToString(trail.Name)
		trailARN := aws.ToString(trail.TrailARN)

		// Get trail status (is logging active?)
		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: aws.String(trailARN),
		})
		if err != nil {
			res.Findings = append(res.Findings, types.CloudTrailFinding{
				Type: "CHECK_FAILED", Severity: "HIGH",
				TrailName: name,
				Message:   fmt.Sprintf("Could not get trail status: %v", err),
			})
			continue
		}

		if !aws.ToBool(status.IsLogging) {
			res.Findings = append(res.Findings, types.CloudTrailFinding{
				Type: "LOGGING_DISABLED", Severity: "CRITICAL",
				TrailName: name,
				Message:   fmt.Sprintf("Trail '%s' exists but logging is DISABLED", name),
			})
			fmt.Printf("[CRITICAL] Trail '%s' — logging is DISABLED\n", name)
		} else {
			fmt.Printf("[SECURE]   Trail '%s' — logging is active\n", name)
		}

		// Log file validation
		if !aws.ToBool(trail.LogFileValidationEnabled) {
			res.Findings = append(res.Findings, types.CloudTrailFinding{
				Type: "LOG_VALIDATION_DISABLED", Severity: "MEDIUM",
				TrailName: name,
				Message:   fmt.Sprintf("Trail '%s' has log file validation disabled (tampering undetectable)", name),
			})
			fmt.Printf("[MEDIUM]   Trail '%s' — log file validation disabled\n", name)
		} else {
			fmt.Printf("[SECURE]   Trail '%s' — log file validation enabled\n", name)
		}

		// Multi-region coverage
		if aws.ToBool(trail.IsMultiRegionTrail) {
			hasMultiRegion = true
			fmt.Printf("[SECURE]   Trail '%s' — multi-region coverage\n", name)
		} else {
			fmt.Printf("[INFO]     Trail '%s' — single-region only\n", name)
		}

		// Management events (read/write)
		selectors, err := client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: aws.String(trailARN),
		})
		if err == nil && len(selectors.EventSelectors) > 0 {
			sel := selectors.EventSelectors[0]
			if string(sel.ReadWriteType) == "WriteOnly" {
				res.Findings = append(res.Findings, types.CloudTrailFinding{
					Type: "READ_EVENTS_NOT_LOGGED", Severity: "LOW",
					TrailName: name,
					Message:   fmt.Sprintf("Trail '%s' only logs write events — read events are not captured", name),
				})
				fmt.Printf("[LOW]      Trail '%s' — read events not logged\n", name)
			}
		}

		res.Trails = append(res.Trails, types.TrailSummary{
			Name:              name,
			IsLogging:         aws.ToBool(status.IsLogging),
			IsMultiRegion:     aws.ToBool(trail.IsMultiRegionTrail),
			LogValidation:     aws.ToBool(trail.LogFileValidationEnabled),
			S3Bucket:          aws.ToString(trail.S3BucketName),
			HasCustomEventSel: len(selectors.EventSelectors) > 0,
		})
	}

	if !hasMultiRegion {
		res.Findings = append(res.Findings, types.CloudTrailFinding{
			Type: "NO_MULTI_REGION_TRAIL", Severity: "HIGH",
			TrailName: "N/A",
			Message:   "No multi-region trail found — activity in other regions is unlogged",
		})
		fmt.Println("[HIGH]     No multi-region trail configured")
	}

	return res, nil
}
