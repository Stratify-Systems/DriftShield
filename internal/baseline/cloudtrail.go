package baseline

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func newCloudTrailClient(ctx context.Context) (*cloudtrail.Client, error) {
	region := config.GetRegion()
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return cloudtrail.NewFromConfig(cfg), nil
}

// LoadCloudTrailBaseline loads the CloudTrail baseline from disk.
func LoadCloudTrailBaseline() (*types.CloudTrailBaseline, error) {
	return LoadBaseline[types.CloudTrailBaseline](config.CloudTrailBaselineFile)
}

// SaveCloudTrailBaseline saves the CloudTrail baseline to disk.
func SaveCloudTrailBaseline(bl *types.CloudTrailBaseline) error {
	return SaveBaseline(config.CloudTrailBaselineFile, bl)
}

// CreateCloudTrailBaseline snapshots the current CloudTrail trail configurations.
func CreateCloudTrailBaseline(ctx context.Context) (*types.CloudTrailBaseline, error) {
	client, err := newCloudTrailClient(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe trails: %w", err)
	}

	now := time.Now().Format(time.RFC3339)
	region := config.GetRegion()
	bl := &types.CloudTrailBaseline{
		CreatedAt: now,
		UpdatedAt: now,
		Region:    region,
		Trails:    make(map[string]types.CloudTrailTrailSnapshot),
	}

	fmt.Printf("Creating CloudTrail baseline for region: %s\n", region)
	fmt.Printf("Found %d trail(s)\n\n", len(out.TrailList))

	for _, trail := range out.TrailList {
		name := aws.ToString(trail.Name)
		trailARN := aws.ToString(trail.TrailARN)

		snapshot := types.CloudTrailTrailSnapshot{
			Name:          name,
			IsMultiRegion: aws.ToBool(trail.IsMultiRegionTrail),
			LogValidation: aws.ToBool(trail.LogFileValidationEnabled),
			S3Bucket:      aws.ToString(trail.S3BucketName),
			ReadWriteType: "All",
		}

		status, serr := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: aws.String(trailARN),
		})
		if serr == nil {
			snapshot.IsLogging = aws.ToBool(status.IsLogging)
		}

		selectors, eerr := client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: aws.String(trailARN),
		})
		if eerr == nil && len(selectors.EventSelectors) > 0 {
			snapshot.ReadWriteType = string(selectors.EventSelectors[0].ReadWriteType)
		}

		bl.Trails[name] = snapshot
		fmt.Printf("  Captured trail: %s\n", name)
	}

	if err := SaveCloudTrailBaseline(bl); err != nil {
		return nil, fmt.Errorf("failed to save CloudTrail baseline: %w", err)
	}

	fmt.Printf("\nCloudTrail baseline saved to %s\n", config.CloudTrailBaselineFile)
	fmt.Printf("  %d trail(s) captured\n", len(bl.Trails))
	return bl, nil
}

// CompareCloudTrailWithBaseline compares current trail configs against the baseline.
// Returns (drifts, baselineExists, error).
func CompareCloudTrailWithBaseline(ctx context.Context) ([]types.CloudTrailDrift, bool, error) {
	bl, err := LoadCloudTrailBaseline()
	if err != nil {
		return nil, false, err
	}
	if bl == nil {
		return nil, false, nil
	}

	currentRegion := config.GetRegion()
	if bl.Region != "" && bl.Region != currentRegion {
		return nil, false, fmt.Errorf(
			"[ERROR] Region mismatch: baseline was captured in %q but current region is %q.\n"+
				"  Re-run 'driftshield cloudtrail baseline' in region %q, or pass -r %s to use the baseline region",
			bl.Region, currentRegion, currentRegion, bl.Region,
		)
	}

	client, err := newCloudTrailClient(ctx)
	if err != nil {
		return nil, true, err
	}

	fmt.Printf("Comparing against CloudTrail baseline...\n\n")
	fmt.Printf("  Baseline created: %s\n", bl.CreatedAt)
	fmt.Printf("  Baseline region:  %s\n\n", bl.Region)

	var drifts []types.CloudTrailDrift

	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return nil, true, fmt.Errorf("failed to describe trails: %w", err)
	}

	currentTrails := make(map[string]bool)

	for _, trail := range out.TrailList {
		name := aws.ToString(trail.Name)
		trailARN := aws.ToString(trail.TrailARN)
		currentTrails[name] = true
		trailDrifted := false

		blTrail, exists := bl.Trails[name]
		if !exists {
			drifts = append(drifts, types.CloudTrailDrift{
				Type: "TRAIL_ADDED", TrailName: name,
				Message: fmt.Sprintf("Trail '%s' was added since baseline", name),
			})
			fmt.Printf("[DRIFT]    Trail '%s' added\n", name)
			continue
		}

		status, serr := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: aws.String(trailARN),
		})
		if serr == nil {
			currentLogging := aws.ToBool(status.IsLogging)
			if currentLogging != blTrail.IsLogging {
				drifts = append(drifts, types.CloudTrailDrift{
					Type: "LOGGING_STATUS_CHANGED", TrailName: name,
					Message:  fmt.Sprintf("Trail '%s' logging status changed", name),
					OldValue: fmt.Sprintf("%v", blTrail.IsLogging),
					NewValue: fmt.Sprintf("%v", currentLogging),
				})
				fmt.Printf("[DRIFT]    Trail '%s' logging: %v -> %v\n", name, blTrail.IsLogging, currentLogging)
				trailDrifted = true
			}
		}

		currentValidation := aws.ToBool(trail.LogFileValidationEnabled)
		if currentValidation != blTrail.LogValidation {
			drifts = append(drifts, types.CloudTrailDrift{
				Type: "LOG_VALIDATION_CHANGED", TrailName: name,
				Message:  fmt.Sprintf("Trail '%s' log file validation changed", name),
				OldValue: fmt.Sprintf("%v", blTrail.LogValidation),
				NewValue: fmt.Sprintf("%v", currentValidation),
			})
			fmt.Printf("[DRIFT]    Trail '%s' log validation: %v -> %v\n", name, blTrail.LogValidation, currentValidation)
			trailDrifted = true
		}

		currentMultiRegion := aws.ToBool(trail.IsMultiRegionTrail)
		if currentMultiRegion != blTrail.IsMultiRegion {
			drifts = append(drifts, types.CloudTrailDrift{
				Type: "MULTI_REGION_CHANGED", TrailName: name,
				Message:  fmt.Sprintf("Trail '%s' multi-region setting changed", name),
				OldValue: fmt.Sprintf("%v", blTrail.IsMultiRegion),
				NewValue: fmt.Sprintf("%v", currentMultiRegion),
			})
			fmt.Printf("[DRIFT]    Trail '%s' multi-region: %v -> %v\n", name, blTrail.IsMultiRegion, currentMultiRegion)
			trailDrifted = true
		}

		currentBucket := aws.ToString(trail.S3BucketName)
		if currentBucket != blTrail.S3Bucket {
			drifts = append(drifts, types.CloudTrailDrift{
				Type: "S3_BUCKET_CHANGED", TrailName: name,
				Message:  fmt.Sprintf("Trail '%s' S3 bucket changed", name),
				OldValue: blTrail.S3Bucket,
				NewValue: currentBucket,
			})
			fmt.Printf("[DRIFT]    Trail '%s' S3 bucket: %s -> %s\n", name, blTrail.S3Bucket, currentBucket)
			trailDrifted = true
		}

		selectors, eerr := client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: aws.String(trailARN),
		})
		if eerr == nil && len(selectors.EventSelectors) > 0 {
			currentRW := string(selectors.EventSelectors[0].ReadWriteType)
			if currentRW != blTrail.ReadWriteType {
				drifts = append(drifts, types.CloudTrailDrift{
					Type: "EVENT_SELECTOR_CHANGED", TrailName: name,
					Message:  fmt.Sprintf("Trail '%s' event selector changed", name),
					OldValue: blTrail.ReadWriteType,
					NewValue: currentRW,
				})
				fmt.Printf("[DRIFT]    Trail '%s' read/write type: %s -> %s\n", name, blTrail.ReadWriteType, currentRW)
				trailDrifted = true
			}
		}

		if !trailDrifted {
			fmt.Printf("[OK]       Trail '%s' unchanged\n", name)
		}
	}

	for name := range bl.Trails {
		if !currentTrails[name] {
			drifts = append(drifts, types.CloudTrailDrift{
				Type: "TRAIL_DELETED", TrailName: name,
				Message: fmt.Sprintf("Trail '%s' was deleted since baseline", name),
			})
			fmt.Printf("[DRIFT]    Trail '%s' deleted\n", name)
		}
	}

	return drifts, true, nil
}

// RemediateCloudTrailDrift restores drifted trail settings back to baseline.
func RemediateCloudTrailDrift(ctx context.Context, drifts []types.CloudTrailDrift) (*types.RemediationResults, error) {
	bl, err := LoadCloudTrailBaseline()
	if err != nil || bl == nil {
		return nil, fmt.Errorf("failed to load CloudTrail baseline")
	}

	client, err := newCloudTrailClient(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.RemediationResults{}

	for _, drift := range drifts {
		switch drift.Type {
		case "LOGGING_STATUS_CHANGED":
			blTrail, ok := bl.Trails[drift.TrailName]
			if !ok {
				continue
			}
			if blTrail.IsLogging {
				_, fErr := client.StartLogging(ctx, &cloudtrail.StartLoggingInput{
					Name: aws.String(drift.TrailName),
				})
				if fErr != nil {
					fmt.Printf("[FAILED]  Trail '%s' — could not re-enable logging: %v\n", drift.TrailName, fErr)
					res.Failed = append(res.Failed, types.RemediationItem{Name: drift.TrailName, Type: drift.Type, Error: fErr.Error()})
				} else {
					fmt.Printf("[FIXED]   Trail '%s' — logging re-enabled\n", drift.TrailName)
					res.Fixed = append(res.Fixed, types.RemediationItem{Name: drift.TrailName, Type: drift.Type})
				}
			} else {
				_, fErr := client.StopLogging(ctx, &cloudtrail.StopLoggingInput{
					Name: aws.String(drift.TrailName),
				})
				if fErr != nil {
					fmt.Printf("[FAILED]  Trail '%s' — could not stop logging: %v\n", drift.TrailName, fErr)
					res.Failed = append(res.Failed, types.RemediationItem{Name: drift.TrailName, Type: drift.Type, Error: fErr.Error()})
				} else {
					fmt.Printf("[FIXED]   Trail '%s' — logging stopped (restored to baseline)\n", drift.TrailName)
					res.Fixed = append(res.Fixed, types.RemediationItem{Name: drift.TrailName, Type: drift.Type})
				}
			}

		case "LOG_VALIDATION_CHANGED":
			blTrail, ok := bl.Trails[drift.TrailName]
			if !ok {
				continue
			}
			_, fErr := client.UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{
				Name:                    aws.String(drift.TrailName),
				EnableLogFileValidation: aws.Bool(blTrail.LogValidation),
			})
			if fErr != nil {
				fmt.Printf("[FAILED]  Trail '%s' — could not restore log validation: %v\n", drift.TrailName, fErr)
				res.Failed = append(res.Failed, types.RemediationItem{Name: drift.TrailName, Type: drift.Type, Error: fErr.Error()})
			} else {
				fmt.Printf("[FIXED]   Trail '%s' — log file validation restored to %v\n", drift.TrailName, blTrail.LogValidation)
				res.Fixed = append(res.Fixed, types.RemediationItem{Name: drift.TrailName, Type: drift.Type})
			}

		default:
			msg := "Creating, deleting, or re-routing trails is highly disruptive and therefore skipped. Please resolve manually via the AWS Console or update your baseline."
			fmt.Printf("[SKIP]    Trail '%s' — drift type '%s'\n          %s\n", drift.TrailName, drift.Type, msg)
			res.Skipped = append(res.Skipped, types.RemediationItem{
				Name: drift.TrailName, Type: drift.Type,
				Reason: msg,
			})
		}
	}

	return res, nil
}
