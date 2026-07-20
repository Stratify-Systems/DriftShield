package baseline

import (
	"context"
	"errors"
	"fmt"
	"github.com/SuryaTK2007/DriftShield/internal/display"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func newS3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return s3.NewFromConfig(cfg), nil
}

// GetBucketConfig retrieves the full security configuration for a bucket.
func GetBucketConfig(ctx context.Context, client *s3.Client, bucketName string) types.S3BucketConfig {
	bc := types.S3BucketConfig{
		BucketName:        bucketName,
		PublicAccessBlock: nil,
		Versioning:        "Disabled",
		Encryption:        "None",
	}

	// Public access block
	pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
			bc.PublicAccessBlock = map[string]bool{
				"BlockPublicAcls": false, "IgnorePublicAcls": false,
				"BlockPublicPolicy": false, "RestrictPublicBuckets": false,
			}
		}
	} else if pab.PublicAccessBlockConfiguration != nil {
		c := pab.PublicAccessBlockConfiguration
		bc.PublicAccessBlock = map[string]bool{
			"BlockPublicAcls":       aws.ToBool(c.BlockPublicAcls),
			"IgnorePublicAcls":      aws.ToBool(c.IgnorePublicAcls),
			"BlockPublicPolicy":     aws.ToBool(c.BlockPublicPolicy),
			"RestrictPublicBuckets": aws.ToBool(c.RestrictPublicBuckets),
		}
	}

	// Versioning
	ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil {
		if ver.Status == s3types.BucketVersioningStatusEnabled {
			bc.Versioning = "Enabled"
		} else if ver.Status == s3types.BucketVersioningStatusSuspended {
			bc.Versioning = "Suspended"
		}
	} else {
		bc.Versioning = "Unknown"
	}

	// Encryption
	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError" {
			bc.Encryption = "None"
		} else {
			bc.Encryption = "Unknown"
		}
	} else {
		rules := enc.ServerSideEncryptionConfiguration.Rules
		if len(rules) > 0 && rules[0].ApplyServerSideEncryptionByDefault != nil {
			bc.Encryption = string(rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm)
		}
	}

	return bc
}

// LoadS3Baseline loads the S3 baseline from disk.
func LoadS3Baseline() (*types.S3Baseline, error) {
	return LoadBaseline[types.S3Baseline](config.BaselineFile)
}

// SaveS3Baseline saves the S3 baseline to disk.
func SaveS3Baseline(bl *types.S3Baseline) error {
	return SaveBaseline(config.BaselineFile, bl)
}

// CreateS3Baseline creates a baseline from current S3 configurations.
func CreateS3Baseline(ctx context.Context) (*types.S3Baseline, error) {
	client, err := newS3Client(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	now := time.Now().Format(time.RFC3339)
	bl := &types.S3Baseline{
		CreatedAt: now,
		UpdatedAt: now,
		Buckets:   make(map[string]types.S3BucketConfig),
	}

	fmt.Println("Creating baseline from current configurations...")
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		fmt.Printf("  Capturing: %s\n", name)
		bl.Buckets[name] = GetBucketConfig(ctx, client, name)
	}

	if err := SaveS3Baseline(bl); err != nil {
		return nil, fmt.Errorf("failed to save baseline: %w", err)
	}

	fmt.Printf("\nBaseline saved to %s\n", config.BaselineFile)
	fmt.Printf("  %d bucket(s) captured\n", len(out.Buckets))
	return bl, nil
}

// CompareS3WithBaseline compares current configs with baseline.
func CompareS3WithBaseline(ctx context.Context) ([]types.S3Drift, bool, error) {
	bl, err := LoadS3Baseline()
	if err != nil {
		return nil, false, err
	}
	if bl == nil {
		fmt.Println("[WARNING] No baseline found. Run with 'baseline' command first.")
		return nil, false, nil
	}

	client, err := newS3Client(ctx)
	if err != nil {
		return nil, false, err
	}

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, false, fmt.Errorf("failed to list buckets: %w", err)
	}

	fmt.Println("Comparing against baseline...")
	fmt.Printf("  Baseline created: %s\n\n", bl.CreatedAt)

	drifts := make([]types.S3Drift, 0)
	driftedBuckets := map[string]bool{}

	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		current := GetBucketConfig(ctx, client, name)
		blCfg, exists := bl.Buckets[name]

		if !exists {
			drifts = append(drifts, types.S3Drift{
				Bucket: name, Type: "NEW_BUCKET",
				Message: "Bucket not in baseline (newly created)",
				Current: current,
			})
			fmt.Printf(display.NEW()+"%s (not in baseline)\n", name)
			driftedBuckets[name] = true
			continue
		}

		// Compare public access block
		if !mapsEqual(current.PublicAccessBlock, blCfg.PublicAccessBlock) {
			var details []string
			for _, key := range []string{"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"} {
				cv, bv := current.PublicAccessBlock[key], blCfg.PublicAccessBlock[key]
				if cv != bv {
					details = append(details, fmt.Sprintf("%s: %v -> %v", key, bv, cv))
				}
			}
			drifts = append(drifts, types.S3Drift{
				Bucket: name, Type: "PUBLIC_ACCESS_CHANGED",
				Message: "Public access settings changed", Details: details,
				Current: current.PublicAccessBlock, Baseline: blCfg.PublicAccessBlock,
			})
			fmt.Printf(display.DRIFT()+"%s\n", name)
			for _, d := range details {
				fmt.Printf("           - %s\n", d)
			}
			driftedBuckets[name] = true
		}

		// Versioning
		if current.Versioning != blCfg.Versioning {
			drifts = append(drifts, types.S3Drift{
				Bucket: name, Type: "VERSIONING_CHANGED",
				Message:  fmt.Sprintf("Versioning: %s -> %s", blCfg.Versioning, current.Versioning),
				Current:  current.Versioning,
				Baseline: blCfg.Versioning,
			})
			fmt.Printf(display.DRIFT()+"%s\n           - Versioning: %s -> %s\n", name, blCfg.Versioning, current.Versioning)
			driftedBuckets[name] = true
		}

		// Encryption
		if current.Encryption != blCfg.Encryption {
			drifts = append(drifts, types.S3Drift{
				Bucket: name, Type: "ENCRYPTION_CHANGED",
				Message:  fmt.Sprintf("Encryption: %s -> %s", blCfg.Encryption, current.Encryption),
				Current:  current.Encryption,
				Baseline: blCfg.Encryption,
			})
			fmt.Printf(display.DRIFT()+"%s\n           - Encryption: %s -> %s\n", name, blCfg.Encryption, current.Encryption)
			driftedBuckets[name] = true
		}

		if !driftedBuckets[name] {
			fmt.Printf(display.OK()+"%s\n", name)
		}
	}

	// Deleted buckets
	currentNames := make(map[string]bool)
	for _, b := range out.Buckets {
		currentNames[aws.ToString(b.Name)] = true
	}
	for bName, bCfg := range bl.Buckets {
		if !currentNames[bName] {
			drifts = append(drifts, types.S3Drift{
				Bucket: bName, Type: "BUCKET_DELETED",
				Message: "Bucket was deleted", Baseline: bCfg,
			})
			fmt.Printf(display.DELETED()+"%s\n", bName)
		}
	}

	return drifts, true, nil
}

// RemediateS3Drift fixes drifted S3 configurations back to baseline.
func RemediateS3Drift(ctx context.Context, drifts []types.S3Drift, dryRun bool) (*types.RemediationResults, error) {
	if len(drifts) == 0 {
		fmt.Println(display.INFO() + "No drifts to remediate.")
		return &types.RemediationResults{}, nil
	}

	client, err := newS3Client(ctx)
	if err != nil {
		return nil, err
	}

	bl, err := LoadS3Baseline()
	if err != nil || bl == nil {
		return nil, fmt.Errorf("failed to load baseline")
	}

	res := &types.RemediationResults{}
	fmt.Println("Starting remediation...")

	for _, drift := range drifts {
		bucket := drift.Bucket

		if drift.Type == "NEW_BUCKET" || drift.Type == "BUCKET_DELETED" {
			msg := "Creating or deleting entire AWS buckets is skipped to prevent accidental data destruction or state conflicts. Please resolve manually or update the baseline."
			fmt.Printf(display.SKIP()+"%s - %s\n          %s\n", bucket, drift.Type, msg)
			res.Skipped = append(res.Skipped, types.RemediationItem{
				Bucket: bucket, Type: drift.Type, Reason: msg,
			})
			continue
		}

		blCfg, ok := bl.Buckets[bucket]
		if !ok {
			continue
		}

		switch drift.Type {
		case "PUBLIC_ACCESS_CHANGED":
			pab := blCfg.PublicAccessBlock
			if dryRun {
				fmt.Printf("[DRY-RUN] Would restore PublicAccessBlock for %s\n", bucket)
				res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
			} else {
				_, fErr := client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
					Bucket: aws.String(bucket),
					PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(pab["BlockPublicAcls"]),
						IgnorePublicAcls:      aws.Bool(pab["IgnorePublicAcls"]),
						BlockPublicPolicy:     aws.Bool(pab["BlockPublicPolicy"]),
						RestrictPublicBuckets: aws.Bool(pab["RestrictPublicBuckets"]),
					},
				})
				if fErr != nil {
					fmt.Printf(display.FAILED()+"%s - %v\n", bucket, fErr)
					res.Failed = append(res.Failed, types.RemediationItem{Bucket: bucket, Type: drift.Type, Error: fErr.Error()})
				} else {
					fmt.Printf(display.FIXED()+"%s - Public access block restored\n", bucket)
					res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
				}
			}
		case "VERSIONING_CHANGED":
			if dryRun {
				fmt.Printf("[DRY-RUN] Would restore Versioning to %s for %s\n", blCfg.Versioning, bucket)
				res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
			} else {
				status := s3types.BucketVersioningStatusSuspended
				if blCfg.Versioning == "Enabled" {
					status = s3types.BucketVersioningStatusEnabled
				}
				_, fErr := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
					Bucket:                  aws.String(bucket),
					VersioningConfiguration: &s3types.VersioningConfiguration{Status: status},
				})
				if fErr != nil {
					fmt.Printf(display.FAILED()+"%s - %v\n", bucket, fErr)
					res.Failed = append(res.Failed, types.RemediationItem{Bucket: bucket, Type: drift.Type, Error: fErr.Error()})
				} else {
					fmt.Printf(display.FIXED()+"%s - Versioning restored to %s\n", bucket, blCfg.Versioning)
					res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
				}
			}
		case "ENCRYPTION_CHANGED":
			if blCfg.Encryption != "" && blCfg.Encryption != "None" && blCfg.Encryption != "Unknown" {
				if dryRun {
					fmt.Printf("[DRY-RUN] Would restore Encryption to %s for %s\n", blCfg.Encryption, bucket)
					res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
				} else {
					_, fErr := client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
						Bucket: aws.String(bucket),
						ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
							Rules: []s3types.ServerSideEncryptionRule{{
								ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
									SSEAlgorithm: s3types.ServerSideEncryption(blCfg.Encryption),
								},
							}},
						},
					})
					if fErr != nil {
						fmt.Printf(display.FAILED()+"%s - %v\n", bucket, fErr)
						res.Failed = append(res.Failed, types.RemediationItem{Bucket: bucket, Type: drift.Type, Error: fErr.Error()})
					} else {
						fmt.Printf(display.FIXED()+"%s - Encryption restored to %s\n", bucket, blCfg.Encryption)
						res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
					}
				}
			} else {
				if dryRun {
					fmt.Printf("[DRY-RUN] Would remove Encryption for %s\n", bucket)
					res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
				} else {
					_, fErr := client.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{
						Bucket: aws.String(bucket),
					})
					if fErr != nil {
						fmt.Printf(display.FAILED()+"%s - %v\n", bucket, fErr)
						res.Failed = append(res.Failed, types.RemediationItem{Bucket: bucket, Type: drift.Type, Error: fErr.Error()})
					} else {
						fmt.Printf(display.FIXED()+"%s - Encryption removed (baseline had none)\n", bucket)
						res.Fixed = append(res.Fixed, types.RemediationItem{Bucket: bucket, Type: drift.Type})
					}
				}
			}

		default:
			fmt.Printf(display.SKIP()+"%s - Unknown drift type: %s\n", bucket, drift.Type)
			res.Skipped = append(res.Skipped, types.RemediationItem{
				Bucket: bucket, Type: drift.Type, Reason: "Unknown drift type",
			})
		}
	}

	return res, nil
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
