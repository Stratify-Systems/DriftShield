package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

// NewS3Client creates a new S3 client.
func NewS3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(config.GetRegion()))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return s3.NewFromConfig(cfg), nil
}

// accountBPACache caches the account-level BPA result so we only call it once per scan.
var (
	accountBPAOnce   sync.Once
	accountBPASecure bool
	accountBPAErr    error
)

// resetAccountBPACache clears the cache — called at the start of each scan so tests
// and successive CLI invocations always get a fresh read.
func resetAccountBPACache() {
	accountBPAOnce = sync.Once{}
}

// getAccountLevelBPA fetches the account-level Block Public Access setting.
// Returns true only if all four flags are enabled at the account level.
// If the account has no explicit account-level BPA config, returns false (not secure at account level).
func getAccountLevelBPA(ctx context.Context) (bool, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(config.GetRegion()))
	if err != nil {
		return false, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Resolve the account ID via STS.
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, fmt.Errorf("failed to get caller identity: %w", err)
	}
	accountID := aws.ToString(identity.Account)

	// Query the account-level BPA.
	s3cClient := s3control.NewFromConfig(cfg)
	out, err := s3cClient.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(accountID),
	})
	if err != nil {
		var ae smithy.APIError
		// NoSuchPublicAccessBlockConfiguration means no account-level setting exists.
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
			return false, nil
		}
		return false, fmt.Errorf("failed to get account-level public access block: %w", err)
	}

	c := out.PublicAccessBlockConfiguration
	if c == nil {
		return false, nil
	}

	secure := aws.ToBool(c.BlockPublicAcls) &&
		aws.ToBool(c.IgnorePublicAcls) &&
		aws.ToBool(c.BlockPublicPolicy) &&
		aws.ToBool(c.RestrictPublicBuckets)
	return secure, nil
}

// GetPublicAccessStatus checks whether a bucket is protected from public access.
//
// A bucket is considered SECURE if EITHER:
//   - The account-level Block Public Access has all four settings enabled, OR
//   - The bucket-level Block Public Access has all four settings enabled.
//
// This matches the actual AWS enforcement model: account-level BPA overrides
// bucket-level settings, so a bucket is safe even without its own bucket-level config
// when the account-level protection is fully enabled.
func GetPublicAccessStatus(ctx context.Context, client *s3.Client, bucketName string, accountLevelSecure bool) (bool, map[string]bool) {
	// If account-level BPA is fully enabled, the bucket is protected regardless
	// of its own bucket-level config.
	if accountLevelSecure {
		return true, map[string]bool{
			"BlockPublicAcls":       true,
			"IgnorePublicAcls":      true,
			"BlockPublicPolicy":     true,
			"RestrictPublicBuckets": true,
		}
	}

	// Fall back to bucket-level BPA.
	output, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
			return false, nil
		}
		return false, nil
	}

	cfg := output.PublicAccessBlockConfiguration
	if cfg == nil {
		return false, nil
	}

	m := map[string]bool{
		"BlockPublicAcls":       aws.ToBool(cfg.BlockPublicAcls),
		"IgnorePublicAcls":      aws.ToBool(cfg.IgnorePublicAcls),
		"BlockPublicPolicy":     aws.ToBool(cfg.BlockPublicPolicy),
		"RestrictPublicBuckets": aws.ToBool(cfg.RestrictPublicBuckets),
	}

	secure := m["BlockPublicAcls"] && m["IgnorePublicAcls"] &&
		m["BlockPublicPolicy"] && m["RestrictPublicBuckets"]
	return secure, m
}

// getBucketRegion resolves the home region of a bucket.
// us-east-1 is the default — GetBucketLocation returns an empty LocationConstraint for it.
func getBucketRegion(ctx context.Context, client *s3.Client, bucketName string) string {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return config.GetRegion() // best-effort fallback
	}
	if out.LocationConstraint == "" {
		return "us-east-1"
	}
	return string(out.LocationConstraint)
}

// regionalS3Client creates an S3 client pinned to the given region.
func regionalS3Client(ctx context.Context, region string) (*s3.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}

// ScanAllBuckets scans every S3 bucket for public access risks.
// It checks the account-level Block Public Access first (once, shared across all buckets),
// then falls back to per-bucket settings using the correct region for each bucket.
func ScanAllBuckets(ctx context.Context) (*types.S3ScanResults, error) {
	resetAccountBPACache()

	client, err := NewS3Client(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	fmt.Printf("Found %d bucket(s)\n\n", len(out.Buckets))

	// Fetch account-level BPA once; warn on error but don't abort.
	accountLevelSecure, acctErr := getAccountLevelBPA(ctx)
	if acctErr != nil {
		fmt.Printf("[WARN] Could not check account-level Block Public Access: %v\n", acctErr)
		fmt.Println("       Falling back to bucket-level checks only.\n")
		accountLevelSecure = false
	} else if accountLevelSecure {
		fmt.Println("[INFO] Account-level Block Public Access is fully enabled.")
		fmt.Println("       All buckets are protected at the account level.\n")
	}

	res := &types.S3ScanResults{}
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)

		// Use the bucket's own region for per-bucket checks.
		bucketRegion := getBucketRegion(ctx, client, name)
		bucketClient := client
		if bucketRegion != config.GetRegion() {
			if rc, rcErr := regionalS3Client(ctx, bucketRegion); rcErr == nil {
				bucketClient = rc
			}
		}

		secure, _ := GetPublicAccessStatus(ctx, bucketClient, name, accountLevelSecure)
		if secure {
			fmt.Printf("[SECURE]   %s\n", name)
			res.Secure = append(res.Secure, name)
		} else {
			fmt.Printf("[AT RISK]  %s\n", name)
			res.AtRisk = append(res.AtRisk, name)
		}
	}
	return res, nil
}
