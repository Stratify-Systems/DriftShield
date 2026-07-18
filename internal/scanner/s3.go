package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

// GetPublicAccessStatus checks whether a bucket has public access blocked.
func GetPublicAccessStatus(ctx context.Context, client *s3.Client, bucketName string) (bool, map[string]bool) {
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

// ScanAllBuckets scans every S3 bucket for public access risks.
func ScanAllBuckets(ctx context.Context) (*types.S3ScanResults, error) {
	client, err := NewS3Client(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	fmt.Printf("Found %d bucket(s)\n\n", len(out.Buckets))

	res := &types.S3ScanResults{}
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		secure, _ := GetPublicAccessStatus(ctx, client, name)
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
