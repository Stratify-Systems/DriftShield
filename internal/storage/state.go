package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/SuryaTK2007/DriftShield/internal/config"
)

// SaveBaseline saves the given baseline data for a service either to S3 or locally.
func SaveBaseline(ctx context.Context, filename string, data []byte) error {
	if config.StateBucket != "" {
		return saveToS3(ctx, filename, data)
	}
	return saveLocally(filename, data)
}

// LoadBaseline loads the baseline data for a service from S3 or locally.
func LoadBaseline(ctx context.Context, filename string) ([]byte, error) {
	if config.StateBucket != "" {
		return loadFromS3(ctx, filename)
	}
	return loadLocally(filename)
}

func saveLocally(filename string, data []byte) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	return os.WriteFile(filename, data, 0644)
}

func loadLocally(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("baseline not found locally")
		}
		return nil, err
	}
	return data, nil
}

func newS3Client(ctx context.Context) (*s3.Client, error) {
	region := config.StateBucketRegion
	if region == "" {
		region = config.GetRegion()
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for storage: %w", err)
	}
	return s3.NewFromConfig(cfg), nil
}

func saveToS3(ctx context.Context, filename string, data []byte) error {
	client, err := newS3Client(ctx)
	if err != nil {
		return err
	}

	key := filepath.Base(filename)
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(config.StateBucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("failed to save baseline to S3 bucket %s: %w", config.StateBucket, err)
	}
	return nil
}

func loadFromS3(ctx context.Context, filename string) ([]byte, error) {
	client, err := newS3Client(ctx)
	if err != nil {
		return nil, err
	}

	key := filepath.Base(filename)
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(config.StateBucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load baseline from S3 bucket %s: %w", config.StateBucket, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object body: %w", err)
	}
	return data, nil
}
