package lib

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

func GetRegion() string {
	// AWS_DEFAULT_REGION env var
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		return region
	}
	// EC2 instance metadata
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err == nil {
		metaClient := imds.NewFromConfig(cfg)
		regionOut, err := metaClient.GetRegion(ctx, nil)
		if err == nil && regionOut.Region != "" {
			return regionOut.Region
		}
	}
	// Sensible fallback
	return "us-east-1"
}
