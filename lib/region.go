package lib

import (
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"os"
)

func GetRegion() string {
	// AWS_DEFAULT_REGION env var
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		return region
	}
	// EC2 instance metadata
	metaSession, _ := session.NewSession()
	metaClient := ec2metadata.New(metaSession)
	region, _ := metaClient.Region()
	if region != "" {
		return region
	}
	// Sensible fallback
	return "us-east-1"
}
