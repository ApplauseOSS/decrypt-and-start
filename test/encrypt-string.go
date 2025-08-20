package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/applauseoss/decrypt-and-start/lib"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// This function should work like an entrypoint: exec "${@}"
func Exec() {
	flag.Parse()
	if len(os.Args) == 1 {
		return
	}
	cmd, err := exec.LookPath(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := syscall.Exec(cmd, flag.Args(), os.Environ()); err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()
	region := lib.GetRegion()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// KMS service client
	client := kms.NewFromConfig(cfg)
	cmk_arn := "arn:aws:kms:us-east-1:873559269338:alias/dev-secret-encryption"

	text := "some-encrypted-string"
	// fmt.Println("Encrypting:", text)

	result, err := client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(cmk_arn),
		Plaintext: []byte(text),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(result.CiphertextBlob))
}
