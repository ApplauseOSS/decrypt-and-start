package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	// "strings"
	"syscall"
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
	// Initialize KMS session
	// sess := session.Must(session.NewSessionWithOptions(session.Options{
	//	SharedConfigState: session.SharedConfigEnable,
	// }))
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	}))
	cmk_arn := "arn:aws:kms:us-east-1:873559269338:key/1b03c937-31f8-4fa5-a5cf-42e9f437bda2"
	// KMS service client
	svc := kms.New(sess)

	text := "some-encrypted-string"

	result, err := svc.Encrypt(&kms.EncryptInput{
		KeyId: aws.String(cmk_arn),
		Plaintext: []byte(text),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(base64.URLEncoding.EncodeToString(result.CiphertextBlob))
}
