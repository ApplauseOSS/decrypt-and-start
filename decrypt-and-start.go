package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
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
	// Initialize a "fake" session to get our region
	metaSession, _ := session.NewSession()
	metaClient := ec2metadata.New(metaSession)
	region, _ := metaClient.Region()
	conf := aws.NewConfig().WithRegion(region)
	// Initialize KMS session
	sess := session.Must(session.NewSession(conf))
	// KMS service client
	svc := kms.New(sess)
	for _, e := range os.Environ() {
		// e = each k=v pair/line, pair = split k = [0], v = [1] array
		pair := strings.SplitN(e, "=", 2)
		// See if value starts with 'decrypt:'
		if strings.HasPrefix(pair[1], "decrypt:") {
			fmt.Println("Decrypting " + pair[0] + " ...")
			cyphertext, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(pair[1], "decrypt:"))
			if err != nil {
				log.Fatal(err)
			}
			// blob := []byte(string(cyphertext))
			blob := cyphertext
			// decrypt data
			result, err := svc.Decrypt(&kms.DecryptInput{CiphertextBlob: blob})
			if err != nil {
				log.Fatal(err)
			}
			decrypted_value := string(result.Plaintext)
			os.Setenv(pair[0], decrypted_value)
		}
	}
	Exec()
}
