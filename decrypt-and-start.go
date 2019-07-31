package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/applauseoss/decrypt-and-start/lib"
	enc_sdk "github.com/applauseoss/decrypt-and-start/lib/aws_encryption_sdk"
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
	for _, e := range os.Environ() {
		// e = each k=v pair/line, pair = split k = [0], v = [1] array
		pair := strings.SplitN(e, "=", 2)
		// See if value starts with 'decrypt:'
		if strings.HasPrefix(pair[1], "decrypt:") {
			fmt.Println("Decrypting the value of " + pair[0] + "...")
			ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pair[1], "decrypt:"))
			if err != nil {
				log.Fatal(err)
			}
			kms_helper := enc_sdk.NewKmsHelper(lib.GetRegion())
			decrypted_value, err := kms_helper.Decrypt(ciphertext)
			if err != nil {
				log.Fatal(err)
			}
			os.Setenv(pair[0], string(decrypted_value))
		}
	}
	Exec()
}
