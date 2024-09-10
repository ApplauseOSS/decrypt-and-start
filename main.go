package main

import (
	"flag"
	"fmt"
	"github.com/applauseoss/decrypt-and-start/lib"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// This function should work like an entrypoint: exec "${@}"
func Exec() {
	args := flag.Args()
	if len(args) == 0 {
		return
	}
	cmd, err := exec.LookPath(args[0])
	if err != nil {
		log.Fatal(err)
	}
	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatal(err)
	}
}

func main() {
	var workerCount int
	var assumedRole string
	flag.IntVar(&workerCount, "p", 10, "number of parallel workers (defaults to 10)")
	flag.StringVar(&assumedRole, "assume-role", "", "Arn of role to assume for variables decryption")
	flag.Parse()
	workerPool := lib.NewWorkerPool(workerCount)
	workerPool.Start(assumedRole)
	// Put encrypted env vars in queue for workers to process
	go func() {
		for _, e := range os.Environ() {
			// e = each k=v pair/line, pair = split k = [0], v = [1] array
			pair := strings.SplitN(e, "=", 2)
			// See if value starts with 'decrypt:'
			if strings.HasPrefix(pair[1], "decrypt:") {
				env := &lib.EnvVar{Name: pair[0], Value: pair[1]}
				workerPool.InChan <- env
				fmt.Println("Decrypting the value of " + pair[0] + "...")
			}
		}
		// Close the input channel so workers know there's nothing left to process
		close(workerPool.InChan)
	}()
	// Process decrypted values
	for {
		env, ok := <-workerPool.OutChan
		if env != nil {
			os.Setenv(env.Name, env.Value)
		}
		// If the output channel is closed, there are no more values to receive
		if !ok {
			break
		}
	}
	Exec()
}
