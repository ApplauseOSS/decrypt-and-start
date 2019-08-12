package lib

import (
	"encoding/base64"
	enc_sdk "github.com/applauseoss/decrypt-and-start/lib/aws_encryption_sdk"
	"log"
	"strings"
)

type EnvVar struct {
	Name  string
	Value string
}

type WorkerPool struct {
	InChan      chan *EnvVar
	OutChan     chan *EnvVar
	workerCount int
	doneChan    chan bool
}

func NewWorkerPool(count int) *WorkerPool {
	w := &WorkerPool{workerCount: count}
	w.InChan = make(chan *EnvVar)
	w.OutChan = make(chan *EnvVar)
	w.doneChan = make(chan bool)
	return w
}

func (w *WorkerPool) Start() {
	for i := 0; i < w.workerCount; i++ {
		go func() {
			kmsHelper := enc_sdk.NewKmsHelper(GetRegion())
			for {
				env, ok := <-w.InChan
				if env != nil {
					ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(env.Value, "decrypt:"))
					if err != nil {
						log.Fatalf("Error encountered while decrypting var '%s': %s", env.Name, err.Error())
					}
					decrypted_value, err := kmsHelper.Decrypt(ciphertext)
					if err != nil {
						log.Fatalf("Error encountered while decrypting var '%s': %s", env.Name, err.Error())
					}
					env.Value = string(decrypted_value)
					w.OutChan <- env
				}
				if !ok {
					break
				}
			}
			w.doneChan <- true
		}()
	}
	// Wait for workers to finish
	go func() {
		remainingWorkers := w.workerCount
		for {
			done := <-w.doneChan
			if done {
				remainingWorkers--
				if remainingWorkers == 0 {
					break
				}
			}
		}
		// Close the output channel when all workers have finished
		close(w.OutChan)
	}()
}
