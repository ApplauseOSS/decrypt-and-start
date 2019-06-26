#!/bin/bash

ENC_VAR=$(go run test/encrypt-string.go)
./decrypt-and-start env | grep ENV_VAR
