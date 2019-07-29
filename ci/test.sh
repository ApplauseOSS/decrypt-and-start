#!/bin/bash

export ENC_VAR=$(go run test/encrypt-string.go)
go run decrypt-and-start.go env | grep ENC_VAR
