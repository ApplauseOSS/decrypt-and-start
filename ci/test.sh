#!/bin/bash

export ENC_VAR=$(go run test/encrypt-string.go 'some-secret-string')
go run decrypt-and-start.go env | grep ENC_VAR
