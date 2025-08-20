#!/bin/bash

ENC_VAR=$(go run test/encrypt-string.go)
echo $ENC_VAR
export ENC_VAR="decrypt:$ENC_VAR"
./decrypt-and-start env | grep ENC_VAR
