#!/bin/bash

mkdir build
GOOS=linux GOARCH=amd64 go build .
zip function.zip main
mv function.zip build
rm main