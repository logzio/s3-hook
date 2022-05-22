#!/bin/bash

mkdir build
GOOS=linux go build ..
zip function.zip main
mv function.zip build
rm main