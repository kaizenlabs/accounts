#!/bin/bash

echo "Building image..."

openssl version
ls ~/usr/local



# docker build -t gcr.io/ethos-197614/accounts:develop -t  gcr.io/ethos-197614/accounts:develop-$SHA  -f ./Dockerfile.dev .

# docker push gcr.io/ethos-197614/accounts:develop-$SHA
# docker push gcr.io/ethos-197614/accounts:develop