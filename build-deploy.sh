#!/bin/bash

echo "Building image..."

openssl version
root/google-cloud-sdk/bin/gcloud config list

# docker build -t gcr.io/ethos-197614/accounts:develop -t  gcr.io/ethos-197614/accounts:develop-$SHA  -f ./Dockerfile.dev .

# docker push gcr.io/ethos-197614/accounts:develop-$SHA
# docker push gcr.io/ethos-197614/accounts:develop