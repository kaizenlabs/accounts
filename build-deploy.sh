#!/bin/bash

echo "Building image..."

openssl version

# docker build -t gcr.io/ethos-197614/accounts:develop -t  gcr.io/ethos-197614/accounts:develop-$SHA  -f ./Dockerfile.dev .

gcloud config list


# docker push gcr.io/ethos-197614/accounts:develop-$SHA
# docker push gcr.io/ethos-197614/accounts:develop