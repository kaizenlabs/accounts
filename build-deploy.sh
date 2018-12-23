#!/bin/bash

SHA=$(git rev-parse HEAD)

echo "Building image..."

openssl enc -aes-256-cbc -pass pass:$PASS -d -in service-account.enc -out sa.json -p

gcloud auth activate-service-account --key-file sa.json
gcloud config set compute/zone us-central1-a
gcloud config set project $PROJECT_ID
gcloud container clusters get-credentials ethos-cluster-develop
gcloud auth configure-docker -q


docker build -t gcr.io/ethos-197614/accounts:develop -t  gcr.io/ethos-197614/accounts:develop-$SHA  -f ./Dockerfile.dev .

docker push gcr.io/ethos-197614/accounts:develop-$SHA
docker push gcr.io/ethos-197614/accounts:develop

kubectl apply -f k8s_dev

kubectl set image deployments/accounts-deployment accounts=gcr.io/ethos-197614/accounts:develop-$SHA
