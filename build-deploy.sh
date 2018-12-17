#!/bin/bash

echo "Building image..."

openssl version
echo $PATH
ls
cd 
ls ~ 
echo "End\n"
ls /
echo "End\n"
echo "End\n"
ls /var/go



# docker build -t gcr.io/ethos-197614/accounts:develop -t  gcr.io/ethos-197614/accounts:develop-$SHA  -f ./Dockerfile.dev .

# docker push gcr.io/ethos-197614/accounts:develop-$SHA
# docker push gcr.io/ethos-197614/accounts:develop