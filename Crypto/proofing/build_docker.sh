#!/bin/bash
docker build -t proofing .
docker run --rm -d -p 13300:13301 --name proofing proofing