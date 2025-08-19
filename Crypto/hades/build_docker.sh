#!/bin/bash
docker build -t hades .
docker run --rm -d -p 13301:13301 --name hades hades