#!/bin/bash
docker build -t pwn_smallrop .
docker run -p1338:1337 -it pwn_smallrop