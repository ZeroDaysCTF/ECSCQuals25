FROM ubuntu:20.04@sha256:b25ef49a40b7797937d0d23eca3b0a41701af6757afca23d504d50826f0b37ce AS app
RUN apt-get update && apt-get install -y gcc
COPY chall.c /chall.c
RUN gcc -no-pie -z relro -z lazy /chall.c -o /chall

FROM pwn.red/jail
COPY --from=app / /srv
COPY --from=app /chall /srv/app/run

COPY flag.txt /srv/app/flag.txt
RUN chmod 755 /srv/app/run
