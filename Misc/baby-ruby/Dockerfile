FROM ruby:3.1-slim

EXPOSE 2337

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y update && \
    apt-get -y install gcc socat coreutils python3 dos2unix && \
    useradd -m -s /bin/bash ctf

WORKDIR /app


COPY flag.txt /

COPY jail.rb .
RUN dos2unix jail.rb
RUN chmod +x jail.rb && \
    chmod 444 /flag.txt

USER ctf

CMD ["ruby", "/app/jail.rb"]