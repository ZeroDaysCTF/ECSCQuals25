#sudo docker build -t pwn1 .
#sudo docker run -d -p 2237:2237 --rm -it pwn1


FROM python:3.6

EXPOSE 2337

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y update && \
    apt-get -y install gcc socat coreutils python3 curl dos2unix && \
    useradd -m -s /bin/bash ctf

RUN pip install pycryptodome sympy

WORKDIR /app


COPY flag.txt .

COPY chall.py .
RUN dos2unix chall.py
RUN chmod +x chall.py && \
    chmod 444 flag.txt

USER ctf

CMD socat -T 30 \
    TCP-LISTEN:2337,nodelay,reuseaddr,fork \
    EXEC:"stdbuf -i0 -o0 -e0 /app/chall.py"