FROM ubuntu:22.04

RUN apt update && apt install -y socat python3-pip
RUN pip install PyCryptodome

COPY proofing.py /srv/proofing.py
COPY flag.txt /flag.txt

EXPOSE 13301

CMD socat tcp-l:13301,reuseaddr,fork exec:"python3 /srv/proofing.py",pty,raw