FROM ubuntu:24.04
RUN apt-get update --fix-missing && \
 apt-get install -y socat && \
 rm -rf /var/lib/apt/lists/*
RUN groupadd -r ctf && useradd -r -g ctf ctf

ADD --chown=ctf challenge/ /home/ctf/
RUN chown -R root:ctf /home/ctf
RUN chmod 440 /home/ctf/flag.txt
RUN chmod 750 /home/ctf/smallrop

USER ctf
WORKDIR /home/ctf
EXPOSE 1337
ENTRYPOINT ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:./smallrop,stderr"]