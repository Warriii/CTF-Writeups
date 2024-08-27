# source filesystem
FROM ubuntu:22.04 AS app
# apt install any dependencies if necessary
RUN apt-get update && apt-get install -y openssl libssl-dev && rm -rf /var/lib/apt/lists/*
RUN openssl rand -hex 16 > pwd.txt
RUN openssl rand -hex 16 > uname.txt 

# this is the actual container that runs
FROM pwn.red/jail
# copy ubuntu file system into our redpwn jail
COPY --from=app / /srv
# copy local file into docker
COPY ./challenge /srv/app/run
# copy flag into docker if needed
COPY ./flag.txt /srv/app/flag.txt

RUN cp /srv/pwd.txt /srv/app
RUN cp /srv/uname.txt /srv/app


# Challenge will be served on port 5000