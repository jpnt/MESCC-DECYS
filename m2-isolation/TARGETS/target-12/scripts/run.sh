#!/usr/bin/sh

## run inside vm with docker installed
docker run --name captest -d -p 8000:80 isepdei/capabilities01

## capsh
docker exec captest sh -c 'capsh --print' > capsh-print.txt

## proc status
docker exec captest sh -c 'grep Cap /proc/1/status' > proc-status.txt
