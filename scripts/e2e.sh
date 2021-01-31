#!/bin/bash

docker run -d --network host containous/whoami -port 5000

curl -L -O https://github.com/traefik/traefik/releases/download/v2.3.6/traefik_v2.3.6_linux_amd64.tar.gz
tar -zxvf traefik_v2.3.6_linux_amd64.tar.gz

sed -i "/goPath/ s;$; $GOPATH;" "scripts/traefik-ci.yaml"

./traefik --configfile scripts/traefik-ci.yaml