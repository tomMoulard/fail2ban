#!/bin/bash

set -v

docker run -d --network host containous/whoami -port 5000

curl -L -O https://github.com/traefik/traefik/releases/download/v2.3.6/traefik_v2.3.6_linux_amd64.tar.gz
tar -zxvf traefik_v2.3.6_linux_amd64.tar.gz

sed -i "/goPath:/ s;$; $GOPATH;" "scripts/traefik-ci.yaml"

# NO RULES
sed -i "/filename:/ s;$; scripts/no-rules.yaml;" "scripts/traefik-ci.yaml"

timeout 20s ./traefik --configfile scripts/traefik-ci.yaml 1> logs.all &

sleep 5

curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'
curl 'http://localhost:5000/whoami'

sleep 20

cat logs.all