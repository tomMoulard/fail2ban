#!/bin/bash

docker run -d --network host containous/whoami -port 5000

curl -O https://github.com/traefik/traefik/releases/download/v2.3.6/traefik_v2.3.6_linux_amd64.tar.gz
tar -zxvf traefik_v2.3.6_linux_amd64.tar.gz

./traefik --configfile trafik.yaml
