#!/bin/bash
set -ev

docker run -d --network host containous/whoami -port 5000

curl -L -O https://github.com/traefik/traefik/releases/download/v2.3.6/traefik_v2.3.6_linux_amd64.tar.gz
tar -zxvf traefik_v2.3.6_linux_amd64.tar.gz

sed -i "/goPath:/ s;$; $GOPATH;" "ci/yamls/traefik-ci.yaml"

mkdir ci/inside_ci

./ci/scripts/rules.sh no-rules

./ci/scripts/rules.sh local-banned

./ci/scripts/rules.sh local-allowd