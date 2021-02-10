#!/bin/bash
set -ev

curl -L -O https://github.com/traefik/traefik/releases/download/v2.3.6/traefik_v2.3.6_linux_amd64.tar.gz
tar -zxvf traefik_v2.3.6_linux_amd64.tar.gz

sed -i "/goPath:/ s;$; $GOPATH;" "ci/yamls/traefik-ci.yaml"

mkdir ci/inside_ci

sed "/filename:/ s;$; ci/yamls/$1.yaml;" "ci/yamls/traefik-ci.yaml" > ci/inside_ci/ci-$1.yaml

timeout 20s ./traefik --configfile ci/inside_ci/ci-$1.yaml 1> ci/inside_ci/logs.all || echo 'timeout traefik' &

sleep 5

./ci/scripts/check-$1.sh
