#!/bin/bash
set -ev

echo "########### $1 # START ##############"

sed "/filename:/ s;$; ci/yamls/$1.yaml;" "ci/yamls/traefik-ci.yaml" > ci/inside_ci/ci-$1.yaml

timeout 20s ./traefik --configfile ci/inside_ci/ci-$1.yaml 1> ci/inside_ci/logs.all || echo 'timeout traefik' &

sleep 5

curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/whoami'
curl 'http://localhost:8000/yes'
curl 'http://localhost:8000/no'
curl 'http://localhost:8000/blocked'


sleep 20

cat ci/inside_ci/logs.all

./ci/scripts/check-$1.sh

echo "########### $1 # END ##############"
