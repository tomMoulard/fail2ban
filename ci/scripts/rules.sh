#!/bin/bash

set -v

echo "########### $1 # START ##############"

sed "/filename:/ s;$; ci/yamls/$1.yaml;" "ci/yamls/traefik-ci.yaml" > ci/inside_ci/ci-$1.yaml

timeout 20s ./traefik --configfile ci/inside_ci/ci-$1.yaml 1> ci/inside_ci/logs.all &

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

cat ci/inside_ci/logs.all

echo '########### $1 # END ##############'
