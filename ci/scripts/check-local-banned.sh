#!/bin/bash
set -ev

docker run -d --network host containous/whoami -port 5000

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

sleep 20

cat ci/inside_ci/logs.all

grep "Blacklisted: '127.0.0.1/32'" ci/inside_ci/logs.all && echo 'OK'

grep "127.0.0.1 is in blacklisted" ci/inside_ci/logs.all && echo 'OK'
