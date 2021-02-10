#!/bin/bash
set -ev

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
