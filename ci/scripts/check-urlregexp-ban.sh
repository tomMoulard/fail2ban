#!/bin/bash
set -ev

docker run -d --network host containous/whoami -port 5000
docker run -d --network host containous/whoami -port 30000
sleep 5

curl 'http://whoami1.docker.localhost:8000/'
curl 'http://whoami2.docker.localhost:8000/'
curl 'http://whoami1.docker.localhost:8000/whoami'
curl 'http://whoami2.docker.localhost:8000/whoami'
curl 'http://localhost:8000/whoami1'
curl 'http://localhost:8000/whoami2'

grep "Url ('whoami1.docker.localhost:8000/path1') was matched by regexp: '/whoami'" ci/inside_ci/logs.all && echo 'OK'
grep "Url ('whoami2.docker.localhost:8000/path1') was matched by regexp: '/whoami'" ci/inside_ci/logs.all && echo 'OK'
grep "Url ('localhost:8000/whoami1') was matched by regexp: '/whoami'" ci/inside_ci/logs.all && echo 'OK'
grep "Url ('localhost:8000/whoami2') was matched by regexp: '/whoami'" ci/inside_ci/logs.all && echo 'OK'


curl 'http://whoami1.docker.localhost:8000/path2'
curl 'http://whoami2.docker.localhost:8000/path2'
curl 'http://whoami1.docker.localhost:8000/path3'
curl 'http://whoami2.docker.localhost:8000/path3'

grep "Url ('whoami1.docker.localhost:8000/path2') was matched by regexp: 'whoami1.docker.localhost:8000/path2'" ci/inside_ci/logs.all && echo 'OK'
grep "Url ('whoami2.docker.localhost:8000/path3') was matched by regexp: 'whoami1.docker.localhost:8000/path3'" ci/inside_ci/logs.all && echo 'OK'

curl 'http://whoami1.docker.localhost:8000/path2/one'
curl 'http://whoami2.docker.localhost:8000/path2/one'
curl 'http://whoami1.docker.localhost:8000/path3/one'
curl 'http://whoami2.docker.localhost:8000/path3/one'

grep "Url ('whoami1.docker.localhost:8000/path2/one') was matched by regexp: 'whoami1.docker.localhost:8000/path2'" ci/inside_ci/logs.all && echo 'OK'
grep "Url ('whoami2.docker.localhost:8000/path3/one') was matched by regexp: 'whoami1.docker.localhost:8000/path3'" ci/inside_ci/logs.all && echo 'OK'

sleep 20

cat ci/inside_ci/logs.all


