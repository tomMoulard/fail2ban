#!/bin/bash
set -ev

grep "Blacklisted: '127.0.0.1/32'" ci/inside_ci/logs.all && echo 'OK'

grep "127.0.0.1 is blacklisted" ci/inside_ci/logs.all && echo 'OK'

grep "127.0.0.1 is now banned temporarily" ci/inside_ci/logs.all || echo 'OK'