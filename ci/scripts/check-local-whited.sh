#!/bin/bash
set -ev

grep "Allowlisted: '127.0.0.1/32'" ci/inside_ci/logs.all && echo 'OK'

grep "127.0.0.1 is denylisted" ci/inside_ci/logs.all || echo 'OK'

grep "127.0.0.1 is now banned temporarily" ci/inside_ci/logs.all || echo 'OK'