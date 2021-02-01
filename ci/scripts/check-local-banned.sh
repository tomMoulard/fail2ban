#!/bin/bash
set -ev

grep "Blacklisted: '127.0.0.1/32'" ci/inside_ci/logs.all && echo 'OK'

grep "127.0.0.1 is in blacklisted" ci/inside_ci/logs.all && echo 'OK'
