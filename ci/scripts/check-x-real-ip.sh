#!/bin/bash
set -ev

grep "127.0.0.1 is now banned temporarily" ci/inside_ci/logs.all && echo 'OK'