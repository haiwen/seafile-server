#!/bin/bash

set -e -x

SCRIPT=${BASH_SOURCE[0]}
TESTS_DIR=$(dirname "${SCRIPT}")

cd $TESTS_DIR

py.test "$@"
