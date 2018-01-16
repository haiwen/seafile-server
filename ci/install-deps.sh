#!/bin/bash

set -e -x

SCRIPT=${BASH_SOURCE[0]}
TESTS_DIR=$(dirname "${SCRIPT}")/..
SETUP_DIR=${TESTS_DIR}/ci

cd $SETUP_DIR

pip install -r requirements.txt

# download precompiled libevhtp
# TODO(lins05): we should consider build from source with https://github.com/criticalstack/libevhtp in the future
libevhtp_bin=libevhtp-bin_1.2.0.tar.gz
wget https://dl.bintray.com/lins05/generic/libevhtp-bin/$libevhtp_bin
# tar xvf $libevhtp_bin --strip-components=3 -C /usr
tar xf $libevhtp_bin -C $HOME
