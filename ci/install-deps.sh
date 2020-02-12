#!/bin/bash

set -e -x

SCRIPT=${BASH_SOURCE[0]}
TESTS_DIR=$(dirname "${SCRIPT}")/..
SETUP_DIR=${TESTS_DIR}/ci

cd $SETUP_DIR

sudo apt-get update
sudo apt-get install -y intltool libarchive-dev libcurl4-openssl-dev libevent-dev \
libfuse-dev libglib2.0-dev libjansson-dev libmysqlclient-dev libonig-dev \
sqlite3 libsqlite3-dev libtool net-tools uuid-dev valac mysql-client

pip install wheel
pip install -r requirements.txt
