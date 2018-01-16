#!/bin/bash

set -e

SCRIPT=${BASH_SOURCE[0]}
PROJECT_DIR=$(dirname "${SCRIPT}")

cd $PROJECT_DIR

export PYTHONPATH=$PROJECT_DIR:$PYTHONPATH

ci/run.py --test-only
