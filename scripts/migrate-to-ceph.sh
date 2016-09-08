#!/bin/bash

echo ""

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
default_seafile_data_dir=${TOPDIR}/seafile-data
default_conf_dir=${TOPDIR}/conf

migrate_to_ceph=${INSTALLPATH}/seafobj_migrate.py

script_name=$0
function usage () {
    echo "usage : "
    echo "$(basename ${script_name}) ceph_seafile_central_conf_dir"
    echo ""
}

function check_python_executable() {
    if [[ "$PYTHON" != "" && -x $PYTHON ]]; then
        return 0
    fi

    if which python2.7 2>/dev/null 1>&2; then
        PYTHON=python2.7
    elif which python27 2>/dev/null 1>&2; then
        PYTHON=python27
    elif which python2.6 2>/dev/null 1>&2; then
        PYTHON=python2.6
    elif which python26 2>/dev/null 1>&2; then
        PYTHON=python26
    else
        echo
        echo "Can't find a python executable of version 2.6 or above in PATH"
        echo "Install python 2.6+ before continue."
        echo "Or if you installed it in a non-standard PATH, set the PYTHON enviroment varirable to it"
        echo
        exit 1
    fi
}

function validate_ccnet_conf_dir () {
    if [[ ! -d ${default_ccnet_conf_dir} ]]; then
        echo "Error: there is no ccnet config directory."
        echo "Have you run setup-seafile.sh before this?"
        echo ""
        exit -1;
    fi
}

function do_migrate_to_ceph () {
    validate_ccnet_conf_dir;

    export CCNET_CONF_DIR=${default_ccnet_conf_dir}
    export SEAFILE_CONF_DIR=${default_seafile_data_dir}
    export SEAFILE_CENTRAL_CONF_DIR=${default_conf_dir}
    export CEPH_SEAFILE_CENTRAL_CONF_DIR=${ceph_seafile_central_conf_dir}

    export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.6/site-packages:${INSTALLPATH}/seafile/lib64/python2.6/site-packages:${INSTALLPATH}/seahub/thirdpart:$PYTHONPATH
    export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seafile/lib64/python2.7/site-packages:$PYTHONPATH

    $PYTHON ${migrate_to_ceph}
}

check_python_executable;

if [ $# -gt 0 ];
then
    for param in $@;
    do
        if [ ${param} = "-h" -o ${param} = "--help" ];
        then
            usage;
            exit 1;
        fi
    done
fi

if [ $# -ne 1 ];
then
    usage;
    exit 1;
fi

ceph_seafile_central_conf_dir="$1"
do_migrate_to_ceph;

echo "Done."
