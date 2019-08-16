#!/bin/bash

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
central_config_dir=${TOPDIR}/conf

function check_python_executable() {
    if [[ "$PYTHON" != "" && -x $PYTHON ]]; then
        return 0
    fi

    if !(python --version 2>&1 | grep "3\.[0-9]\.[0-9]") 2>/dev/null 1>&2; then
        echo
        echo "The current version of python is not 3.x.x, please use Python 3.x.x ."
        echo
        exit 1
    fi

    PYTHON="python"$(python --version | cut -b 8-10)
    if !which $PYTHON 2>/dev/null 1>&2; then
        echo
        echo "Can't find a python executable of $PYTHON in PATH"
        echo "Install $PYTHON before continue."
        echo "Or if you installed it in a non-standard PATH, set the PYTHON enviroment varirable to it"
        echo
        exit 1
    fi
}

function read_seafile_data_dir () {
    seafile_ini=${default_ccnet_conf_dir}/seafile.ini
    if [[ ! -f ${seafile_ini} ]]; then
        echo "${seafile_ini} not found. Now quit"
        exit 1
    fi
    seafile_data_dir=$(cat "${seafile_ini}")
    if [[ ! -d ${seafile_data_dir} ]]; then
        echo "Your seafile server data directory \"${seafile_data_dir}\" is invalid or doesn't exits."
        echo "Please check it first, or create this directory yourself."
        echo ""
        exit 1;
    fi
}

check_python_executable;
read_seafile_data_dir;

export CCNET_CONF_DIR=${default_ccnet_conf_dir}
export SEAFILE_CONF_DIR=${seafile_data_dir}
export SEAFILE_CENTRAL_CONF_DIR=${central_config_dir}
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python3.6/site-packages:${INSTALLPATH}/seafile/lib64/python3.6/site-packages:${INSTALLPATH}/seahub/thirdpart:$PYTHONPATH

manage_py=${INSTALLPATH}/seahub/manage.py
exec "$PYTHON" "$manage_py" createsuperuser
