#!/bin/bash

echo ""

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
default_conf_dir=${TOPDIR}/conf
seaf_fsck=${INSTALLPATH}/seafile/bin/seaf-fsck
default_seafile_data_dir=${TOPDIR}/seafile-data

export PATH=${INSTALLPATH}/seafile/bin:$PATH
export SEAFILE_LD_LIBRARY_PATH=${INSTALLPATH}/seafile/lib/:${INSTALLPATH}/seafile/lib64:${LD_LIBRARY_PATH}

script_name=$0
function usage () {
    echo "usage : "
    echo "$(basename ${script_name}) [-h/--help] [-r/--repair] [-E/--export path_to_export] [repo_id_1 [repo_id_2 ...]]"
    echo ""
}

function validate_ccnet_conf_dir () {
    if [[ ! -d ${default_ccnet_conf_dir} ]]; then
        echo "Error: there is no ccnet config directory."
        echo "Have you run setup-seafile.sh before this?"
        echo ""
        exit -1;
    fi
}

function validate_seafile_data_dir () {
    if [[ ! -d ${default_seafile_data_dir} ]]; then
        echo "Your seafile server data directory \"${default_seafile_data_dir}\" is invalid or doesn't exits."
        echo "Please check it first, or create this directory yourself."
        echo ""
        exit 1;
    fi
}

function run_seaf_fsck () {
    validate_ccnet_conf_dir;
    validate_seafile_data_dir;

    echo "Starting seaf-fsck, please wait ..."
    echo

    LD_LIBRARY_PATH=$SEAFILE_LD_LIBRARY_PATH ${seaf_fsck} \
        -c "${default_ccnet_conf_dir}" -d "${default_seafile_data_dir}" \
        -F "${default_conf_dir}" \
        ${seaf_fsck_opts}

    echo "seaf-fsck run done"
    echo
}

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

seaf_fsck_opts=$@
run_seaf_fsck;

echo "Done."
