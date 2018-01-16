#!/usr/bin/env python
#coding: UTF-8

import argparse
import glob
import os
import re
import sys
from collections import namedtuple
from contextlib import contextmanager
from os.path import abspath, basename, dirname, exists, join

import requests
from pexpect import spawn

from utils import (
    cd, chdir, create_dir, debug, green, info, red, setup_logging, shell,
    warning
)

MYSQL_ROOT_PASSWD = 's123'


class ServerCtl(object):
    def __init__(self, datadir, db='sqlite3'):
        self.db = db
        self.datadir = datadir
        self.central_conf_dir = join(datadir, 'conf')
        self.seafile_data_dir = join(datadir, 'seafile-data')
        self.ccnet_conf_dir = join(datadir, 'ccnet')
        self.log_dir = join(datadir, 'logs')
        create_dir(self.log_dir)

        self.ccnet_log = join(self.log_dir, 'ccnet.log')
        self.seafile_log = join(self.log_dir, 'seafile.log')

        self.ccnet_proc = None
        self.seafile_proc = None

    def setup(self):
        if self.db == 'mysql':
            create_mysql_dbs()

        self.init_ccnet()
        self.init_seafile()

    def init_ccnet(self):
        cmd = [
            'ccnet-init',
            '-F',
            self.central_conf_dir,
            '-c',
            self.ccnet_conf_dir,
            '--name',
            'test',
            '--host',
            'test.seafile.com',
        ]
        shell(cmd)

    def init_seafile(self):
        cmd = [
            'seaf-server-init',
            '--central-config-dir',
            self.central_conf_dir,
            '--seafile-dir',
            self.seafile_data_dir,
            '--fileserver-port',
            '8082',
        ]

        shell(cmd)

    @contextmanager
    def run(self):
        try:
            self.start()
            yield self
        finally:
            self.stop()
            for logfile in self.ccnet_log, self.seafile_log:
                shell('echo {0}; cat {0}'.format(logfile))

    def start(self):
        self.start_ccnet()
        self.start_seafile()

    def start_ccnet(self):
        cmd = [
            "ccnet-server",
            "-F",
            self.central_config_dir,
            "-c",
            self.ccnet_conf_dir,
            "-f",
            self.ccnet_log,
        ]
        self.ccnet_proc = shell(cmd)

    def start_seafile(self):
        cmd = [
            "seafile-server",
            "-F",
            self.central_config_dir,
            "-c",
            self.seafile_conf_dir,
            "-d",
            self.seafile_data_dir,
            "-l",
            self.seafile_log,
        ]
        self.seafile_proc = shell(cmd)

    def stop(self):
        if self.ccnet_proc:
            self.ccnet_proc.terminate()
        if self.seafile_proc:
            self.seafile_proc.terminate()


def create_mysql_dbs():
    shell('mysqladmin -u root password %s' % MYSQL_ROOT_PASSWD)
    sql = '''\
create database `ccnet-existing` character set = 'utf8';
create database `seafile-existing` character set = 'utf8';
create database `seahub-existing` character set = 'utf8';

create user 'seafile'@'localhost' identified by 'seafile';

GRANT ALL PRIVILEGES ON `ccnet-existing`.* to `seafile`@localhost;
GRANT ALL PRIVILEGES ON `seafile-existing`.* to `seafile`@localhost;
GRANT ALL PRIVILEGES ON `seahub-existing`.* to `seafile`@localhost;
    '''

    shell('mysql -u root -p%s' % MYSQL_ROOT_PASSWD, inputdata=sql)
