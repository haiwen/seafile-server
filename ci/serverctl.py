#!/usr/bin/env python
#coding: UTF-8

import argparse
import glob
import logging
import os
import re
import sys
from collections import namedtuple
from contextlib import contextmanager
from os.path import abspath, basename, dirname, exists, join

import requests
from tenacity import TryAgain, retry, stop_after_attempt, wait_fixed

from utils import (
    cd, chdir, debug, green, info, mkdirs, red, setup_logging, shell, warning
)

logger = logging.getLogger(__name__)


class ServerCtl(object):
    def __init__(self, topdir, datadir, db='sqlite3', seaf_server_bin='seaf-server', ccnet_server_bin='ccnet-server'):
        self.db = db
        self.datadir = datadir
        self.central_conf_dir = join(datadir, 'conf')
        self.seafile_conf_dir = join(datadir, 'seafile-data')
        self.ccnet_conf_dir = join(datadir, 'ccnet')

        self.log_dir = join(datadir, 'logs')
        mkdirs(self.log_dir)
        self.ccnet_log = join(self.log_dir, 'ccnet.log')
        self.seafile_log = join(self.log_dir, 'seafile.log')

        self.ccnet_server_bin = ccnet_server_bin
        self.seaf_server_bin = seaf_server_bin

        self.sql_dir = join(topdir, 'seafile-server', 'scripts', 'sql')

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
        if self.db == 'mysql':
            self.add_ccnet_db_conf()
        else:
            self.add_ccnet_sqlite_db_conf()

    def add_ccnet_sqlite_db_conf(self):
        ccnet_conf = join(self.central_conf_dir, 'ccnet.conf')
        ccnet_db_conf = '''\
[Database]
'''
        with open(ccnet_conf, 'a+') as fp:
            fp.write('\n')
            fp.write(ccnet_db_conf)

    def add_ccnet_db_conf(self):
        ccnet_conf = join(self.central_conf_dir, 'ccnet.conf')
        ccnet_db_conf = '''\
[Database]
ENGINE = mysql
HOST = 127.0.0.1
PORT = 3306
USER = seafile
PASSWD = seafile
DB = ccnet
CONNECTION_CHARSET = utf8
'''
        with open(ccnet_conf, 'a+') as fp:
            fp.write('\n')
            fp.write(ccnet_db_conf)

    def init_seafile(self):
        cmd = [
            'seaf-server-init',
            '--central-config-dir',
            self.central_conf_dir,
            '--seafile-dir',
            self.seafile_conf_dir,
            '--fileserver-port',
            '8082',
        ]

        shell(cmd)
        if self.db == 'mysql':
            self.add_seafile_db_conf()
        else:
            self.add_seafile_sqlite_db_conf()

    def add_seafile_sqlite_db_conf(self):
        seafile_conf = join(self.central_conf_dir, 'seafile.conf')
        seafile_db_conf = '''\
[database]
'''
        with open(seafile_conf, 'a+') as fp:
            fp.write('\n')
            fp.write(seafile_db_conf)

    def add_seafile_db_conf(self):
        seafile_conf = join(self.central_conf_dir, 'seafile.conf')
        seafile_db_conf = '''\
[database]
type = mysql
host = 127.0.0.1
port = 3306
user = seafile
password = seafile
db_name = seafile
connection_charset = utf8
'''
        with open(seafile_conf, 'a+') as fp:
            fp.write('\n')
            fp.write(seafile_db_conf)

    @contextmanager
    def run(self):
        try:
            self.start()
            yield self
        except:
            self.print_logs()
            raise
        finally:
            self.stop()

    def print_logs(self):
        for logfile in self.ccnet_log, self.seafile_log:
            if exists(logfile):
                shell('cat {0}'.format(logfile))

    @retry(wait=wait_fixed(1), stop=stop_after_attempt(10))
    def wait_ccnet_ready(self):
        if not exists(join(self.ccnet_conf_dir, 'ccnet.sock')):
            raise TryAgain

    def start(self):
        logger.info('Starting to create ccnet and seafile db tables')
        self.create_database_tables()
        logger.info('Starting ccnet server')
        self.start_ccnet()
        self.wait_ccnet_ready()
        logger.info('Starting seafile server')
        self.start_seafile()

    def create_database_tables(self):
        if self.db == 'mysql':
           ccnet_sql_path = join(self.sql_dir, 'mysql', 'ccnet.sql')
           seafile_sql_path = join(self.sql_dir, 'mysql', 'seafile.sql')
           sql = '''USE ccnet; source {};
                    USE seafile; source {};'''.format(ccnet_sql_path, seafile_sql_path)
           shell('sudo mysql -u root -proot', inputdata=sql, wait=False)
        else:
           config_sql_path = join(self.sql_dir, 'sqlite', 'config.sql')
           groupmgr_sql_path = join(self.sql_dir, 'sqlite', 'groupmgr.sql')
           org_sql_path = join(self.sql_dir, 'sqlite', 'org.sql')
           user_sql_path = join(self.sql_dir, 'sqlite', 'user.sql')
           seafile_sql_path = join(self.sql_dir, 'sqlite', 'seafile.sql')

           misc_dir = join(self.ccnet_conf_dir, 'misc')
           os.mkdir (misc_dir, 0755)
           groupmgr_dir = join(self.ccnet_conf_dir, 'GroupMgr')
           os.mkdir (groupmgr_dir, 0755)
           orgmgr_dir = join(self.ccnet_conf_dir, 'OrgMgr')
           os.mkdir (orgmgr_dir, 0755)
           usermgr_dir = join(self.ccnet_conf_dir, 'PeerMgr')
           os.mkdir (usermgr_dir, 0755)

           config_db_path = join(misc_dir, 'config.db')
           groupmgr_db_path = join(groupmgr_dir, 'groupmgr.db')
           orgmgr_db_path = join(orgmgr_dir, 'orgmgr.db')
           usermgr_db_path = join(usermgr_dir, 'usermgr.db')
           seafile_db_path = join(self.seafile_conf_dir, 'seafile.db')

           sql = '.read {}'.format(config_sql_path)
           shell('sqlite3 ' + config_db_path, inputdata=sql, wait=False)
           sql = '.read {}'.format(groupmgr_sql_path)
           shell('sqlite3 ' + groupmgr_db_path, inputdata=sql, wait=False)
           sql = '.read {}'.format(org_sql_path)
           shell('sqlite3 ' + orgmgr_db_path, inputdata=sql, wait=False)
           sql = '.read {}'.format(user_sql_path)
           shell('sqlite3 ' + usermgr_db_path, inputdata=sql, wait=False)
           sql = '.read {}'.format(user_sql_path)
           shell('sqlite3 ' + usermgr_db_path, inputdata=sql, wait=False)
           sql = '.read {}'.format(seafile_sql_path)
           shell('sqlite3 ' + seafile_db_path, inputdata=sql, wait=False)

    def start_ccnet(self):
        cmd = [
            self.ccnet_server_bin,
            "-F",
            self.central_conf_dir,
            "-c",
            self.ccnet_conf_dir,
            "-f",
            self.ccnet_log,
        ]
        self.ccnet_proc = shell(cmd, wait=False)

    def start_seafile(self):
        cmd = [
            self.seaf_server_bin,
            "-F",
            self.central_conf_dir,
            "-c",
            self.ccnet_conf_dir,
            "-d",
            self.seafile_conf_dir,
            "-l",
            self.seafile_log,
        ]
        self.seafile_proc = shell(cmd, wait=False)

    def stop(self):
        if self.ccnet_proc:
            logger.info('Stopping ccnet server')
            self.ccnet_proc.terminate()
        if self.seafile_proc:
            logger.info('Stopping seafile server')
            self.seafile_proc.terminate()

    def get_seaserv_envs(self):
        envs = dict(os.environ)
        envs.update({
            'SEAFILE_CENTRAL_CONF_DIR': self.central_conf_dir,
            'CCNET_CONF_DIR': self.ccnet_conf_dir,
            'SEAFILE_CONF_DIR': self.seafile_conf_dir,
        })
        return envs


def create_mysql_dbs():
    sql = '''\
create database `ccnet` character set = 'utf8';
create database `seafile` character set = 'utf8';

create user 'seafile'@'localhost' identified by 'seafile';

GRANT ALL PRIVILEGES ON `ccnet`.* to `seafile`@localhost;
GRANT ALL PRIVILEGES ON `seafile`.* to `seafile`@localhost;
    '''

    shell('sudo mysql -u root -proot', inputdata=sql)
