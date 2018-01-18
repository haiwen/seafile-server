#!/usr/bin/env python
"""
Install dir: ~/opt/local
Data dir: /tmp/haiwen
"""

import argparse
import glob
import json
import logging
import os
import re
import sys
from os.path import abspath, basename, exists, expanduser, join

import requests
import termcolor

from serverctl import ServerCtl
from utils import (
    cd, chdir, debug, green, info, lru_cache, mkdirs, on_travis, red,
    setup_logging, shell, warning
)

logger = logging.getLogger(__name__)

TOPDIR = abspath(join(os.getcwd(), '..'))
if on_travis():
    PREFIX = expanduser('~/opt/local')
else:
    PREFIX = os.environ.get('SEAFILE_INSTALL_PREFIX', '/usr/local')
INSTALLDIR = '/tmp/seafile-tests'


def num_jobs():
    return int(os.environ.get('NUM_JOBS', 2))


@lru_cache()
def make_build_env():
    env = dict(os.environ)
    libsearpc_dir = abspath(join(TOPDIR, 'libsearpc'))
    ccnet_dir = abspath(join(TOPDIR, 'ccnet-server'))

    def _env_add(*a, **kw):
        kw['env'] = env
        return prepend_env_value(*a, **kw)

    _env_add('CPPFLAGS', '-I%s' % join(PREFIX, 'include'), seperator=' ')

    _env_add('LDFLAGS', '-L%s' % join(PREFIX, 'lib'), seperator=' ')

    _env_add('LDFLAGS', '-L%s' % join(PREFIX, 'lib64'), seperator=' ')

    _env_add('PATH', join(PREFIX, 'bin'))
    _env_add('PYTHONPATH', join(PREFIX, 'lib/python2.7/site-packages'))
    _env_add('PKG_CONFIG_PATH', join(PREFIX, 'lib', 'pkgconfig'))
    _env_add('PKG_CONFIG_PATH', join(PREFIX, 'lib64', 'pkgconfig'))
    _env_add('PKG_CONFIG_PATH', libsearpc_dir)
    _env_add('PKG_CONFIG_PATH', ccnet_dir)
    _env_add('LD_LIBRARY_PATH', join(PREFIX, 'lib'))

    for key in ('PATH', 'PKG_CONFIG_PATH', 'CPPFLAGS', 'LDFLAGS', 'PYTHONPATH'):
        info('%s: %s', key, env.get(key, ''))
    return env


def prepend_env_value(name, value, seperator=':', env=None):
    '''append a new value to a list'''
    env = env or os.environ
    current_value = env.get(name, '')
    new_value = value
    if current_value:
        new_value += seperator + current_value

    env[name] = new_value
    return env


@lru_cache()
def get_branch_json_file():
    url = 'https://raw.githubusercontent.com/haiwen/seafile-test-deploy/master/branches.json'
    return requests.get(url).json()


def get_project_branch(project, default_branch='master'):
    travis_branch = os.environ.get('TRAVIS_BRANCH', 'master')
    if project.name == 'seafile-server':
        return travis_branch
    conf = get_branch_json_file()
    return conf.get(travis_branch, {}).get(project.name, default_branch)


class Project(object):
    def __init__(self, name):
        self.name = name
        self.version = ''

    @property
    def url(self):
        return 'https://www.github.com/haiwen/{}.git'.format(self.name)

    @property
    def projectdir(self):
        return join(TOPDIR, self.name)

    @property
    def branch(self):
        return get_project_branch(self)

    def clone(self):
        if exists(self.name):
            with cd(self.name):
                shell('git fetch origin --tags')
        else:
            shell(
                'git clone --depth=1 --branch {} {}'.
                format(self.branch, self.url)
            )

    @chdir
    def compile_and_install(self):
        cmds = [
            './autogen.sh',
            './configure --prefix={}'.format(PREFIX),
            'make -j{} V=0'.format(num_jobs()),
            'make install',
        ]
        for cmd in cmds:
            shell(cmd)

    @chdir
    def use_branch(self, branch):
        shell('git checkout {}'.format(branch))


class Libsearpc(Project):
    def __init__(self):
        super(Libsearpc, self).__init__('libsearpc')


class CcnetServer(Project):
    def __init__(self):
        super(CcnetServer, self).__init__('ccnet-server')


class SeafileServer(Project):
    def __init__(self):
        super(SeafileServer, self).__init__('seafile-server')


def fetch_and_build():
    libsearpc = Project('libsearpc')
    ccnet = CcnetServer()
    seafile = SeafileServer()

    libsearpc.clone()
    libsearpc.compile_and_install()

    ccnet.clone()
    ccnet.compile_and_install()

    seafile.compile_and_install()


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('-t', '--test-only', action='store_true')

    return ap.parse_args()


def main():
    mkdirs(INSTALLDIR)
    os.environ.update(make_build_env())
    args = parse_args()
    if on_travis() and not args.test_only:
        fetch_and_build()
    if on_travis():
        dbs = ('sqlite3', 'mysql')
    else:
        dbs = ('sqlite3',)
    for db in dbs:
        shell('rm -rf {}/*'.format(INSTALLDIR))
        start_and_test_with_db(db)


def start_and_test_with_db(db):
    info('Setting up seafile server with %s database', db)
    server = ServerCtl(INSTALLDIR, db)
    server.setup()
    with server.run():
        info('Testing with %s database', db)
        with cd(SeafileServer().projectdir):
            shell('py.test', env=server.get_seaserv_envs())


if __name__ == '__main__':
    os.chdir(TOPDIR)
    setup_logging()
    main()
