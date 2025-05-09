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
    cd, chdir, debug, green, info, lru_cache, mkdirs, on_github_actions, red,
    setup_logging, shell, warning
)

logger = logging.getLogger(__name__)

TOPDIR = abspath(join(os.getcwd(), '..'))
if on_github_actions():
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
    if on_github_actions():
        _env_add('PYTHONPATH', join(os.environ.get('RUNNER_TOOL_CACHE'), 'Python/3.12.10/x64/lib/python3.12/site-packages'))
    _env_add('PYTHONPATH', join(PREFIX, 'lib/python3.12/site-packages'))
    _env_add('PKG_CONFIG_PATH', join(PREFIX, 'lib', 'pkgconfig'))
    _env_add('PKG_CONFIG_PATH', join(PREFIX, 'lib64', 'pkgconfig'))
    _env_add('PKG_CONFIG_PATH', libsearpc_dir)
    _env_add('PKG_CONFIG_PATH', ccnet_dir)
    _env_add('LD_LIBRARY_PATH', join(PREFIX, 'lib'))

    _env_add('JWT_PRIVATE_KEY', '@%ukmcl$k=9u-grs4azdljk(sn0kd!=mzc17xd7x8#!u$1x@kl')

    _env_add('SEAFILE_MYSQL_DB_CCNET_DB_NAME', 'ccnet')

    # Prepend the seafile-server/python to PYTHONPATH so we don't need to "make
    # install" each time after editing python files.
    _env_add('PYTHONPATH', join(SeafileServer().projectdir, 'python'))

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

    def branch(self):
        return get_project_branch(self)

    def clone(self):
        if exists(self.name):
            with cd(self.name):
                shell('git fetch origin --tags')
        else:
            shell(
                'git clone --depth=1 --branch {} {}'.
                format(self.branch(), self.url)
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

    def branch(self):
        return 'master'


class CcnetServer(Project):
    def __init__(self):
        super(CcnetServer, self).__init__('ccnet-server')

    def branch(self):
        return '7.1'


class SeafileServer(Project):
    def __init__(self):
        super(SeafileServer, self).__init__('seafile-server')

class Libevhtp(Project):
    def __init__(self):
        super(Libevhtp, self).__init__('libevhtp')

    def branch(self):
        return 'master'

    @chdir
    def compile_and_install(self):
        cmds = [
            'cmake -DEVHTP_DISABLE_SSL=ON -DEVHTP_BUILD_SHARED=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5 .',
            'make',
            'sudo make install',
            'sudo ldconfig',
        ]

        for cmd in cmds:
            shell(cmd)

class Libjwt(Project):
    def __init__(self):
        super(Libjwt, self).__init__('libjwt')

    def branch(self):
        return 'v1.13.1'

    @property
    def url(self):
        return 'https://www.github.com/benmcollins/libjwt.git'

    @chdir
    def compile_and_install(self):
        cmds = [
            'autoreconf -i',
            './configure',
            'sudo make all',
            'sudo make install',
        ]

        for cmd in cmds:
            shell(cmd)

class Libhiredis(Project):
    def __init__(self):
        super(Libhiredis, self).__init__('hiredis')

    def branch(self):
        return 'v1.1.0'

    @property
    def url(self):
        return 'https://github.com/redis/hiredis.git'

    @chdir
    def compile_and_install(self):
        cmds = [
            'sudo make',
            'sudo make install',
        ]

        for cmd in cmds:
            shell(cmd)

def fetch_and_build():
    libsearpc = Libsearpc()
    libjwt = Libjwt()
    libhiredis = Libhiredis()
    libevhtp = Libevhtp()
    ccnet = CcnetServer()
    seafile = SeafileServer()

    libsearpc.clone()
    libjwt.clone()
    libhiredis.clone()
    libevhtp.clone()
    ccnet.clone()

    libsearpc.compile_and_install()
    libjwt.compile_and_install()
    libhiredis.compile_and_install()
    libevhtp.compile_and_install()
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
    if on_github_actions() and not args.test_only:
        fetch_and_build()
    dbs = ('mysql',)
    for db in dbs:
        start_and_test_with_db(db)


def start_and_test_with_db(db):
    if db == 'sqlite3':
        fileservers = ('c_fileserver',)
    else:
        fileservers = ('go_fileserver', 'c_fileserver')
    for fileserver in fileservers:
        shell('rm -rf {}/*'.format(INSTALLDIR))
        info('Setting up seafile server with %s database, use %s', db, fileserver)
        server = ServerCtl(
            TOPDIR,
            SeafileServer().projectdir,
            INSTALLDIR,
            fileserver,
            db=db,
            # Use the newly built seaf-server (to avoid "make install" each time when developping locally)
            seaf_server_bin=join(SeafileServer().projectdir, 'server/seaf-server')
        )
        server.setup()
        with server.run():
            info('Testing with %s database', db)
            with cd(SeafileServer().projectdir):
                shell('py.test', env=server.get_seaserv_envs())


if __name__ == '__main__':
    os.chdir(TOPDIR)
    setup_logging()
    main()
