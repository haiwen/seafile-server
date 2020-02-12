#coding: UTF-8

import logging
import os
import re
import sys
from contextlib import contextmanager
from os.path import abspath, basename, exists, expanduser, join
from subprocess import PIPE, CalledProcessError, Popen

import requests
import termcolor

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

logger = logging.getLogger(__name__)


def _color(s, color):
    return s if not os.isatty(sys.stdout.fileno()) \
        else termcolor.colored(str(s), color)


def green(s):
    return _color(s, 'green')


def red(s):
    return _color(s, 'red')


def debug(fmt, *a):
    logger.debug(green(fmt), *a)


def info(fmt, *a):
    logger.info(green(fmt), *a)


def warning(fmt, *a):
    logger.warn(red(fmt), *a)


def shell(cmd, inputdata=None, wait=True, **kw):
    info('calling "%s" in %s', cmd, kw.get('cwd', os.getcwd()))
    kw['shell'] = not isinstance(cmd, list)
    kw['stdin'] = PIPE if inputdata else None
    p = Popen(cmd, **kw)
    if inputdata:
        p.communicate(inputdata)
    if wait:
        p.wait()
        if p.returncode:
            raise CalledProcessError(p.returncode, cmd)
    else:
        return p


@contextmanager
def cd(path):
    olddir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(olddir)


def chdir(func):
    def wrapped(self, *w, **kw):
        with cd(self.projectdir):
            return func(self, *w, **kw)

    return wrapped


def setup_logging():
    kw = {
        'format': '[%(asctime)s][%(module)s]: %(message)s',
        'datefmt': '%m/%d/%Y %H:%M:%S',
        'level': logging.DEBUG,
        'stream': sys.stdout,
    }

    logging.basicConfig(**kw)
    logging.getLogger('requests.packages.urllib3.connectionpool'
                      ).setLevel(logging.WARNING)


def mkdirs(*paths):
    for path in paths:
        if not exists(path):
            os.mkdir(path)

def on_github_actions():
    return 'GITHUB_ACTIONS' in os.environ

@contextmanager
def cd(path):
    path = expanduser(path)
    olddir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(olddir)
