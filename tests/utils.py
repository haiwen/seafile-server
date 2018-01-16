import os
import random
import string

from seaserv import ccnet_api, seafile_api


def create_and_get_repo(*a, **kw):
    repo_id = seafile_api.create_repo(*a, **kw)
    repo = seafile_api.get_repo(repo_id)
    return repo


def randstring(length=12):
    return ''.join(random.choice(string.lowercase) for i in range(length))
