import os
import random
import string

from seaserv import ccnet_api, seafile_api


def create_and_get_repo(*a, **kw):
    repo_id = seafile_api.create_repo(*a, **kw)
    repo = seafile_api.get_repo(repo_id)
    return repo


def randstring(length=12):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(length))

def create_and_get_group(*a, **kw):
    group_id = ccnet_api.create_group(*a, **kw)
    group = ccnet_api.get_group(group_id)
    return group

def assert_repo_with_permission(r1, r2, permission):
    if isinstance(r2, list):
        assert len(r2) == 1
        r2 = r2[0]
    assert r2.id == r1.id
    assert r2.permission == permission
