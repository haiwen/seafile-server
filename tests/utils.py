import os
import random
import string

from seaserv import ccnet_api, seafile_api


def create_and_get_repo(*a, **kw):
    repo_id = 0
    repo_id = seafile_api.create_repo(*a, **kw)
    assert repo_id != 0

    repo = 0
    repo = seafile_api.get_repo(repo_id)
    assert repo != 0
    assert repo.id == repo_id

    return repo


def randstring(length=12):
    return ''.join(random.choice(string.lowercase) for i in range(length))

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

def create_and_get_org(*a, **kw):
    org_id = ccnet_api.create_org(*a, **kw)
    org = ccnet_api.get_org_by_id(org_id)
    return org
