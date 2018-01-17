import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api

from tests.config import ADMIN_USER, USER, USER2


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo_to_user(repo, permission):
    assert api.check_permission(repo.id, USER2) is None

    api.share_repo(repo.id, USER, USER2, permission)
    assert api.check_permission(repo.id, USER2) == permission

    repos = api.get_share_in_repo_list(USER2, 0, 1)
    assert len(repos) == 1
    r = repos[0]
    assert r.id == repo.id
    assert r.permission == permission


    repos = api.get_share_out_repo_list(USER, 0, 1)
    assert len(repos) == 1
    r = repos[0]
    assert r.id == repo.id
    assert r.permission == permission

    api.remove_share(repo.id, USER, USER2)
    assert api.check_permission(repo.id, USER2) is None


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo_to_group(repo, group, permission):
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 0
    
    api.group_share_repo(repo.id, group.id, USER, permission)
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 1
    r = repos[0]
    assert r.id == repo.id
    assert r.permission == permission

    ccnet_api.group_add_member(group.id, USER, USER2)
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 1
    r = group_list[0]
    assert r.id == group.id

    repos2 = api.get_repos_by_group(r.id)
    assert len(repos2) == 1
    r = repos2[0]
    assert r.id == repo.id
    assert r.permission == permission

    api.group_unshare_repo(repo.id, group.id, USER);
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 0
