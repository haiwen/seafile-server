import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api

from tests.config import ADMIN_USER, USER, USER2
from tests.utils import assert_repo_with_permission


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo_to_user(repo, permission):
    assert api.check_permission(repo.id, USER) == 'rw'
    assert api.check_permission(repo.id, USER2) is None

    api.share_repo(repo.id, USER, USER2, permission)
    assert api.check_permission(repo.id, USER2) == permission

    repos = api.get_share_in_repo_list(USER2, 0, 1)
    assert_repo_with_permission(repo, repos, permission)

    api.remove_share(repo.id, USER, USER2)
    assert api.check_permission(repo.id, USER2) is None


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo_to_group(repo, group, permission):
    assert api.check_permission(repo.id, USER) == 'rw'
    assert api.check_permission(repo.id, USER2) is None

    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 0

    group_list = ccnet_api.get_groups(USER)
    assert len(group_list) == 1
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 0

    api.group_share_repo(repo.id, group.id, USER, permission)
    repos = api.get_repos_by_group(group.id)
    assert_repo_with_permission(repo, repos, permission)

    ccnet_api.group_add_member(group.id, USER, USER2)
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 1
    group = group_list[0]
    assert group.id == group.id

    repos2 = api.get_repos_by_group(group.id)
    assert_repo_with_permission(repo, repos2, permission)

    assert api.check_permission(repo.id, USER2) == permission

    api.group_unshare_repo(repo.id, group.id, USER);
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 0

    assert api.check_permission(repo.id, USER2) is None
