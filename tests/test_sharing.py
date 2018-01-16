import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api

from tests.config import ADMIN_USER, USER, USER2


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo(repo, permission):
    assert api.check_permission(repo.id, USER2) is None

    api.share_repo(repo.id, USER, USER2, permission)
    assert api.check_permission(repo.id, USER2) == permission

    repos = api.get_share_in_repo_list(USER2, 0, 1)
    assert len(repos) == 1
    r = repos[0]
    assert r.id == repo.id
    assert r.permission == permission

    api.remove_share(repo.id, USER, USER2)
    assert api.check_permission(repo.id, USER2) is None
