import pytest
from seaserv import seafile_api as api 
from seaserv import ccnet_api

from tests.config import ADMIN_USER, USER, USER2

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_repo_perm_in_structure (repo, permission):
    id1 = ccnet_api.create_group('group1', USER, parent_group_id=-1)
    id2 = ccnet_api.create_group('group2', USER, parent_group_id = id1)
    assert id1 != -1 and id2 != -1

    # USER2 in child group (id2) has permission to access repo in parent group (id1) #
    assert ccnet_api.group_add_member(id2, USER, USER2) != -1
    assert api.group_share_repo(repo.id, id1, USER, permission) != -1
    assert api.check_permission(repo.id, USER2) == permission

    assert api.group_unshare_repo(repo.id, id1, USER) != -1
    assert api.check_permission(repo.id, USER2) == None

    assert ccnet_api.remove_group(id2) != -1
    assert ccnet_api.remove_group(id1) != -1
