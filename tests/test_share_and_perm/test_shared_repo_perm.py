import pytest
import time
from seaserv import seafile_api as api
from seaserv import ccnet_api

from tests.config import ADMIN_USER, USER, USER2
from tests.utils import assert_repo_with_permission


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo_to_user(repo, permission):
    assert api.check_permission(repo.id, USER) == 'rw'
    assert api.check_permission(repo.id, USER2) is None

    assert api.repo_has_been_shared(repo.id) == False

    api.share_repo(repo.id, USER, USER2, permission)
    assert api.check_permission(repo.id, USER2) == permission

    assert api.repo_has_been_shared(repo.id)

    repos = api.get_share_in_repo_list(USER2, 0, 1)
    assert_repo_with_permission(repo, repos, permission)

    repos = api.get_share_out_repo_list(USER, 0, 1)
    assert_repo_with_permission(repo, repos, permission)

    users = api.list_repo_shared_to(USER, repo.id)
    assert len (users) == 1
    assert users[0].repo_id == repo.id
    assert users[0].user == USER2
    assert users[0].perm == permission

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

    group_ids = api.get_shared_group_ids_by_repo(repo.id)
    assert group_ids[0] == str(group.id)

    group_list = api.list_repo_shared_group_by_user(USER, repo.id)
    assert len(group_list) == 1
    group_list = api.list_repo_shared_group_by_user(USER2, repo.id)
    assert len(group_list) == 0

    repo_get = api.get_group_shared_repo_by_path (repo.id, None, group.id)
    assert repo_get and repo_get.repo_id == repo.id

    ccnet_api.group_add_member(group.id, USER, USER2)
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 1
    group = group_list[0]
    assert group.id == group.id

    repos2 = api.get_repos_by_group(group.id)
    assert_repo_with_permission(repo, repos2, permission)

    assert api.check_permission(repo.id, USER2) == permission

    repos = api.get_group_repos_by_user (USER)
    assert len(repos) == 1

    repoids = api.get_group_repoids(group.id)
    assert len(repoids) == 1

    repos = api.get_group_repos_by_owner(USER)
    assert len(repos) == 1
    api.remove_group_repos_by_owner(group.id, USER)
    repos = api.get_group_repos_by_owner(USER)
    assert len(repos) == 0

    api.set_group_repo(repo.id, group.id, USER, permission)
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 1
    api.remove_group_repos(group.id)
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 0

    api.group_unshare_repo(repo.id, group.id, USER)
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 0

    assert api.check_permission(repo.id, USER2) is None

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_dir_to_user(repo, permission):
    v_repo_id_1 =  api.share_subdir_to_user(repo.id, '/dir1', USER, USER2, permission)
    v_repo_id_2 =  api.share_subdir_to_user(repo.id, '/dir2', USER, USER2, permission)
    assert api.check_permission(v_repo_id_1, USER2) == permission
    assert api.check_permission(v_repo_id_2, USER2) == permission

    vir_repo_2 = api.get_shared_repo_by_path(repo.id, '/dir2', USER2)
    assert vir_repo_2.permission == permission

    users = api.get_shared_users_for_subdir(repo.id, '/dir1', USER)
    assert len(users) == 1 and users[0].user == USER2

    assert api.del_file(repo.id, '/', '[\"dir1\"]', USER) == 0
    assert api.unshare_subdir_for_user(repo.id, '/dir2', USER, USER2) == 0

    time.sleep(2.5)

    assert api.get_shared_repo_by_path(repo.id, '/dir1', USER2) is None
    assert api.get_shared_repo_by_path(repo.id, '/dir2', USER2) is None

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_dir_to_group(repo, group, permission):
    assert ccnet_api.group_add_member(group.id, USER, USER2) == 0
    v_repo_id_1 = api.share_subdir_to_group(repo.id, '/dir1', USER, group.id, permission)
    v_repo_id_2 = api.share_subdir_to_group(repo.id, '/dir2', USER, group.id, permission)

    assert api.check_permission(v_repo_id_1, USER2) == permission
    assert api.check_permission(v_repo_id_2, USER2) == permission

    repo_get = api.get_group_shared_repo_by_path (repo.id, '/dir1', group.id)
    assert repo_get and repo_get.repo_id == v_repo_id_1

    users = api.get_shared_groups_for_subdir(repo.id, '/dir1', USER)
    assert len(users) == 1

    assert api.del_file(repo.id, '/', '[\"dir1\"]', USER) == 0
    assert api.unshare_subdir_for_group(repo.id, '/dir2', USER, group.id) == 0

    time.sleep(2.5)

    assert api.check_permission(v_repo_id_1, USER2) is None
    assert api.check_permission(v_repo_id_2, USER2) is None

@pytest.mark.parametrize('permission_to_share, permission_to_set', [('r', 'rw'), ('rw', 'r')])
def test_set_share_permission(repo,  permission_to_share, permission_to_set):
    assert api.check_permission(repo.id, USER2) == None

    api.share_repo(repo.id, USER, USER2, permission_to_share)
    assert api.check_permission(repo.id, USER2) == permission_to_share

    api.set_share_permission(repo.id, USER, USER2, permission_to_set)
    assert api.check_permission(repo.id, USER2) == permission_to_set

    api.remove_share(repo.id, USER, USER2)

@pytest.mark.parametrize('permission_to_share, permission_to_set', [('r', 'rw'), ('rw', 'r')])
def set_group_repo_permission(repo,  group, permission_to_share, permission_to_set):
    ccnet_api.group_add_member(group.id, USER, USER2)
    assert api.check_permission(repo.id, USER2) == None

    api.set_group_repo(repo.id, group.id, USER, permission_to_share)
    assert api.check_permission(repo.id, USER2) == permission_to_share

    api.set_group_repo_permission(group.id, repo.id, permission_to_set)
    assert api.check_permission(repo.id, USER2) == permission_to_set

    api.group_unshare_repo(repo.id, group.id, USER)

@pytest.mark.parametrize('permission_to_share, permission_to_update', [('r', 'rw'), ('rw', 'r')])
def test_update_share_subdir_perm_for_user(repo, permission_to_share, permission_to_update):
    v_repo_id =  api.share_subdir_to_user(repo.id, '/dir1', USER, USER2, permission_to_share)
    assert api.check_permission(v_repo_id, USER2) == permission_to_share

    api.update_share_subdir_perm_for_user(repo.id, '/dir1', USER, USER2, permission_to_update)
    assert api.check_permission(v_repo_id, USER2) == permission_to_update

    api.unshare_subdir_for_user(repo.id, '/dir1', USER, USER2) == 0

@pytest.mark.parametrize('permission_to_share, permission_to_update', [('r', 'rw'), ('rw', 'r')])
def test_update_share_subdir_perm_for_group(repo, group, permission_to_update, permission_to_share):
    ccnet_api.group_add_member(group.id, USER, USER2)
    v_repo_id = api.share_subdir_to_group(repo.id, '/dir1', USER, group.id, permission_to_share)
    assert api.check_permission(v_repo_id, USER2) == permission_to_share

    api.update_share_subdir_perm_for_group(repo.id, '/dir1', USER, group.id, permission_to_update)
    assert api.check_permission(v_repo_id, USER2) == permission_to_update

    api.unshare_subdir_for_group(repo.id, '/dir1', USER, group.id)

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_get_shared_users_by_repo(repo, group, permission):
    ccnet_api.group_add_member(group.id, USER, USER2)
    t_users = api.get_shared_users_by_repo(repo.id)
    assert len(t_users) == 0

    api.share_repo(repo.id, USER, USER2, permission)
    api.set_group_repo(repo.id, group.id, ADMIN_USER, permission)
    t_users = api.get_shared_users_by_repo(repo.id)
    assert len(t_users) == 2

    api.remove_share(repo.id, USER, USER2)
    api.group_unshare_repo(repo.id, group.id, USER)

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_subdir_permission_in_virtual_repo(repo, group, permission):
    api.post_dir(repo.id, '/dir1', 'subdir1', USER)
    api.post_dir(repo.id, '/dir2', 'subdir2', USER)

    v_repo_id_1 = api.share_subdir_to_user(repo.id, '/dir1', USER, USER2, permission)
    v_subdir_repo_id_1 = api.create_virtual_repo(v_repo_id_1, '/subdir1', 'subdir1', 'test_desc', USER, passwd='')
    assert api.check_permission(v_subdir_repo_id_1, USER2) == permission

    assert ccnet_api.group_add_member(group.id, USER, USER2) == 0
    v_repo_id_2 = api.share_subdir_to_group(repo.id, '/dir2', USER, group.id, permission)
    v_subdir_repo_id_2 = api.create_virtual_repo(v_repo_id_2, '/subdir2', 'subdir2', 'test_desc', USER, passwd='')
    assert api.check_permission(v_subdir_repo_id_2, USER2) == permission

    assert api.unshare_subdir_for_user(repo.id, '/dir1', USER, USER2) == 0
    assert api.unshare_subdir_for_group(repo.id, '/dir2', USER, group.id) == 0
