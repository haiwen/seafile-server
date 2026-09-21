import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api

from tests.config import USER, USER2

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_folder_to_user(repo, permission):
    parent_dir = '/'
    test_fold = 'fold_test'
    path = parent_dir + test_fold
    api.post_dir(repo.id, parent_dir, test_fold, USER)

    api.share_subdir_to_user(repo.id, path, USER, USER2, permission)
    api.check_permission_by_path(repo.id, path, USER) == 'rw'

    repos = api.get_share_in_repo_list(USER2, 0, 1)

    if isinstance(repos, list):
        assert len(repos) == 1
        dir_repo = repos[0]
    assert dir_repo.name == test_fold
    assert dir_repo.permission == permission
    assert api.get_repo_owner(dir_repo.id) == USER

    subdir = 'sub_test'
    path_sub = path + subdir
    api.post_dir(repo.id, path, subdir, USER)

    assert api.check_permission_by_path(repo.id, path_sub, USER) == 'rw'
    assert api.check_permission_by_path(dir_repo.id, path_sub, USER2) == permission

    api.unshare_subdir_for_user(repo.id, path, USER, USER2)
    folds = api.get_share_in_repo_list(USER2, 0, 1)
    assert len(folds) == 0

    api.del_file(repo.id, parent_dir, test_fold, USER)
    api.check_permission_by_path(repo.id, path, USER) is None

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_folder_to_group(repo, group, permission):
    parent_dir = '/'
    test_fold = 'fold2'
    path = parent_dir + test_fold
    api.post_dir(repo.id, parent_dir, test_fold, USER)
    api.check_permission_by_path(repo.id, path, USER) == 'rw'

    ccnet_api.group_add_member(group.id, USER, USER2)
    api.share_subdir_to_group(repo.id, path, USER, group.id, permission, passwd='')
    group_list = ccnet_api.get_groups(USER2)
    if isinstance(group_list, list):
        assert len(group_list) == 1
        s_group = group_list[0]
    assert group.id == s_group.id

    repos_list = api.get_repos_by_group(s_group.id)
    assert len(repos_list) == 1
    g_repo = repos_list[0]

    assert g_repo.name == test_fold
    assert api.check_permission_by_path(g_repo.id, path, USER2) == permission
    assert api.get_repo_owner(g_repo.id) == USER

    api.unshare_subdir_for_group(repo.id, path, USER, group.id)
    assert api.check_permission_by_path(g_repo.id, path, USER2) is None

    api.del_file(repo.id, parent_dir, test_fold, USER)
    api.check_permission_by_path(repo.id, path, USER) is None
