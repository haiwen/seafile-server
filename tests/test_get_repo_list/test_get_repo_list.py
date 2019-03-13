import pytest

from seaserv import seafile_api as api
from tests.config import USER
from tests.utils import randstring

attr_to_assert = ['id', 'name', 'version', 'last_modify', 'size',
                  'last_modifier', 'head_cmmt_id', 'repo_id', 'repo_name',
                  'last_modified', 'encrypted', 'is_virtual', 'origin_repo_id',
                  'origin_repo_name', 'origin_path', 'store_id' ,'share_type',
                  'permission', 'user', 'group_id']

def assert_by_attr_name (repo, repo_to_test, attr):
    if (attr == 'id'):
        assert getattr(repo_to_test, attr) == repo.id
    elif (attr == 'name'):
        assert getattr(repo_to_test, attr) == repo.name
    elif (attr == 'size'):
        assert getattr(repo_to_test, attr) == repo.size
    elif (attr == 'last_modifier'):
        assert getattr(repo_to_test, attr) == repo.last_modifier
    elif (attr == 'head_cmmt_id'):
        assert getattr(repo_to_test, attr) == repo.head_cmmt_id
    elif (attr == 'repo_id'):
        assert getattr(repo_to_test, attr) == repo.id
    elif (attr == 'repo_name'):
        assert getattr(repo_to_test, attr) == repo.name
    elif (attr == 'last_modified'):
        assert getattr(repo_to_test, attr) == repo.last_modified
    elif (attr == 'encrypted'):
        assert getattr(repo_to_test, attr) == repo.encrypted
    elif (attr == 'is_virtual'):
        assert getattr(repo_to_test, attr) == repo.is_virtual
    elif (attr == 'origin_repo_id'):
        assert getattr(repo_to_test, attr) == repo.origin_repo_id
    elif (attr == 'origin_repo_name'):
        assert getattr(repo_to_test, attr) != None
    elif (attr == 'origin_path'):
        assert getattr(repo_to_test, attr) == repo.origin_path
    elif (attr == 'store_id'):
        assert getattr(repo_to_test, attr) == repo.store_id
    elif (attr == 'share_type'):
        assert getattr(repo_to_test, attr) != None
    elif (attr == 'permission'):
        assert getattr(repo_to_test, attr) == 'rw'
    elif (attr == 'group_id'):
        assert getattr(repo_to_test,attr) != 0

def assert_public_repos_attr(repo, repo_to_test):
    for attr in attr_to_assert:
       assert hasattr(repo_to_test, attr) == True

       assert hasattr(repo_to_test, 'is_virtual')
       is_virtual = getattr(repo_to_test, 'is_virtual')

       if (is_virtual == False):
           if (attr == 'origin_repo_id' or
               attr == 'origin_path'):
               continue

       if (attr == 'origin_repo_name'):
           continue

       if (attr == 'group_id'):
           continue

       assert_by_attr_name(repo, repo_to_test, attr)

def assert_group_repos_attr(repo, repo_to_test):
    for attr in attr_to_assert:
        assert hasattr(repo_to_test, attr) == True

        assert hasattr(repo_to_test, 'is_virtual')
        is_virtual = getattr(repo_to_test, 'is_virtual')

        if (is_virtual == False):
            if (attr == 'origin_repo_id' or
                attr == 'origin_repo_name' or
                attr == 'origin_path'):
                continue

        assert_by_attr_name(repo, repo_to_test, attr)

def test_get_group_repos(repo, group):
    repo = api.get_repo(repo.id)
    api.group_share_repo(repo.id, group.id, USER, 'rw')
    repos = api.get_repos_by_group(group.id)
    assert_group_repos_attr(repo, repos[0])

    repos = api.get_group_repos_by_owner(USER)
    assert_group_repos_attr(repo, repos[0])

    v_repo_id = api.share_subdir_to_group(repo.id, '/dir1', USER, group.id, 'rw')
    v_repo = api.get_repo(v_repo_id)
    v_repo_to_test = api.get_group_shared_repo_by_path(repo.id, '/dir1', group.id)
    assert_group_repos_attr(v_repo, v_repo_to_test)
    api.unshare_subdir_for_group(repo.id, '/dir1', USER, group.id)

    repos = api.get_group_repos_by_user(USER)
    assert_group_repos_attr(repo, repos[0])

    assert api.group_unshare_repo(repo.id, group.id, USER) == 0

def test_get_inner_pub_repos(repo):
    repo = api.get_repo(repo.id)
    api.add_inner_pub_repo(repo.id, 'rw')
    repos = api.get_inner_pub_repo_list()
    assert_public_repos_attr(repo, repos[0])

    repos = api.list_inner_pub_repos_by_owner(USER)
    assert_public_repos_attr(repo, repos[0])

    assert api.remove_inner_pub_repo(repo.id) == 0
