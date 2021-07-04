import pytest

from seaserv import seafile_api as api
from tests.config import USER
from tests.utils import randstring

attr_to_assert = ['id', 'name', 'version', 'last_modify', 'size',
                  'last_modifier', 'head_cmmt_id', 'repo_id', 'repo_name',
                  'last_modified', 'encrypted', 'is_virtual', 'origin_repo_id',
                  'origin_repo_name', 'origin_path', 'store_id' ,'share_type',
                  'permission', 'user', 'group_id', 'enc_version', 'salt']

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
        assert getattr(repo_to_test, attr) != 0
    elif (attr == 'enc_version'):
        assert getattr(repo_to_test, attr) == repo.enc_version
    elif (attr == 'salt'):
        enc_version = getattr(repo_to_test, 'enc_version')
        if (enc_version >= 3):
           assert getattr(repo_to_test, attr)
        else:
           assert getattr(repo_to_test, attr) == None
        assert getattr(repo_to_test, attr) == repo.salt

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

repo_name = 'test_get_repo_list'
password = 'test_get_repo_list'
@pytest.mark.parametrize('is_encrypted, enc_version' ,[(False, 0), (True, 2), (True, 3)])
def test_get_group_repos(group, is_encrypted, enc_version):
    if is_encrypted:
        repo_id = api.create_repo(repo_name, '', USER, password, enc_version)
    else:
        repo_id = api.create_repo(repo_name, '', USER)
    api.post_dir(repo_id, '/', 'dir1', USER)

    repo = api.get_repo(repo_id)
    api.group_share_repo(repo_id, group.id, USER, 'rw')
    repos = api.get_repos_by_group(group.id)
    assert_group_repos_attr(repo, repos[0])

    repos = api.get_group_repos_by_owner(USER)
    assert_group_repos_attr(repo, repos[0])

    if is_encrypted:
        v_repo_id = api.share_subdir_to_group(repo_id, '/dir1', USER, group.id, 'rw', password)
    else:
        v_repo_id = api.share_subdir_to_group(repo_id, '/dir1', USER, group.id, 'rw')

    v_repo = api.get_repo(v_repo_id)
    v_repo_to_test = api.get_group_shared_repo_by_path(repo_id, '/dir1', group.id)
    assert_group_repos_attr(v_repo, v_repo_to_test)
    api.unshare_subdir_for_group(repo_id, '/dir1', USER, group.id)

    repos = api.get_group_repos_by_user(USER)
    assert_group_repos_attr(repo, repos[0])

    assert api.group_unshare_repo(repo_id, group.id, USER) == 0
    api.remove_repo(repo_id)

@pytest.mark.parametrize('is_encrypted, enc_version' ,[(False, 0), (True, 2), (True, 3)])
def test_get_inner_pub_repos(is_encrypted, enc_version):
    if is_encrypted:
        repo_id = api.create_repo(repo_name, '', USER, password, enc_version)
    else:
        repo_id = api.create_repo(repo_name, '', USER)

    repo = api.get_repo(repo_id)
    api.add_inner_pub_repo(repo_id, 'rw')
    repos = api.get_inner_pub_repo_list()
    assert_public_repos_attr(repo, repos[0])

    repos = api.list_inner_pub_repos_by_owner(USER)
    assert_public_repos_attr(repo, repos[0])

    assert api.remove_inner_pub_repo(repo_id) == 0
    api.remove_repo(repo_id)
