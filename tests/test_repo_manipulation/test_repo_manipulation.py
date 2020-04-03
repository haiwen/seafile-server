import pytest
from tests.config import USER, USER2
from seaserv import seafile_api as api

def get_repo_list_order_by(t_start, t_limit, order_by):
    t_repo_list = api.get_repo_list(t_start, t_limit, order_by)
    assert t_repo_list and len(t_repo_list)
    if order_by == "size":
        assert t_repo_list[0].size >= t_repo_list[1].size
    if order_by == "file_count":
        assert t_repo_list[0].file_count >= t_repo_list[1].file_count

def test_repo_manipulation():

    #test get_system_default_repo_id
    t_default_repo_id = api.get_system_default_repo_id()
    assert t_default_repo_id

    #test create_repo
    t_repo_id = api.create_repo('test_repo_manipulation', '', USER, passwd=None)
    assert t_repo_id

    #test counts_repo
    t_repo_count = 0
    t_repo_count = api.count_repos()
    assert t_repo_count != 0

    #test get_repo ,edit_repo
    t_new_name = 'n_name'
    t_new_desc = 'n_desc'
    t_repo_version = 1
    t_repo = api.get_repo(t_repo_id)
    assert t_repo

    api.edit_repo(t_repo_id, t_new_name, t_new_desc, USER)
    t_repo = api.get_repo(t_repo_id)
    assert t_repo.name == t_new_name and t_repo.desc == t_new_desc

    #test revert_repo and get_commit
    t_commit_id_before_changing = t_repo.head_cmmt_id

    api.post_dir(t_repo_id, '/', 'dir1', USER)
    t_repo = api.get_repo(t_repo_id)

    api.revert_repo(t_repo_id, t_commit_id_before_changing, USER)

    t_repo = api.get_repo(t_repo_id)
    t_commit_id_after_revert = t_repo.head_cmmt_id

    t_commit_before_changing = api.get_commit(t_repo_id, t_repo_version, t_commit_id_before_changing)
    t_commit_after_revert = api.get_commit(t_repo_id, t_repo_version, t_commit_id_after_revert)
    assert t_commit_before_changing.root_id == t_commit_after_revert.root_id

    #test is_repo_owner
    assert api.is_repo_owner(USER, t_repo_id)
    assert api.is_repo_owner(USER2, t_repo_id) == 0

    #test get_repo_owner
    owner_get = api.get_repo_owner(t_repo_id)
    assert owner_get == USER

    #test set_repo_owner
    api.set_repo_owner(t_repo_id, USER2)
    assert api.is_repo_owner(USER2, t_repo_id)

    #test create_enc_repo
    t_enc_repo_id = '826d1b7b-f110-46f2-8d5e-7b5ac3e11f4d'
    t_enc_version = 2
    t_passwd = '123'
    magic_and_random_key = api.generate_magic_and_random_key (t_enc_version, t_enc_repo_id, t_passwd)
    t_magic = magic_and_random_key.magic
    t_random_key = magic_and_random_key.random_key
    t_enc_repo_id = api.create_enc_repo (t_enc_repo_id, 'test_encrypted_repo', '', USER, t_magic, t_random_key, None, t_enc_version)
    assert t_enc_repo_id == '826d1b7b-f110-46f2-8d5e-7b5ac3e11f4d'

    #test get_repos_by_id_prefix
    t_id_prefix = '826d1b7b'
    t_repo_list = api.get_repos_by_id_prefix(t_id_prefix, False, -1, -1)
    assert t_repo_list[0].id == '826d1b7b-f110-46f2-8d5e-7b5ac3e11f4d'

    #test get_repo_list
    #test order by None
    order_by = None
    get_repo_list_order_by(-1 ,-1, order_by)

    #test order by size
    order_by = "size"
    get_repo_list_order_by(-1 ,-1, order_by)

    #test order by file_count
    order_by = "file_count"
    get_repo_list_order_by(-1 ,-1, order_by)

    t_start = 1;
    t_limit = 1;
    t_repo_list = api.get_repo_list(t_start, t_limit, None)
    assert t_repo_list and len(t_repo_list) == 1

    #test get_owned_repo_list
    t_repo_list = api.get_owned_repo_list(USER2)
    assert t_repo_list and len(t_repo_list)

    #test get_commit_list
    t_offset = 0;
    t_limit = 0;
    t_commit_list = api.get_commit_list(t_repo_id, t_offset, t_limit)
    assert t_commit_list and len(t_commit_list) == 4

    t_offset = 1;
    t_limit = 1;
    t_commit_list = api.get_commit_list(t_repo_id, t_offset, t_limit)
    assert t_commit_list and len(t_commit_list) == 1

    #test search_repos_by_name
    t_repo_list = api.search_repos_by_name (t_repo.name)
    assert len (t_repo_list) == 1 and t_repo_list[0].id == t_repo_id
    t_repo_list = api.search_repos_by_name (t_repo.name.upper())
    assert len (t_repo_list) == 1 and t_repo_list[0].id == t_repo_id
    t_repo_list = api.search_repos_by_name (t_repo.name.lower())
    assert len (t_repo_list) == 1 and t_repo_list[0].id == t_repo_id

    #test remove_repo
    api.remove_repo(t_repo_id)
    t_repo = api.get_repo(t_repo_id)
    assert t_repo == None
