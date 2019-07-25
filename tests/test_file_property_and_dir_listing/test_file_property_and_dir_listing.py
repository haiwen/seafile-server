import pytest
import os
import time
from tests.config import USER
from seaserv import seafile_api as api

file_name = 'test.txt'
dir_name = 'test_dir'
file_content = 'test file content'
file_path = os.getcwd() + '/' + file_name

def create_the_file ():
    fp = open(file_path, 'w')
    fp.write(file_content)
    fp.close()

def test_file_property_and_dir_listing ():

    t_repo_version = 1
    t_repo_id = api.create_repo('test_file_property_and_dir_listing', '', USER, passwd=None)

    create_the_file()

    api.post_file(t_repo_id, file_path, '/', file_name, USER)
    api.post_dir(t_repo_id, '/', dir_name, USER)
    api.post_file(t_repo_id, file_path, '/' + dir_name, file_name, USER)

    #test is_valid_filename
    t_valid_file_name = 'valid_filename'
    t_invalid_file_name = '/invalid_filename'
    assert api.is_valid_filename(t_repo_id, t_valid_file_name)
    assert api.is_valid_filename(t_repo_id, t_invalid_file_name) == 0

    #test get_file_id_by_path
    t_file_id = api.get_file_id_by_path(t_repo_id, '/test.txt')
    assert t_file_id

    #test get_dir_id_by_path
    t_dir_id = api.get_dir_id_by_path(t_repo_id, '/test_dir')
    assert t_dir_id

    #test get_file_size
    t_file_size = len(file_content)
    assert t_file_size == api.get_file_size(t_repo_id, t_repo_version, t_file_id)

    #test get_dir_size
    t_dir_size = len(file_content)
    assert t_dir_size == api.get_dir_size(t_repo_id, t_repo_version, t_dir_id)

    #test get_file_count_info_by_path
    t_file_count_info = api.get_file_count_info_by_path(t_repo_id , '/')
    assert t_file_count_info.file_count == 2
    assert t_file_count_info.dir_count == 1
    assert t_file_count_info.size == t_file_size + t_dir_size

    #test get_file_id_by_commit_and_path
    t_file_id_tmp = t_file_id
    t_repo = api.get_repo(t_repo_id)
    assert t_repo
    t_commit_id = t_repo.head_cmmt_id
    t_file_id = api.get_file_id_by_commit_and_path(t_repo_id,
                                                   t_commit_id,
                                                   '/test.txt')

    assert t_file_id == t_file_id_tmp

    #test get_dirent_by_path
    std_file_mode = 0o100000 | 0o644
    t_dirent_obj = api.get_dirent_by_path(t_repo_id, '/test.txt')
    assert t_dirent_obj
    assert t_dirent_obj.obj_id == t_file_id
    assert t_dirent_obj.obj_name == 'test.txt'
    assert t_dirent_obj.mode == std_file_mode
    assert t_dirent_obj.version == t_repo_version
    assert t_dirent_obj.size == t_file_size
    assert t_dirent_obj.modifier == USER

    #test list_file_by_file_id
    t_block_list =  api.list_file_by_file_id(t_repo_id, t_file_id)
    assert t_block_list

    #test list_blocks_by_file_id
    t_block_list = api.list_blocks_by_file_id(t_repo_id, t_file_id)
    assert t_block_list

    #test list_dir_by_dir_id
    t_dir_list = api.list_dir_by_dir_id(t_repo_id, t_dir_id)
    assert len(t_dir_list) == 1

    #test list_dir_by_path
    t_dir_list = api.list_dir_by_path(t_repo_id, '/test_dir')
    assert len(t_dir_list) == 1

    #test get_dir_id_by_commit_and_path
    t_dir_id = api.get_dir_id_by_commit_and_path(t_repo_id, t_commit_id, '/test_dir')
    assert t_dir_id

    #test list_dir_by_commit_and_path
    t_dir_list = api.list_dir_by_commit_and_path(t_repo_id, t_commit_id, '/test_dir')
    assert len(t_dir_list) == 1

    #test list_dir_with_perm
    t_dir_list = api.list_dir_with_perm(t_repo_id, '/test_dir', t_dir_id, USER)
    assert len(t_dir_list) == 1

    #test mkdir_with_parent
    api.mkdir_with_parents (t_repo_id, '/test_dir', 'test_subdir', USER)
    t_dir_id = api.get_dir_id_by_path(t_repo_id, '/test_dir/test_subdir')
    assert t_dir_id

    #test get_total_storage
    t_total_size = api.get_total_storage()
    t_repo_size = api.get_repo_size(t_repo_id)
    assert t_total_size == t_repo_size

    #get_total_file_number
    time.sleep(1)
    assert api.get_total_file_number() == 2

    api.remove_repo(t_repo_id)
