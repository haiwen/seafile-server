import pytest
import os
import time
from tests.config import USER
from seaserv import seafile_api as api

file_name = 'test.txt'
file_content = 'test file content'
file_path = os.getcwd() + '/' + file_name
dir_name = "test_dir"

def create_the_file ():
    with open(file_path, 'w') as fp:
        fp.write(file_content)

def test_file_operation():
    t_repo_version = 1
    t_repo_id1 = api.create_repo('test_file_operation1', '', USER, passwd = None)

    create_the_file()

    assert api.post_file(t_repo_id1, file_path, '/', file_name, USER) == 0
    assert api.post_dir(t_repo_id1, '/', dir_name, USER) == 0

    #test search files
    file_list = api.search_files (t_repo_id1, "test")
    assert len(file_list) == 2
    assert file_list[0].path == "/test.txt"
    assert file_list[1].path == "/test_dir"

    file_list = api.search_files (t_repo_id1, "dir")
    assert len(file_list) == 1
    assert file_list[0].path == "/test_dir"

    api.remove_repo(t_repo_id1)
