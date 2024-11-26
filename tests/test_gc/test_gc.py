import pytest
import requests
import os
import time
from subprocess import run
from tests.config import USER, USER2
from seaserv import seafile_api as api
from concurrent.futures import ThreadPoolExecutor
from requests_toolbelt import MultipartEncoder

file_name = 'file.txt'
first_name = 'first.txt'
first_path = os.getcwd() + '/' + first_name
first_content = 'Fist file content.\r\n'

second_name = 'second.txt'
second_content = 'Second file content.\r\n'
second_path = os.getcwd() + '/' + second_name

third_name = 'third.txt'
third_path = os.getcwd() + '/' + third_name
third_content = 'Third file content.\r\n'

def create_test_file():
    fp = open(first_path, 'w')
    fp.write(first_content)
    fp.close()
    fp = open(second_path, 'w')
    fp.write(second_content)
    fp.close()
    fp = open(third_path, 'w')
    fp.write(third_content)
    fp.close()

def del_local_files():
    os.remove(first_path)
    os.remove(second_path)
    os.remove(third_path)

def create_test_dir(repo, dir_name):
    parent_dir = '/'
    api.post_dir(repo.id,parent_dir,dir_name,USER)

def run_gc(repo_id, rm_fs, check):
    cmdStr = 'seafserv-gc --verbose -F /tmp/seafile-tests/conf -d /tmp/seafile-tests/seafile-data %s %s %s'%(rm_fs, check, repo_id)
    cmd=cmdStr.split(' ')
    ret = run (cmd)
    assert ret.returncode == 0

@pytest.mark.parametrize('rm_fs', ['', '--rm-fs'])
def test_gc_full_history(repo, rm_fs):
    create_test_file()

    api.set_repo_valid_since (repo.id, -1)

    create_test_dir(repo,'subdir')
    v_repo_id = api.share_subdir_to_user(repo.id, '/subdir', USER, USER2, 'rw')
    assert v_repo_id is not None
    assert api.post_file(repo.id, first_path, '/subdir', file_name, USER) == 0

    assert api.post_empty_file(repo.id, '/', file_name, USER) == 0
    t_repo = api.get_repo(repo.id)
    assert api.put_file(repo.id, first_path, '/', file_name, USER, t_repo.head_cmmt_id)
    t_repo = api.get_repo(repo.id)
    assert api.put_file(repo.id, second_path, '/', file_name, USER, t_repo.head_cmmt_id)
    t_repo = api.get_repo(repo.id)
    assert api.put_file(repo.id, third_path, '/', file_name, USER, t_repo.head_cmmit_id)
    time.sleep(1)

    api.del_file(repo.id, '/', '[\"'+file_name+'\"]', USER)

    run_gc(repo.id, rm_fs, '')
    run_gc(repo.id, '', '--check')

    del_local_files()

@pytest.mark.parametrize('rm_fs', ['', '--rm-fs'])
def test_gc_no_history(repo, rm_fs):
    create_test_file()

    api.set_repo_valid_since (repo.id, 0)

    create_test_dir(repo,'subdir')
    v_repo_id = api.share_subdir_to_user(repo.id, '/subdir', USER, USER2, 'rw')
    assert v_repo_id is not None
    assert api.post_file(repo.id, first_path, '/subdir', file_name, USER) == 0

    assert api.post_empty_file(repo.id, '/', file_name, USER) == 0
    t_repo = api.get_repo(repo.id)
    assert api.put_file(repo.id, first_path, '/', file_name, USER, t_repo.head_cmmt_id)
    t_repo = api.get_repo(repo.id)
    assert api.put_file(repo.id, second_path, '/', file_name, USER, t_repo.head_cmmt_id)
    t_repo = api.get_repo(repo.id)
    time.sleep(1)
    assert api.put_file(repo.id, third_path, '/', file_name, USER, t_repo.head_cmmt_id)

    time.sleep(1)
    api.del_file(repo.id, '/', '[\"'+file_name+'\"]', USER)

    run_gc(repo.id, rm_fs, '')
    api.set_repo_valid_since (repo.id, 0)
    run_gc(repo.id, '', '--check')
    
    del_local_files()

@pytest.mark.parametrize('rm_fs', ['', '--rm-fs'])
def test_gc_partial_history(repo, rm_fs):
    create_test_file()

    create_test_dir(repo,'subdir')
    v_repo_id = api.share_subdir_to_user(repo.id, '/subdir', USER, USER2, 'rw')
    assert v_repo_id is not None
    assert api.post_file(repo.id, first_path, '/subdir', file_name, USER) == 0

    assert api.post_empty_file(repo.id, '/', file_name, USER) == 0
    t_repo = api.get_repo(repo.id)
    time.sleep(1)
    assert api.put_file(repo.id, first_path, '/', file_name, USER, t_repo.head_cmmt_id)
    t_repo = api.get_repo(repo.id)
    time.sleep(1)
    assert api.put_file(repo.id, second_path, '/', file_name, USER, t_repo.head_cmmt_id)

    t_repo = api.get_repo(repo.id)
    t_commit = api.get_commit(t_repo.id, t_repo.version, t_repo.head_cmmt_id)
    api.set_repo_valid_since (repo.id, t_commit.ctime)

    time.sleep(1)
    assert api.put_file(repo.id, third_path, '/', file_name, USER, t_repo.head_cmmt_id)

    api.del_file(repo.id, '/', '[\"'+file_name+'\"]', USER)

    run_gc(repo.id, rm_fs, '')
    run_gc(repo.id, '', '--check')

    del_local_files()
