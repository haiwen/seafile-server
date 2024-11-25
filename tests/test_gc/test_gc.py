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

large_file_name = 'large.txt'
large_file_size = 2*1024*1024*1024
large_file_path = os.getcwd() + '/' + large_file_name

def create_large_file():
    fp = open(large_file_path, 'wb')
    fp.write(os.urandom(large_file_size))
    fp.close()

def del_large_file():
    os.remove(large_file_path)

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

def upload_file_in_chunks(url, file_path, chunk_size=8*1024*1024):
    status = 200
    rsp = ''
    with open(file_path, 'rb') as file:
        chunk_num = 0
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break

            start = chunk_num * chunk_size
            end = min((chunk_num + 1) * chunk_size - 1, large_file_size - 1)

            m = MultipartEncoder(
                    fields={
                            'parent_dir': '/',
                            'file': (os.path.basename(file_path), chunk, 'application/octet-stream')
                })

            headers = {
                'Content-Range': f"bytes {start}-{end}/{large_file_size}",
                'Content-Type': m.content_type,
                'Content-Disposition': 'attachment; filename="large.txt"'
            }

            response = requests.post(url, data = m, headers=headers)
            status = response.status_code
            rsp = response.text
            if status != 200:
                break

            chunk_num += 1
        return status, rsp

@pytest.mark.parametrize('rm_fs', ['', '--rm-fs'])
def test_gc_on_upload(repo, rm_fs):
    create_large_file()
    api.set_repo_valid_since (repo.id, 0)

    obj_id = '{"parent_dir":"/"}'
    token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, False)
    upload_url_base = 'http://127.0.0.1:8082/upload-aj/'+ token

    status_code = 200
    executor = ThreadPoolExecutor()
    future = executor.submit(upload_file_in_chunks, upload_url_base, large_file_path)

    while True:
        offset = api.get_upload_tmp_file_offset(repo.id, "/" + large_file_name)
        if offset == large_file_size:
            break
        time.sleep (0.5)
    time.sleep (1)
    run_gc(repo.id, rm_fs, '')

    while not future.done():
        time.sleep(0.5)

    status_code = future.result()[0]
    assert status_code == 500

    api.set_repo_valid_since (repo.id, 0)
    run_gc(repo.id, '', '--check')

    del_large_file ()
