import pytest
import requests
import os
import time
import json
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

large_file_name = 'large.txt'
large_file_size = 1024 * 1024 * 1024
large_file_path = os.getcwd() + '/' + large_file_name

upload_timeout = 300

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

def create_gc_test_file():
    with open(large_file_path, 'wb') as fp:
        for _ in range(large_file_size // (1024 * 1024)):
            fp.write(os.urandom(1024 * 1024))

def del_gc_test_file():
    if os.path.exists(large_file_path):
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

def upload_gc_test_file(url):
    with open(large_file_path, 'rb') as fp:
        m = MultipartEncoder(
                fields={
                        'parent_dir': '/',
                        'file': (large_file_name, fp, 'application/octet-stream')
                })
        headers = {
                'Content-Type': m.content_type,
                'Content-Range': 'bytes 0-{}/{}'.format(
                    large_file_size - 1, large_file_size),
                'Content-Disposition': 'attachment; filename="{}"'.format(large_file_name)
        }
        return requests.post(url, data=m, headers=headers, timeout=upload_timeout)

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

def wait_for_virtual_repo_merge(origin_repo_id, virtual_repo_id, path):
    for _ in range(10):
        origin_dir_id = api.get_dir_id_by_path(origin_repo_id, path)
        virtual_dir_id = api.get_dir_id_by_path(virtual_repo_id, '/')
        if origin_dir_id == virtual_dir_id:
            return
        time.sleep(0.5)
    assert False, 'virtual repo merge did not finish'

@pytest.mark.parametrize('rm_fs', ['', '--rm-fs'])
def test_gc_when_merging_virtual_repo(repo, rm_fs):
    create_test_file()
    api.set_repo_valid_since(repo.id, 0)

    create_test_dir(repo,'subdir')
    v_repo_id = api.share_subdir_to_user(repo.id, '/subdir', USER, USER2, 'rw')
    assert v_repo_id is not None

    assert api.post_file(v_repo_id, first_path, '/', file_name, USER2) == 0
    run_gc(repo.id, rm_fs, '')

    wait_for_virtual_repo_merge(repo.id, v_repo_id, '/subdir')
    assert api.get_dirent_by_path(repo.id, '/subdir/' + file_name) is not None

    api.set_repo_valid_since(repo.id, 0)
    run_gc(repo.id, '', '--check')

    assert api.unshare_subdir_for_user(repo.id, '/subdir', USER, USER2) == 0
    del_local_files()

def test_gc_when_origin_deletes_file_before_virtual_repo_merge(repo):
    create_test_file()

    api.set_repo_valid_since(repo.id, 0)

    create_test_dir(repo,'subdir')
    assert api.post_file(repo.id, first_path, '/subdir', first_name, USER) == 0

    v_repo_id = api.share_subdir_to_user(repo.id, '/subdir', USER, USER2, 'rw')
    assert v_repo_id is not None

    api.set_repo_valid_since(v_repo_id, 0)

    t_repo = api.get_repo(repo.id)
    base_commit_id = t_repo.head_cmmt_id
    file_id = api.get_file_id_by_path (v_repo_id, first_name)
    assert file_id is not None

    assert api.post_file(repo.id, second_path, '/', second_name, USER) == 0

    # Set an invalid base commit so that the virtual repo will not merge with the origin repo.
    assert api.set_base_commit(v_repo_id, '0' * 40) == 0

    assert api.del_file(repo.id, '/subdir', '[\"' + first_name + '\"]', USER) == 0

    assert api.post_file(repo.id, second_path, '/', second_name, USER) == 0

    assert api.del_file(v_repo_id, '/', '[\"' + first_name + '\"]', USER2) == 0
    assert api.post_file(v_repo_id, second_path, '/', second_name, USER2) == 0

    time.sleep(2.5)

    assert api.set_base_commit(v_repo_id, base_commit_id) == 0
    run_gc(repo.id, "--rm-fs", '')
    run_gc(v_repo_id, '', '--check')

    # The virtual repo has not been merged into the origin repo. Although the file
    # was deleted from the origin repo, it is still referenced by the virtual repo's
    # base commit. The file and its blocks must therefore remain available after GC.
    block_ids = api.list_blocks_by_file_id(repo.id, file_id).splitlines()
    assert api.check_repo_blocks_missing(repo.id, json.dumps(block_ids)) == '[]'

    assert api.unshare_subdir_for_user(repo.id, '/subdir', USER, USER2) == 0
    del_local_files()

# Test cases for the following scenarios:
# 1.The parent repo deletes files that exist in some virtual repos.
# 2.The virtual repo does not properly merge the changes from the parent repo.
# 3.During incremental traversal, the parent repo adds a file with the same content.
def test_gc_when_origin_deletes_file_before_virtual_repo_merge(repo):
    create_test_file()

    api.set_repo_valid_since(repo.id, 0)

    create_test_dir(repo,'subdir')
    assert api.post_file(repo.id, first_path, '/subdir', first_name, USER) == 0

    v_repo_id = api.share_subdir_to_user(repo.id, '/subdir', USER, USER2, 'rw')
    assert v_repo_id is not None

    api.set_repo_valid_since(v_repo_id, 0)

    t_repo = api.get_repo(repo.id)
    base_commit_id = t_repo.head_cmmt_id
    file_id = api.get_file_id_by_path (v_repo_id, first_name)
    assert file_id is not None

    assert api.post_file(repo.id, second_path, '/', second_name, USER) == 0

    # Set an invalid base commit so that the virtual repo will not merge with the origin repo.
    assert api.set_base_commit(v_repo_id, '0' * 40) == 0

    assert api.del_file(repo.id, '/subdir', '[\"' + first_name + '\"]', USER) == 0

    assert api.post_file(repo.id, second_path, '/', second_name, USER) == 0

    assert api.del_file(v_repo_id, '/', '[\"' + first_name + '\"]', USER2) == 0
    assert api.post_file(v_repo_id, second_path, '/', second_name, USER2) == 0

    time.sleep(2.5)

    assert api.set_base_commit(v_repo_id, base_commit_id) == 0
    run_gc(repo.id, "--rm-fs", '')
    run_gc(v_repo_id, '', '--check')

    # The virtual repo has not been merged into the origin repo. Although the file
    # was deleted from the origin repo, it is still referenced by the virtual repo's
    # base commit. The file and its blocks must therefore remain available after GC.
    block_ids = api.list_blocks_by_file_id(repo.id, file_id).splitlines()
    assert api.check_repo_blocks_missing(repo.id, json.dumps(block_ids)) == '[]'

    assert api.unshare_subdir_for_user(repo.id, '/subdir', USER, USER2) == 0
    del_local_files()

# Test cases for the following scenario:
# 1.The parent repo deletes a file.
# 2.The virtual repo does not properly merge the changes from the parent repo.
def test_gc_when_origin_deletes_file_before_virtual_repo_merge(repo):
    create_test_file()

    api.set_repo_valid_since(repo.id, 0)

    create_test_dir(repo,'subdir')
    assert api.post_file(repo.id, first_path, '/subdir', first_name, USER) == 0

    v_repo_id = api.share_subdir_to_user(repo.id, '/subdir', USER, USER2, 'rw')
    assert v_repo_id is not None

    api.set_repo_valid_since(v_repo_id, 0)

    t_repo = api.get_repo(repo.id)
    base_commit_id = t_repo.head_cmmt_id
    file_id = api.get_file_id_by_path (v_repo_id, first_name)
    assert file_id is not None

    # Set an invalid base commit so that the virtual repo will not merge with the origin repo.
    assert api.set_base_commit(v_repo_id, '0' * 40) == 0

    assert api.del_file(repo.id, '/subdir', '[\"' + first_name + '\"]', USER) == 0

    assert api.post_file(repo.id, second_path, '/', second_name, USER) == 0

    time.sleep(2.5)

    assert api.set_base_commit(v_repo_id, base_commit_id) == 0
    run_gc(repo.id, "--rm-fs", '')
    run_gc(v_repo_id, '', '--check')

    # The virtual repo has not been merged into the origin repo.
    # The file and its blocks must therefore remain available after GC.
    block_ids = api.list_blocks_by_file_id(repo.id, file_id).splitlines()
    assert api.check_repo_blocks_missing(repo.id, json.dumps(block_ids)) == '[]'

    assert api.unshare_subdir_for_user(repo.id, '/subdir', USER, USER2) == 0
    del_local_files()

@pytest.mark.parametrize('rm_fs', ['', '--rm-fs'])
def test_gc_during_file_upload(repo, rm_fs):
    create_gc_test_file()
    try:
        api.set_repo_valid_since(repo.id, 0)

        obj_id = '{"parent_dir":"/"}'
        token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, False)
        upload_url = 'http://127.0.0.1:8082/upload-aj/' + token

        index_finished = False
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(upload_gc_test_file, upload_url)

            # The upload handler starts indexing only after the temporary file is complete.
            deadline = time.monotonic() + upload_timeout
            is_uploading = False
            while True:
                offset = api.get_upload_tmp_file_offset(repo.id, '/' + large_file_name)
                if offset > 0:
                    is_uploading = True

                if offset >= large_file_size:
                    break

                # Indexing has finished.
                if offset == 0 and is_uploading:
                    index_finished = True
                    break

                assert time.monotonic() < deadline, 'large file upload did not finish'
                time.sleep(0.1)

            time.sleep(0.5)
            run_gc(repo.id, rm_fs, '')
            response = future.result(timeout=upload_timeout)

        if index_finished:
            assert response.status_code == 200
        else:
            # GC returns 409 only if it removes a block that indexing has written.
            assert response.status_code in (200, 409)

        api.set_repo_valid_since(repo.id, 0)
        run_gc(repo.id, '', '--check')
    finally:
        del_gc_test_file()
