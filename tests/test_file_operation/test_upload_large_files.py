import pytest
import requests
import os
import hashlib
from tests.config import USER, USERNAME
from seaserv import seafile_api as api
from requests_toolbelt import MultipartEncoder

file_name = 'file.txt'
file_name_not_replaced = 'file (1).txt'
file_path = os.getcwd() + '/' + file_name
file_size = 400*1024*1024

download_file_name = 'download_file.txt'
download_file_path = os.getcwd() + '/' + download_file_name

resumable_download_file_name = 'resumable_download_file.txt'
resumable_download_file_path = os.getcwd() + '/' + resumable_download_file_name

resumable_file_name = 'resumable.txt'
chunked_part1_name = 'part1.txt'
chunked_part2_name = 'part2.txt'
chunked_part1_path = os.getcwd() + '/' + chunked_part1_name
chunked_part2_path = os.getcwd() + '/' + chunked_part2_name
chunked_part1_size = 200*1024*1024
chunked_part2_size = 200*1024*1024
total_size = chunked_part1_size + chunked_part2_size

#File_id is not used when upload files, but
#the argument obj_id of get_fileserver_access_token shouldn't be NULL.
file_id = '0000000000000000000000000000000000000000'

def create_test_file():
    fp = open(file_path, 'wb')
    fp.write(os.urandom(file_size))
    fp.close()
    fp = open(chunked_part1_path, 'wb')
    fp.write(os.urandom(chunked_part1_size))
    fp.close()
    fp = open(chunked_part2_path, 'wb')
    fp.write(os.urandom(chunked_part2_size))
    fp.close()

def create_test_dir(repo, dir_name):
    parent_dir = '/'
    api.post_dir(repo.id,parent_dir,dir_name,USER, USERNAME)

def assert_upload_response(response):
    assert response.status_code == 200
    response_json = response.json()
    assert response_json[0]['size'] == file_size
    assert response_json[0]['id'] != file_id
    assert response_json[0]['name'] == file_name

def assert_resumable_upload_response(response, repo_id, file_name, upload_complete):
    assert response.status_code == 200
    if not upload_complete:
        assert response.text == '{"success": true}'
        offset = api.get_upload_tmp_file_offset(repo_id, '/' + file_name)
        assert offset == chunked_part1_size
    else:
        response_json = response.json()
        assert response_json[0]['size'] == total_size
        new_file_id = response_json[0]['id']
        assert len(new_file_id) == 40 and new_file_id != file_id
        assert response_json[0]['name'] == resumable_file_name

def request_resumable_upload(filepath, headers,upload_url_base,parent_dir,is_ajax):
    m = MultipartEncoder(
            fields={
                    'parent_dir': parent_dir,
                    'file': (resumable_file_name, open(filepath, 'rb'), 'application/octet-stream')
            })
    params = {'ret-json':'1'}
    headers["Content-type"] = m.content_type
    if is_ajax:
        response = requests.post(upload_url_base, headers = headers,
                             data = m)
    else:
        response = requests.post(upload_url_base, headers = headers,
                             data = m, params = params)
    return response

def write_file(file_path, file_content):
    fp = open(file_path, 'w')
    fp.write(file_content)
    fp.close()

def del_repo_files(repo_id):
    api.del_file(repo_id, '/', '[\"'+file_name+'\"]', USER, USERNAME)
    api.del_file(repo_id, '/', '[\"'+file_name_not_replaced+'\"]', USER, USERNAME)
    api.del_file(repo_id, '/', '[\"subdir\"]', USER, USERNAME)
    api.del_file(repo_id, '/', '[\"'+resumable_file_name+'\"]', USER, USERNAME)

def del_local_files():
    os.remove(file_path)
    os.remove(download_file_path)
    os.remove(chunked_part1_path)
    os.remove(chunked_part2_path)
    os.remove(resumable_download_file_path)

def sha1sum(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()

def chunked_sha1sum(chunked_part1, chunked_part2):
    f1 = open(chunked_part1, 'rb')
    f2 = open(chunked_part2, 'rb')
    data = f1.read()+f2.read()
    sha1 = hashlib.sha1(data).hexdigest()
    f1.close()
    f2.close()
    return sha1

def test_large_files_ajax(repo):
    create_test_file()
    create_test_dir(repo,'test')
    obj_id = '{"parent_dir":"/"}'

    # upload large file by upload-aj
    file_id1 = sha1sum(file_path)
    token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, USERNAME, False)
    upload_url_base = 'http://127.0.0.1:8082/upload-aj/'+ token
    m = MultipartEncoder(
            fields={
                    'parent_dir': '/',
                    'file': (file_name, open(file_path, 'rb'), 'application/octet-stream')
            })
    response = requests.post(upload_url_base,
                             data = m, headers = {'Content-Type': m.content_type})
    assert_upload_response(response)

    # download file and check sha1
    obj_id = api.get_file_id_by_path(repo.id, '/' + file_name)
    assert obj_id != None
    token = api.get_fileserver_access_token (repo.id, obj_id, 'download', USER, USERNAME, False)
    download_url = 'http://127.0.0.1:8082/files/' + token + '/' + file_name
    response = requests.get(download_url)
    assert response.status_code == 200
    with open(download_file_path, 'wb') as fp:
       fp.write(response.content)

    file_id2 = sha1sum(download_file_path)
    assert file_id1 == file_id2

    file_id1 = chunked_sha1sum(chunked_part1_path, chunked_part2_path)
    parent_dir = '/'
    headers = {'Content-Range':'bytes 0-{}/{}'.format(str(chunked_part1_size - 1),
                                                      str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    response = request_resumable_upload(chunked_part1_path, headers, upload_url_base, parent_dir, True)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, False)

    headers = {'Content-Range':'bytes {}-{}/{}'.format(str(chunked_part1_size),
                                                       str(total_size - 1),
                                                       str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    response = request_resumable_upload(chunked_part2_path, headers, upload_url_base, parent_dir, True)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, True)

    # download file and check sha1
    obj_id = api.get_file_id_by_path(repo.id, '/' + resumable_file_name)
    assert obj_id != None
    token = api.get_fileserver_access_token (repo.id, obj_id, 'download', USER, USERNAME, False)
    download_url = 'http://127.0.0.1:8082/files/' + token + '/' + resumable_file_name
    response = requests.get(download_url)
    assert response.status_code == 200
    with open(resumable_download_file_path, 'wb') as fp:
       fp.write(response.content)
    file_id2 = sha1sum(resumable_download_file_path)
    assert file_id1 == file_id2

    del_repo_files(repo.id)
    del_local_files()

def test_large_files_api(repo):
    create_test_file()
    params = {'ret-json':'1'}
    obj_id = '{"parent_dir":"/"}'
    create_test_dir(repo,'test')

    #test upload file to root dir.
    file_id1 = sha1sum(file_path)
    params = {'ret-json':'1'}
    token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, USERNAME, False)
    upload_url_base = 'http://127.0.0.1:8082/upload-api/' + token
    m = MultipartEncoder(
            fields={
                    'parent_dir': '/',
                    'file': (file_name, open(file_path, 'rb'), 'application/octet-stream')
            })
    response = requests.post(upload_url_base, params = params,
                             data = m, headers = {'Content-Type': m.content_type})
    assert_upload_response(response)

    # download file and check sha1
    obj_id = api.get_file_id_by_path(repo.id, '/' + file_name)
    assert obj_id != None
    token = api.get_fileserver_access_token (repo.id, obj_id, 'download', USER, USERNAME, False)
    download_url = 'http://127.0.0.1:8082/files/' + token + '/' + file_name
    response = requests.get(download_url)
    assert response.status_code == 200
    with open(download_file_path, 'wb') as fp:
       fp.write(response.content)

    file_id2 = sha1sum(download_file_path)
    assert file_id1 == file_id2

    #test resumable upload file to test
    file_id1 = chunked_sha1sum(chunked_part1_path, chunked_part2_path)
    parent_dir = '/'
    headers = {'Content-Range':'bytes 0-{}/{}'.format(str(chunked_part1_size - 1),
                                                      str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    response = request_resumable_upload(chunked_part1_path, headers, upload_url_base, parent_dir, False)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, False)

    headers = {'Content-Range':'bytes {}-{}/{}'.format(str(chunked_part1_size),
                                                       str(total_size - 1),
                                                       str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    response = request_resumable_upload(chunked_part2_path, headers, upload_url_base, parent_dir, False)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, True)

    obj_id = api.get_file_id_by_path(repo.id, '/' + resumable_file_name)
    assert obj_id != None
    token = api.get_fileserver_access_token (repo.id, obj_id, 'download', USER, USERNAME, False)
    download_url = 'http://127.0.0.1:8082/files/' + token + '/' + resumable_file_name
    response = requests.get(download_url)
    assert response.status_code == 200
    with open(resumable_download_file_path, 'wb') as fp:
       fp.write(response.content)
    file_id2 = sha1sum(resumable_download_file_path)
    assert file_id1 == file_id2

    del_repo_files(repo.id)
    del_local_files()
