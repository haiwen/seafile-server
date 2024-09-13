import pytest
import requests
import os
import time
import zipfile
import json
from tests.config import USER
from seaserv import seafile_api as api

file1_name = 'file1.txt'
file2_name = 'file2.txt'
file1_path = os.getcwd() + '/' + file1_name
file2_path = os.getcwd() + '/' + file2_name
file1_content ='File1 content'
file2_content ='File2 content'
download_dir_path = os.getcwd() + '/download_dir'

def create_test_files():
    os.mkdir(download_dir_path)
    with open(file1_path, 'w') as fp1:
        fp1.write(file1_content)
    with open(file2_path, 'w') as fp2:
        fp2.write(file2_content)

def remove_test_files():
    os.rmdir(download_dir_path)
    os.remove(file1_path)
    os.remove(file2_path)

def test_zip_download():
    create_test_files()
    t_repo_id = api.create_repo('test_zip_download', '', USER)
    base_url = 'http://127.0.0.1:8082/'

    #test zip download dir
    dir_name = 'dir'
    api.post_dir(t_repo_id, '/', dir_name, USER)
    api.post_file(t_repo_id, file1_path, '/dir', file1_name, USER)
    api.post_file(t_repo_id, file2_path, '/dir', file2_name, USER)

    dir_id = api.get_dir_id_by_path(t_repo_id, '/dir')
    obj_id = {'obj_id': dir_id, 'dir_name': dir_name, 'is_windows': 0}
    obj_id_json_str = json.dumps(obj_id)
    token = api.get_fileserver_access_token(t_repo_id, obj_id_json_str,
                                            'download-dir', USER)

    time.sleep(1)
    download_url = base_url + 'zip/' + token
    response = requests.get(download_url)
    assert response.status_code == 200

    download_zipfile_path = download_dir_path + '/dir.zip'
    with open(download_zipfile_path, 'wb') as fp:
       fp.write(response.content)
    zipFile = zipfile.ZipFile(download_zipfile_path)
    for name in zipFile.namelist():
        zipFile.extract(name, download_dir_path)
    zipFile.close()
    assert os.path.exists(download_dir_path + '/dir.zip')
    assert os.path.exists(download_dir_path + '/dir')
    assert os.path.exists(download_dir_path + '/dir' + '/file1.txt')
    assert os.path.exists(download_dir_path + '/dir' + '/file2.txt')
    with open(download_dir_path + '/dir' + '/file1.txt', 'r') as fp1:
       line = fp1.read()
    assert line == file1_content
    with open(download_dir_path + '/dir' + '/file2.txt', 'r') as fp2:
       line = fp2.read()
    assert line == file2_content

    os.remove(download_dir_path + '/dir' + '/file1.txt')
    os.remove(download_dir_path + '/dir' + '/file2.txt')
    os.rmdir(download_dir_path + '/dir')
    os.remove(download_dir_path + '/dir.zip')

    #test zip download empty dir
    empty_dir_name = 'empty_dir'
    api.post_dir(t_repo_id, '/', empty_dir_name, USER)

    dir_id = api.get_dir_id_by_path(t_repo_id, '/empty_dir')
    obj_id = {'obj_id': dir_id, 'dir_name': empty_dir_name, 'is_windows': 0}
    obj_id_json_str = json.dumps(obj_id)
    token = api.get_fileserver_access_token(t_repo_id, obj_id_json_str,
                                            'download-dir', USER)
    time.sleep(1)
    download_url = base_url + 'zip/' + token
    response = requests.get(download_url)
    assert response.status_code == 200

    download_zipfile_path = download_dir_path + '/empty_dir.zip'
    with open(download_zipfile_path, 'wb') as fp:
       fp.write(response.content)
    zipFile = zipfile.ZipFile(download_zipfile_path)
    for name in zipFile.namelist():
        zipFile.extract(name, download_dir_path)
    zipFile.close()
    assert os.path.exists(download_dir_path + '/empty_dir')
    assert not os.listdir(download_dir_path + '/empty_dir')

    os.rmdir(download_dir_path + '/empty_dir')
    os.remove(download_dir_path + '/empty_dir.zip')

    #test zip download mutliple files
    api.post_file(t_repo_id, file1_path, '/', file1_name, USER)
    api.post_file(t_repo_id, file2_path, '/', file2_name, USER)
    obj_id = {'parent_dir': '/', 'file_list': [file1_name, file2_name], 'is_windows' : 0}
    obj_id_json_str = json.dumps(obj_id)
    token = api.get_fileserver_access_token(t_repo_id, obj_id_json_str,
                                            'download-multi', USER)

    time.sleep(1)
    download_url = base_url + 'zip/' + token
    response = requests.get(download_url)
    assert response.status_code == 200

    download_zipfile_path = download_dir_path + '/multi_files.zip'
    with open(download_zipfile_path, 'wb') as fp:
       fp.write(response.content)
    zipFile = zipfile.ZipFile(download_zipfile_path)
    for name in zipFile.namelist():
        zipFile.extract(name, download_dir_path)
    zipFile.close()
    assert os.path.exists(download_dir_path + '/file1.txt')
    assert os.path.exists(download_dir_path + '/file2.txt')
    with open(download_dir_path + '/file1.txt', 'r') as fp1:
       line = fp1.read()
    assert line == file1_content
    with open(download_dir_path + '/file2.txt', 'r') as fp2:
       line = fp2.read()
    assert line == file2_content
    os.remove(download_dir_path + '/file1.txt')
    os.remove(download_dir_path + '/file2.txt')
    os.remove(download_dir_path + '/multi_files.zip')

    #test zip download mutliple files in multi-level
    api.post_file(t_repo_id, file2_path, '/dir', file2_name, USER)
    obj_id = {'parent_dir': '/', 'file_list': [file1_name, 'dir/'+file2_name], 'is_windows' : 0}
    obj_id_json_str = json.dumps(obj_id)
    token = api.get_fileserver_access_token(t_repo_id, obj_id_json_str,
                                            'download-multi', USER)

    time.sleep(1)
    download_url = base_url + 'zip/' + token
    response = requests.get(download_url)
    assert response.status_code == 200

    download_zipfile_path = download_dir_path + '/multi_files.zip'
    with open(download_zipfile_path, 'wb') as fp:
       fp.write(response.content)
    zipFile = zipfile.ZipFile(download_zipfile_path)
    for name in zipFile.namelist():
        zipFile.extract(name, download_dir_path)
    zipFile.close()
    assert os.path.exists(download_dir_path + '/file1.txt')
    assert os.path.exists(download_dir_path + '/file2.txt')
    with open(download_dir_path + '/file1.txt', 'r') as fp1:
       line = fp1.read()
    assert line == file1_content
    with open(download_dir_path + '/file2.txt', 'r') as fp2:
       line = fp2.read()
    assert line == file2_content
    os.remove(download_dir_path + '/file1.txt')
    os.remove(download_dir_path + '/file2.txt')
    os.remove(download_dir_path + '/multi_files.zip')

    remove_test_files()
    api.remove_repo(t_repo_id)

