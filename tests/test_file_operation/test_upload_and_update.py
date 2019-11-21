import pytest
import requests
import os
from tests.config import USER
from seaserv import seafile_api as api

file_name = 'file.txt'
file_name_not_replaced = 'file (1).txt'
file_path = os.getcwd() + '/' + file_name
file_content = 'File content.\r\n'
file_size = len(file_content)

resumable_file_name = 'resumable.txt'
resumable_test_file_name = 'test/resumable.txt'
chunked_part1_name = 'part1.txt'
chunked_part2_name = 'part2.txt'
chunked_part1_path = os.getcwd() + '/' + chunked_part1_name
chunked_part2_path = os.getcwd() + '/' + chunked_part2_name
chunked_part1_content = 'First line.\r\n'
chunked_part2_content = 'Second line.\r\n'
total_size = len(chunked_part1_content) + len(chunked_part2_content)

#File_id is not used when upload files, but
#the argument obj_id of get_fileserver_access_token shouldn't be NULL.
file_id = '0000000000000000000000000000000000000000'

def create_test_file():
    fp = open(file_path, 'w')
    fp.close()
    fp = open(chunked_part1_path, 'w')
    fp.close()
    fp = open(chunked_part2_path, 'w')
    fp.close()

def create_test_dir(repo, dir_name):
    parent_dir = '/'
    api.post_dir(repo.id,parent_dir,dir_name,USER)

def assert_upload_response(response, replace, file_exist):
    assert response.status_code == 200
    response_json = response.json()
    assert response_json[0]['size'] == 0
    assert response_json[0]['id'] == file_id
    if file_exist and not replace:
        assert response_json[0]['name'] == file_name_not_replaced
    else:
        assert response_json[0]['name'] == file_name

def assert_resumable_upload_response(response, repo_id, file_name, upload_complete):
    assert response.status_code == 200
    if not upload_complete:
        assert response.text == '{"success": true}'
        offset = api.get_upload_tmp_file_offset(repo_id, '/' + file_name)
        assert offset == len(chunked_part1_content)
    else:
        response_json = response.json()
        assert response_json[0]['size'] == total_size
        new_file_id = response_json[0]['id']
        assert len(new_file_id) == 40 and new_file_id != file_id
        assert response_json[0]['name'] == resumable_file_name

def assert_update_response(response, is_json):
    assert response.status_code == 200
    if is_json:
        response_json = response.json()
        assert response_json[0]['size'] == file_size
        new_file_id = response_json[0]['id']
        assert len(new_file_id) == 40 and new_file_id != file_id
        assert response_json[0]['name'] == file_name
    else:
        new_file_id = response.text
        assert len(new_file_id) == 40 and new_file_id != file_id

def write_file(file_path, file_content):
    fp = open(file_path, 'w')
    fp.write(file_content)
    fp.close()

def del_repo_files(repo_id):
    api.del_file(repo_id, '/', file_name, USER)
    api.del_file(repo_id, '/', file_name_not_replaced, USER)
    api.del_file(repo_id, '/', 'subdir', USER)
    api.del_file(repo_id, '/', resumable_file_name, USER)

def del_local_files():
    os.remove(file_path)
    os.remove(chunked_part1_path)
    os.remove(chunked_part2_path)

def test_ajax(repo):
    create_test_file()
    create_test_dir(repo,'test')
    obj_id = '{"parent_dir":"/"}'

    #test upload file to test dir.
    token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, False)
    upload_url_base = 'http://127.0.0.1:8082/upload-aj/'+ token
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, files = files)
    assert response.status_code == 403

    #test upload file to root dir.
    token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, False)
    upload_url_base = 'http://127.0.0.1:8082/upload-aj/'+ token
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, files = files)
    assert_upload_response(response, False, False)

    #test upload file to test dir when file already exists.
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, files = files)
    assert response.status_code == 403

    #test upload file to root dir when file already exists.
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, files = files)
    assert_upload_response(response, False, True)

    #test upload file to subdir which parent dir is test dir.
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/test',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base,  files = files)
    assert response.status_code == 403
    #test upload file to subdir which parent dir is root dir.
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base,  files = files)
    assert_upload_response(response, False, False)

    #test upload file to subdir which parent dir is test dir when file already exists.
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/test',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base, files = files)
    assert response.status_code == 403

    #test upload file to subdir which parent dir is root dir when file already exists.
    files = {'file': open(file_path, 'rb'),
             'parent_dir':'/',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base, files = files)
    assert_upload_response(response, False, True)

    #test resumable upload file to test dir
    write_file(chunked_part1_path, chunked_part1_content)
    write_file(chunked_part2_path, chunked_part2_content)

    token = api.get_fileserver_access_token(repo.id, obj_id,
                                            'upload', USER, False)
    headers = {'Content-Range':'bytes 0-{}/{}'.format(str(len(chunked_part1_content) - 1),
                                                      str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part1_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_test_file_name, False)

    headers = {'Content-Range':'bytes {}-{}/{}'.format(str(len(chunked_part1_content)),
                                                       str(total_size - 1),
                                                       str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part2_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files)
    assert response.status_code == 403
    #test resumable upload file to root dir
    write_file(chunked_part1_path, chunked_part1_content)
    write_file(chunked_part2_path, chunked_part2_content)

    token = api.get_fileserver_access_token(repo.id, obj_id,
                                            'upload', USER, False)
    headers = {'Content-Range':'bytes 0-{}/{}'.format(str(len(chunked_part1_content) - 1),
                                                      str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part1_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, False)

    headers = {'Content-Range':'bytes {}-{}/{}'.format(str(len(chunked_part1_content)),
                                                       str(total_size - 1),
                                                       str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part2_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, True)

    #test update file.
    write_file(file_path, file_content)
    token = api.get_fileserver_access_token(repo.id, file_id, 'update', USER, False)
    update_url_base = 'http://127.0.0.1:8082/update-aj/' + token
    files = {'file': open(file_path, 'rb'),
             'target_file':'/' + file_name}
    response = requests.post(update_url_base, files = files)
    assert_update_response(response, True)

    del_repo_files(repo.id)
    del_local_files()

def test_api(repo):
    create_test_file()
    params = {'ret-json':'1'}
    obj_id = '{"parent_dir":"/"}'
    create_test_dir(repo,'test')
    #test upload file to test dir instead of  root dir.
    token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, False)
    upload_url_base = 'http://127.0.0.1:8082/upload-api/' + token
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert response.status_code == 403

    #test upload file to root dir.
    token = api.get_fileserver_access_token(repo.id, obj_id, 'upload', USER, False)
    upload_url_base = 'http://127.0.0.1:8082/upload-api/' + token
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert_upload_response(response, False, False)

    #test upload file to test dir instead of root dir when file already exists and replace is set.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/test',
             'replace':'1'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert response.status_code == 403

    #test upload file to root dir when file already exists and replace is set.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/',
             'replace':'1'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert_upload_response(response, True, True)

    #test upload file to test dir instead of root dir when file already exists and replace is unset.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert response.status_code == 403

    #test upload file to root dir when file already exists and replace is unset.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert_upload_response(response, False, True)

    #test upload the file to subdir which parent dir is test.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/test',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert response.status_code == 403

    #test upload the file to subdir.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert_upload_response(response, False, False)

    #test upload the file to subdir which parent dir is test when file already exists and replace is set.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/test',
             'relative_path':'subdir',
             'replace':'1'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert response.status_code == 403

    #test upload the file to subdir when file already exists and replace is set.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/',
             'relative_path':'subdir',
             'replace':'1'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert_upload_response(response, True, True)

    #unset test upload the file to subdir which parent_dir is test when file already exists and replace is unset.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/test',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert response.status_code == 403

    #unset test upload the file to subdir when file already exists and replace is unset.
    files = {'file':open(file_path, 'rb'),
             'parent_dir':'/',
             'relative_path':'subdir'}
    response = requests.post(upload_url_base, params = params,
                             files = files)
    assert_upload_response(response, False, True)

    #test resumable upload file to test
    write_file(chunked_part1_path, chunked_part1_content)
    write_file(chunked_part2_path, chunked_part2_content)

    token = api.get_fileserver_access_token(repo.id, obj_id,
                                            'upload', USER, False)
    headers = {'Content-Range':'bytes 0-{}/{}'.format(str(len(chunked_part1_content) - 1),
                                                      str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part1_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files, params = params)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_test_file_name, False)

    headers = {'Content-Range':'bytes {}-{}/{}'.format(str(len(chunked_part1_content)),
                                                       str(total_size - 1),
                                                       str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part2_path, 'rb'),
             'parent_dir':'/test'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files, params = params)
    assert response.status_code == 403

    #test resumable upload file to root dir
    write_file(chunked_part1_path, chunked_part1_content)
    write_file(chunked_part2_path, chunked_part2_content)

    token = api.get_fileserver_access_token(repo.id, obj_id,
                                            'upload', USER, False)
    headers = {'Content-Range':'bytes 0-{}/{}'.format(str(len(chunked_part1_content) - 1),
                                                      str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part1_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files, params = params)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, False)

    headers = {'Content-Range':'bytes {}-{}/{}'.format(str(len(chunked_part1_content)),
                                                       str(total_size - 1),
                                                       str(total_size)),
               'Content-Disposition':'attachment; filename=\"{}\"'.format(resumable_file_name)}
    files = {'file': open(chunked_part2_path, 'rb'),
             'parent_dir':'/'}
    response = requests.post(upload_url_base, headers = headers,
                             files = files, params = params)
    assert_resumable_upload_response(response, repo.id,
                                     resumable_file_name, True)

    #test update file.
    write_file(file_path, file_content)
    token = api.get_fileserver_access_token(repo.id, file_id, 'update', USER, False)
    update_url_base = 'http://127.0.0.1:8082/update-api/' + token
    files = {'file':open(file_path, 'rb'),
             'target_file':'/' + file_name}
    response = requests.post(update_url_base, files = files)
    assert_update_response(response, False)

    del_repo_files(repo.id)
    del_local_files()
