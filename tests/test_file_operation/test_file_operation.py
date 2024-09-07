import pytest
import os
import time
import json
from tests.config import USER
from seaserv import seafile_api as api

file_name = 'test.txt'
new_file_name = 'new_test.txt'
new_file_name_2 = 'new_test_2.txt'
empty_file_name = 'empty_test.txt'
new_empty_file_name = 'new_empty_test.txt'
file_content = 'test file content'
file_path = os.getcwd() + '/' + file_name
dir_name = "test_dir"

def create_the_file ():
    with open(file_path, 'w') as fp:
        fp.write(file_content)

@pytest.mark.parametrize('in_batch',
                         [True, False])
def test_file_operation(in_batch):
    t_repo_version = 1
    t_repo_id1 = api.create_repo('test_file_operation1', '', USER, passwd = None)

    create_the_file()

    # test post_file
    assert api.post_file(t_repo_id1, file_path, '/', file_name, USER) == 0
    t_file_id = api.get_file_id_by_path(t_repo_id1, '/' + file_name)
    t_file_size = len(file_content)
    assert t_file_size == api.get_file_size(t_repo_id1, t_repo_version, t_file_id)

    # test post_dir
    assert api.post_dir(t_repo_id1, '/', dir_name, USER) == 0

    # test copy_file (synchronize)
    t_copy_file_result1 = api.copy_file(t_repo_id1, '/', '[\"'+file_name+'\"]', t_repo_id1, '/', '[\"'+new_file_name+'\"]', USER, 0, 1)
    assert t_copy_file_result1
    assert t_copy_file_result1.task_id is None
    assert not t_copy_file_result1.background
    t_file_id = api.get_file_id_by_path(t_repo_id1, '/' + new_file_name)
    assert t_file_size == api.get_file_size(t_repo_id1, t_repo_version, t_file_id)

    # test copy_file (asynchronous)
    t_repo_id2 = api.create_repo('test_file_operation2', '', USER, passwd = None)
    usage = api.get_user_self_usage (USER)
    api.set_user_quota(USER, usage + 1);
    t_copy_file_result2 = api.copy_file(t_repo_id1, '/', '[\"'+file_name+'\"]', t_repo_id2, '/', '[\"'+file_name+'\"]', USER, 1, 0)
    assert t_copy_file_result2
    assert t_copy_file_result2.background
    while True:
        time.sleep(0.1)
        t_copy_task = api.get_copy_task(t_copy_file_result2.task_id)
        assert t_copy_task.failed
        assert t_copy_task.failed_reason == 'Quota is full'
        if t_copy_task.failed:
            break;

    api.set_user_quota(USER, -1);
    t_copy_file_result2 = api.copy_file(t_repo_id1, '/', '[\"'+file_name+'\"]', t_repo_id2, '/', '[\"'+file_name+'\"]', USER, 1, 0)
    assert t_copy_file_result2
    assert t_copy_file_result2.task_id
    assert t_copy_file_result2.background
    while True:
        time.sleep(0.1)
        t_copy_task = api.get_copy_task(t_copy_file_result2.task_id)
        if t_copy_task.successful:
            break;
    t_file_id = api.get_file_id_by_path(t_repo_id2, '/' + file_name)
    assert t_file_size == api.get_file_size(t_repo_id2, t_repo_version, t_file_id)

    # test move_file (synchronize)
    t_move_file_info1 = api.get_dirent_by_path(t_repo_id1, '/' + new_file_name)
    t_move_file_result1 = api.move_file(t_repo_id1, '/', '[\"'+new_file_name+'\"]', t_repo_id1, '/' + dir_name, '[\"'+new_file_name+'\"]', 1, USER, 0, 1)
    assert t_move_file_result1
    t_move_file_info2 = api.get_dirent_by_path(t_repo_id1, '/' + dir_name + '/' + new_file_name)
    assert t_move_file_info1.mtime == t_move_file_info2.mtime
    t_file_id = api.get_file_id_by_path(t_repo_id1, '/' + new_file_name)
    assert t_file_id is None

    # test move_file (synchronize)
    t_move_file_result1 = api.move_file(t_repo_id1, '/' + dir_name, '[\"'+new_file_name+'\"]', t_repo_id1, '/', '[\"'+new_file_name_2+'\"]', 1, USER, 0, 1)
    assert t_move_file_result1
    t_file_id = api.get_file_id_by_path(t_repo_id1, '/' + dir_name + '/' + new_file_name)
    assert t_file_id is None

    # test move_file (asynchronous)
    usage = api.get_user_self_usage (USER)
    api.set_user_quota(USER, usage + 1);
    t_move_file_result2 = api.move_file(t_repo_id1, '/', '[\"'+file_name+'\"]', t_repo_id2, '/' , '[\"'+new_file_name+'\"]', 1, USER, 1, 0)
    assert t_move_file_result2
    assert t_move_file_result2.task_id
    assert t_move_file_result2.background
    while True:
        time.sleep(0.1)
        t_move_task = api.get_copy_task(t_move_file_result2.task_id)
        assert t_move_task.failed
        assert t_move_task.failed_reason == 'Quota is full'
        if t_move_task.failed:
            break

    api.set_user_quota(USER, -1);
    t_move_file_result2 = api.move_file(t_repo_id1, '/', '[\"'+file_name+'\"]', t_repo_id2, '/' , '[\"'+new_file_name+'\"]', 1, USER, 1, 0)
    assert t_move_file_result2
    assert t_move_file_result2.task_id
    assert t_move_file_result2.background
    while True:
        time.sleep(0.1)
        t_move_task = api.get_copy_task(t_move_file_result2.task_id)
        if t_move_task.successful:
            break
    t_file_id = api.get_file_id_by_path(t_repo_id2, '/' + new_file_name)
    assert t_file_size == api.get_file_size(t_repo_id2, t_repo_version, t_file_id)

    # test post_empty_file
    assert api.post_empty_file(t_repo_id1, '/' + dir_name, empty_file_name, USER) == 0
    t_file_id = api.get_file_id_by_path(t_repo_id1, '/' + dir_name + '/' + empty_file_name)
    assert api.get_file_size(t_repo_id1, t_repo_version, t_file_id) == 0

    # test rename_file
    assert api.rename_file(t_repo_id1, '/' + dir_name, empty_file_name, new_empty_file_name, USER) == 0

    #test put_file
    t_new_file_id = api.put_file(t_repo_id1, file_path, '/' + dir_name, new_empty_file_name, USER, None)
    assert t_new_file_id

    # test get_file_revisions
    t_commit_list = api.get_file_revisions(t_repo_id2, None, '/' + file_name, 2)
    assert t_commit_list
    assert len(t_commit_list) == 2
    assert t_commit_list[0].creator_name == USER
    
    # test del_file
    if in_batch:
        assert api.batch_del_files(t_repo_id2, '[\"'+'/'+file_name+'\"]', USER) == 0
    else:
        assert api.del_file(t_repo_id2, '/', '[\"'+file_name+'\"]', USER) == 0

    # test get_deleted
    t_deleted_file_list = api.get_deleted(t_repo_id2, 1)
    assert t_deleted_file_list
    assert len(t_deleted_file_list) == 2
    assert t_deleted_file_list[0].obj_name == file_name
    assert t_deleted_file_list[0].basedir == '/'

    # test del a non-exist file. should return 0.
    if in_batch:
        file_list = ["/"+file_name, "/"+new_file_name]
        assert api.batch_del_files(t_repo_id2, json.dumps(file_list), USER) == 0
        t_deleted_file_list = api.get_deleted(t_repo_id2, 1)
        assert t_deleted_file_list
        assert len(t_deleted_file_list) == 3

        file_list = ["/"+dir_name+"/"+new_empty_file_name, "/"+dir_name+"/"+new_file_name, "/"+new_file_name_2]
        assert api.batch_del_files(t_repo_id1, json.dumps(file_list), USER) == 0
        t_deleted_file_list = api.get_deleted(t_repo_id1, 1)
        assert t_deleted_file_list
        assert len(t_deleted_file_list) == 4
    else:
        assert api.del_file(t_repo_id2, '/', '[\"'+file_name+'\"]', USER) == 0

        assert api.del_file(t_repo_id1, '/' + dir_name, '[\"'+new_empty_file_name+'\"]', USER) == 0
        assert api.del_file(t_repo_id1, '/' + dir_name, '[\"'+new_file_name+'\"]', USER) == 0
        assert api.del_file(t_repo_id2, '/', '[\"'+new_file_name+'\"]', USER) == 0
        assert api.del_file(t_repo_id1, '/', '[\"'+new_file_name_2+'\"]', USER) == 0

    time.sleep(1)
    api.remove_repo(t_repo_id1)
    api.remove_repo(t_repo_id2)
