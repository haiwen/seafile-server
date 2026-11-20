import json

import pytest
from seaserv import seafile_api as api

from tests.config import USER


@pytest.mark.parametrize('name', ['\\name', 'na\\me', 'name\\'])
def test_file_operations_with_backslash(repo, tmp_path, name):
    parent = '/' + name
    assert api.post_dir(repo.id, '/', name, USER) == 0
    local_file = tmp_path / 'upload.txt'
    local_file.write_text('original content')

    assert api.post_file(repo.id, str(local_file), parent + '/', name, USER) == 0
    original_id = api.get_file_id_by_path(repo.id, parent + '/' + name)
    assert original_id
    assert [entry.obj_name for entry in api.list_dir_by_path(repo.id, parent)] == [name]

    local_file.write_text('updated content')
    updated_id = api.put_file(
        repo.id, str(local_file), parent + '/', name, USER, None)
    assert updated_id and updated_id != original_id
    assert api.get_file_id_by_path(repo.id, parent + '/' + name) == updated_id

    copied_name = 'copy' + name
    result = api.copy_file(
        repo.id, parent + '/', json.dumps([name]),
        repo.id, '/dir1/', json.dumps([copied_name]), USER, 0, 1)
    assert result and not result.background
    assert api.get_file_id_by_path(repo.id, '/dir1/' + copied_name) == updated_id
    assert api.get_file_id_by_path(repo.id, parent + '/' + name) == updated_id

    moved_name = 'moved' + name
    result = api.move_file(
        repo.id, '/dir1/', json.dumps([copied_name]),
        repo.id, parent + '/', json.dumps([moved_name]), 1, USER, 0, 1)
    assert result and not result.background
    assert api.get_file_id_by_path(repo.id, '/dir1/' + copied_name) is None
    assert api.get_file_id_by_path(repo.id, parent + '/' + moved_name) == updated_id

    renamed_name = 'renamed' + name
    assert api.rename_file(repo.id, parent, moved_name, renamed_name, USER) == 0
    assert api.get_file_id_by_path(repo.id, parent + '/' + moved_name) is None
    assert api.get_file_id_by_path(repo.id, parent + '/' + renamed_name) == updated_id
    assert api.del_file(repo.id, parent, json.dumps([renamed_name]), USER) == 0
    assert api.get_file_id_by_path(repo.id, parent + '/' + renamed_name) is None


@pytest.mark.parametrize('name', ['\\directory', 'dir\\ectory', 'directory\\'])
def test_directory_operations_with_backslash(repo, name):
    relative_path = name + '/nested\\dir'
    path = '/' + relative_path
    assert api.mkdir_with_parents(repo.id, '/', relative_path, USER) == 0
    assert api.get_dir_id_by_path(repo.id, path)
    assert api.post_empty_file(repo.id, path, 'file\\name.txt', USER) == 0
    file_id = api.get_file_id_by_path(repo.id, path + '/file\\name.txt')
    assert file_id

    result = api.copy_file(
        repo.id, '/', json.dumps([name]),
        repo.id, '/dir1/', json.dumps([name]), USER, 0, 1)
    assert result and not result.background
    assert api.get_file_id_by_path(repo.id, '/dir1' + path + '/file\\name.txt') == file_id

    result = api.move_file(
        repo.id, '/dir1/', json.dumps([name]),
        repo.id, '/dir2/', json.dumps([name]), 1, USER, 0, 1)
    assert result and not result.background
    assert api.get_dir_id_by_path(repo.id, '/dir1/' + name) is None
    assert api.get_file_id_by_path(repo.id, '/dir2' + path + '/file\\name.txt') == file_id

    renamed_name = 'renamed' + name
    assert api.rename_file(repo.id, '/dir2', name, renamed_name, USER) == 0
    assert api.get_dir_id_by_path(repo.id, '/dir2/' + name) is None
    assert api.get_dir_id_by_path(repo.id, '/dir2/' + renamed_name)
    assert api.del_file(repo.id, '/dir2', json.dumps([renamed_name]), USER) == 0
    assert api.get_dir_id_by_path(repo.id, '/dir2/' + renamed_name) is None
