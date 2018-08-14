import pytest
from seaserv import seafile_api as api

def test_password (encrypted_repo):

    old_passwd = '123'
    new_passwd = '456'

    assert api.set_passwd(encrypted_repo.id, encrypted_repo.name, old_passwd) == 0
    assert api.get_decrypt_key(encrypted_repo.id, encrypted_repo.name)
    api.change_repo_passwd(encrypted_repo.repo_id, old_passwd, new_passwd, encrypted_repo.name) == 0
    assert api.set_passwd(encrypted_repo.id, encrypted_repo.name, new_passwd) == 0

    assert api.is_password_set(encrypted_repo.id, encrypted_repo.name)
    assert api.unset_passwd(encrypted_repo.id, encrypted_repo.name, new_passwd) == 0
    assert api.is_password_set(encrypted_repo.id, encrypted_repo.name) == 0

