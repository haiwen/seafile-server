import pytest
from tests.config import USER
from seaserv import seafile_api as api

@pytest.mark.parametrize('rpc, enc_version',
                         [('create_repo', 2), ('create_repo', 3), ('create_repo', 4),
                          ('create_enc_repo', 2), ('create_enc_repo', 3), ('create_enc_repo', 4)])
def test_encrypted_repo(rpc, enc_version):
    test_repo_name = 'test_enc_repo'
    test_repo_desc = 'test_enc_repo'
    test_repo_passwd = 'test_enc_repo'
    if rpc == 'create_repo':
        repo_id = api.create_repo(test_repo_name, test_repo_desc, USER,
                                  test_repo_passwd, enc_version)
        assert repo_id
    else:
        if enc_version == 2:
            repo_id = 'd17bf8ca-3019-40ee-8fdb-0258c89fb762'
        elif enc_version == 3:
            repo_id = 'd17bf8ca-3019-40ee-8fdb-0258c89fb763'
        else:
            repo_id = 'd17bf8ca-3019-40ee-8fdb-0258c89fb764'
        enc_info = api.generate_magic_and_random_key(enc_version, repo_id, test_repo_passwd)
        assert enc_info
        ret_repo_id = api.create_enc_repo(repo_id, test_repo_name, test_repo_desc,
                                          USER, enc_info.magic, enc_info.random_key,
                                          enc_info.salt, enc_version)
        assert ret_repo_id == repo_id

    repo = api.get_repo(repo_id)
    assert repo
    assert repo.enc_version == enc_version
    assert len(repo.magic) == 64
    assert len(repo.random_key) == 96
    if enc_version == 3 or enc_version == 4:
        assert len(repo.salt) == 64
        
    new_passwd = 'new password'

    assert api.set_passwd(repo.id, USER, test_repo_passwd) == 0
    assert api.get_decrypt_key(repo.id, USER)
    api.change_repo_passwd(repo.repo_id, test_repo_passwd, new_passwd, USER) == 0
    assert api.set_passwd(repo.id, USER, new_passwd) == 0

    assert api.is_password_set(repo.id, USER)
    assert api.unset_passwd(repo.id, USER) == 0
    assert api.is_password_set(repo.id, USER) == 0

    api.remove_repo(repo_id)

@pytest.mark.parametrize('rpc, enc_version, algo, params',
                         [('create_repo', 2, 'pbkdf2_sha256', '1000'), ('create_repo', 3, 'pbkdf2_sha256', '1000'), ('create_repo', 4, 'pbkdf2_sha256', '1000'),
                         ('create_repo', 2, 'argon2id', '2,102400,8'), ('create_repo', 3, 'argon2id', '2,102400,8'), ('create_repo', 4, 'argon2id', '2,102400,8')])
def test_pwd_hash(rpc, enc_version, algo, params):
    test_repo_name = 'test_enc_repo'
    test_repo_desc = 'test_enc_repo'
    test_repo_passwd = 'test_enc_repo'
    repo_id = api.create_repo(test_repo_name, test_repo_desc, USER,
                              test_repo_passwd, enc_version, pwd_hash_algo=algo, pwd_hash_params=params)
    assert repo_id

    repo = api.get_repo(repo_id)
    assert repo
    assert repo.enc_version == enc_version
    assert len(repo.pwd_hash) == 64
    assert len(repo.random_key) == 96
    if enc_version > 2:
        assert len(repo.salt) == 64
        
    new_passwd = 'new password'

    assert api.set_passwd(repo.id, USER, test_repo_passwd) == 0
    assert api.get_decrypt_key(repo.id, USER)
    api.change_repo_passwd(repo.repo_id, test_repo_passwd, new_passwd, USER) == 0
    assert api.set_passwd(repo.id, USER, new_passwd) == 0

    assert api.is_password_set(repo.id, USER)
    assert api.unset_passwd(repo.id, USER) == 0
    assert api.is_password_set(repo.id, USER) == 0

    api.remove_repo(repo_id)

@pytest.mark.parametrize('enc_version, algo, params',
                         [(2, 'pbkdf2_sha256', '1000'), (3, 'pbkdf2_sha256', '1000'), ( 4, 'pbkdf2_sha256', '1000'),
                         (2, 'argon2id', '2,102400,8'), (3, 'argon2id', '2,102400,8'), (4, 'argon2id', '2,102400,8')])
def test_upgrade_pwd_hash(enc_version, algo, params):
    test_repo_name = 'test_enc_repo'
    test_repo_desc = 'test_enc_repo'
    test_repo_passwd = 'test_enc_repo'
    repo_id = api.create_repo(test_repo_name, test_repo_desc, USER,
                              test_repo_passwd, enc_version)
    assert repo_id

    repo = api.get_repo(repo_id)
    assert repo
    assert repo.enc_version == enc_version
    assert len(repo.random_key) == 96
    if enc_version > 2:
        assert len(repo.salt) == 64

    api.upgrade_repo_pwd_hash_algorithm (repo.repo_id, USER, test_repo_passwd, algo, params) == 0

    repo = api.get_repo(repo_id)
    assert repo.pwd_hash_algo == algo;
    assert repo.pwd_hash_params == params;
    assert repo.pwd_hash

    assert api.set_passwd(repo.id, USER, test_repo_passwd) == 0
    assert api.get_decrypt_key(repo.id, USER)
    assert api.is_password_set(repo.id, USER)
    assert api.unset_passwd(repo.id, USER) == 0
    assert api.is_password_set(repo.id, USER) == 0

    api.remove_repo(repo_id)
