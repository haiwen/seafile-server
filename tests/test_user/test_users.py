import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api
from tests.utils import randstring
from tests.config import USER, USER2, ADMIN_USER

def test_user_management(repo):
    email1 = '%s@%s.com' % (randstring(6), randstring(6))
    email2 = '%s@%s.com' % (randstring(6), randstring(6))
    passwd1 = 'randstring(6)'
    passwd2 = 'randstring(6)'

    ccnet_api.add_emailuser(email1, passwd1, 1, 1)
    ccnet_api.add_emailuser(email2, passwd2, 0, 0)

    ccnet_email1 = ccnet_api.get_emailuser(email1)
    ccnet_email2 = ccnet_api.get_emailuser(email2)
    assert ccnet_email1.is_active == True
    assert ccnet_email1.is_staff == True
    assert ccnet_email2.is_active == False
    assert ccnet_email2.is_staff == False

    assert ccnet_api.validate_emailuser(email1, passwd1) == 0
    assert ccnet_api.validate_emailuser(email2, passwd2) == 0

    users = ccnet_api.search_emailusers('DB',email1, -1, -1)
    assert len(users) == 1
    user_ccnet = users[0]
    assert user_ccnet.email == email1

    user_counts = ccnet_api.count_emailusers('DB')
    user_numbers = ccnet_api.get_emailusers('DB', -1, -1)

    ccnet_api.update_emailuser('DB', ccnet_email2.id, passwd2, 1, 1)
    email2_new = ccnet_api.get_emailuser(email2)
    assert email2_new.is_active == True
    assert email2_new.is_staff == True

    #test group when update user id
    id1 = ccnet_api.create_group('group1', email1, parent_group_id=-1)
    assert id1 != -1
    group1 = ccnet_api.get_group(id1)
    assert group1.parent_group_id == -1

    # test shared repo when update user id
    api.share_repo(repo.id, USER, email1, "rw")
    assert api.repo_has_been_shared(repo.id)

    new_email1 = '%s@%s.com' % (randstring(6), randstring(6))
    assert ccnet_api.update_emailuser_id (email1, new_email1) == 0

    shared_users = api.list_repo_shared_to(USER, repo.id)
    assert len (shared_users) == 1
    assert shared_users[0].repo_id == repo.id
    assert shared_users[0].user == new_email1
    assert shared_users[0].perm == "rw"

    api.remove_share(repo.id, USER, new_email1)

    email1_groups = ccnet_api.get_groups (new_email1)
    assert len (email1_groups) == 1
    assert email1_groups[0].id == id1
    rm1 = ccnet_api.remove_group(id1)
    assert rm1 == 0

    ccnet_api.remove_emailuser('DB', new_email1)
    ccnet_api.remove_emailuser('DB', email2)
