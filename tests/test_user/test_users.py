import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api
from tests.utils import randstring
from tests.config import USER, USER2, ADMIN_USER

def test_user_management():
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

    ccnet_api.remove_emailuser('DB', email1)
    ccnet_api.remove_emailuser('DB', email2)
