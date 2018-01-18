#coding: UTF-8

import logging
import os

import pytest
from tenacity import retry, stop_after_attempt, wait_fixed
from tests.config import (
    ADMIN_PASSWORD, ADMIN_USER, INACTIVE_PASSWORD, INACTIVE_USER, PASSWORD,
    PASSWORD2, USER, USER2
)
from tests.utils import create_and_get_repo, randstring, create_and_get_group, create_and_get_org

from seaserv import ccnet_api, seafile_api

logger = logging.getLogger(__name__)


@retry(wait=wait_fixed(2), stop=stop_after_attempt(10))
def wait_for_server():
    seafile_api.get_repo_list(0, 1)


@pytest.fixture(scope='session', autouse=True)
def create_users():
    """
    Create an admin user and a normal user
    """
    wait_for_server()
    logger.info('preparing users for testing')
    ccnet_api.add_emailuser(USER, PASSWORD, is_staff=False, is_active=True)
    ccnet_api.add_emailuser(USER2, PASSWORD2, is_staff=False, is_active=True)
    ccnet_api.add_emailuser(
        INACTIVE_USER, INACTIVE_PASSWORD, is_staff=False, is_active=False
    )
    ccnet_api.add_emailuser(
        ADMIN_USER, ADMIN_PASSWORD, is_staff=True, is_active=True
    )


@pytest.yield_fixture(scope='function')
def repo():
    repo = create_and_get_repo(
        'testrepo测试-{}'.format(randstring(10)), '', USER, passwd=None
    )
    try:
        yield repo
    finally:
        if seafile_api.get_repo(repo.id):
            # The repo may be deleted in the test case
            seafile_api.remove_repo(repo.id)

@pytest.yield_fixture(scope='function')
def group():
    group = create_and_get_group(
            'test_group测试-{}'.format(randstring(10)), USER, gtype=None
    )
    try:
        yield group
    finally:
        if ccnet_api.get_group(group.id):
            ccnet_api.remove_group(group.id)

@pytest.yield_fixture(scope='function')
def org():
    org = create_and_get_org(
            'testorg测试-{}'.format(randstring(10)), 'seafile_org', 'seatest'
    )
    try:
        yield org
    finally:
        if ccnet_api.get_org_by_id(org.id):
            ccnet_api.remove_org(org.id)







