import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api

from tests.config import ADMIN_USER, USER, USER2
from tests.utils import assert_repo_with_permission


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo_to_user(repo, permission):
    assert api.check_permission(repo.id, USER) == 'rw'
    assert api.check_permission(repo.id, USER2) is None

    api.share_repo(repo.id, USER, USER2, permission)
    assert api.check_permission(repo.id, USER2) == permission

    t_repos_list = 0
    t_repos_list = api.get_share_in_repo_list(USER2, 0, 1)

    assert_repo_with_permission(repo, t_repos_list, permission)

    api.remove_share(repo.id, USER, USER2)
    assert api.check_permission(repo.id, USER2) is None


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_repo_to_group(repo, group, permission):
    assert api.check_permission(repo.id, USER) == 'rw'
    assert api.check_permission(repo.id, USER2) is None

    t_repos = api.get_repos_by_group(group.id)
    assert len(t_repos) == 0

    group_list = ccnet_api.get_groups(USER)
    assert len(group_list) == 1
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 0

    api.group_share_repo(repo.id, group.id, USER, permission)
    t_repos = api.get_repos_by_group(group.id)
    assert_repo_with_permission(repo, t_repos, permission)

    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 0

    ccnet_api.group_add_member(group.id, USER, USER2)
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 1
    t_group = group_list[0]
    assert t_group.id == group.id

    repos2 = api.get_repos_by_group(group.id)
    assert_repo_with_permission(repo, repos2, permission)

    assert api.check_permission(repo.id, USER2) == permission

    api.group_unshare_repo(repo.id, group.id, USER)
    repos = api.get_repos_by_group(group.id)
    assert len(repos) == 0

    assert api.check_permission(repo.id, USER2) is None

@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_org_repo_to_user(repo, org, permission):
    t_org_list = ccnet_api.get_all_orgs(0, 1)
    assert len(t_org_list) == 1

    t_orgs = t_org_list[0]
    assert t_orgs.org_id == org.org_id

    t_org_count = ccnet_api.count_orgs()
    assert t_org_count == 1

    t_user_orgs = ccnet_api.get_orgs_by_user(USER)
    assert len(t_user_orgs) == 0

    ccnet_api.add_org_user(org.org_id, USER, False)
    t_user_orgs = ccnet_api.get_orgs_by_user(USER)
    assert len(t_user_orgs) == 1 
    t_user_org = t_user_orgs[0]
    assert t_user_org.org_id == org.org_id
    
    assert api.check_permission(repo.id, USER) == 'rw'
    assert api.check_permission(repo.id, USER2) is None
    
    api.share_repo(repo.id, USER, USER2, permission)
    
    t_user_orgs = ccnet_api.get_orgs_by_user(USER2)
    assert len(t_user_orgs) == 0

    assert api.check_permission(repo.id, USER2) == permission

    api.remove_share(repo.id, USER, USER2) 
    assert api.check_permission(repo.id, USER2) is None
    
    ccnet_api.add_org_user(org.org_id, USER2, False)
    t_user_orgs = ccnet_api.get_orgs_by_user(USER2)
    assert len(t_user_orgs) == 1
    t_user_org = t_user_orgs[0]
    assert t_user_org.org_id == org.org_id
 
    assert api.check_permission(repo.id, USER2) is None
    api.share_repo(repo.id, USER, USER2, permission)
    assert api.check_permission(repo.id, USER2) == permission

    api.remove_share(repo.id, USER, USER2)
    assert api.check_permission(repo.id, USER2) is None

    ccnet_api.remove_org_user(org.org_id, USER)
    orgs = ccnet_api.get_orgs_by_user(USER)
    assert len(orgs) ==0

    ccnet_api.remove_org_user(org.org_id, USER2)
    orgs = ccnet_api.get_orgs_by_user(USER2)
    assert len(orgs) ==0


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_share_org_repo_to_group(repo, org, permission):
    ccnet_api.add_org_user(org.org_id, USER, False)
    
    assert api.check_permission(repo.id, USER) == 'rw'
    assert api.check_permission(repo.id, USER2) is None

    t_group_list = ccnet_api.get_groups(USER)
    assert len(t_group_list) == 0
    
    t_org_group_id = ccnet_api.create_org_group(org.org_id, 'org_group_test1', USER)
    t_group_list = ccnet_api.get_groups(USER)
    assert len(t_group_list) == 1

    t_group_list = ccnet_api.get_groups(USER2)
    assert len(t_group_list) == 0

    api.group_share_repo(repo.id, t_org_group_id, USER, permission)
    t_repos = api.get_repos_by_group(t_org_group_id)
    assert_repo_with_permission(repo, t_repos, permission)
    
    ccnet_api.group_add_member(t_org_group_id, USER, USER2)
    t_group_list = ccnet_api.get_groups(USER2)
    assert len(t_group_list) == 1
    t_group = t_group_list[0]
    assert t_group.id == t_org_group_id

    t_group_repo = api.get_repos_by_group(t_org_group_id)
    assert_repo_with_permission(repo, t_group_repo, permission)

    assert api.check_permission(repo.id, USER2) == permission

    api.group_unshare_repo(repo.id, t_org_group_id, USER)
    t_repos_list = api.get_repos_by_group(t_org_group_id)
    assert len(t_repos_list) == 0

    assert api.check_permission(repo.id, USER2) is None

    ccnet_api.group_remove_member(t_org_group_id, USER, USER2)
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 0

    ccnet_api.add_org_user(org.org_id, USER2, False)

    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 0

    ccnet_api.group_add_member(t_org_group_id, USER, USER2)
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 1
    t_group = t_group_list[0]
    assert t_group.id == t_org_group_id

    ccnet_api.group_remove_member(t_org_group_id, USER, USER2)
    group_list = ccnet_api.get_groups(USER2)
    assert len(group_list) == 0
