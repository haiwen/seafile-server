import pytest
from tests.config import USER
from seaserv import seafile_api as api

def test_trashed_repos(repo):

    #test get_trash_repo_list
    t_start = -1
    t_limit = -1
    t_trash_repos_tmp = api.get_trash_repo_list(t_start, t_limit)
    api.remove_repo(repo.id)
    t_trash_repos = api.get_trash_repo_list(t_start, t_limit)
    assert len(t_trash_repos) == len(t_trash_repos_tmp) + 1
    t_trash_repos_tmp = t_trash_repos

    #test get_trash_repo_owner
    t_owner = api.get_trash_repo_owner(repo.id)
    assert t_owner == USER

    #test restore_repo_from_trash
    t_repo_get = api.get_repo(repo.id)
    assert t_repo_get == None
    api.restore_repo_from_trash(repo.id)
    t_repo_get = api.get_repo(repo.id)
    assert t_repo_get and t_repo_get.repo_id == repo.id

    #test del_repo_from_trash
    api.del_repo_from_trash(repo.id)
    t_trash_repos = api.get_trash_repo_list(t_start, t_limit)
    assert len(t_trash_repos) == len(t_trash_repos_tmp) - 1

    #test get_trash_repos_by_owner
    t_trash_repos_by_owner_tmp = api.get_trash_repos_by_owner(USER)
    api.remove_repo(repo.id)
    t_trash_repos_by_owner = api.get_trash_repos_by_owner(USER)
    assert len(t_trash_repos_by_owner) == len(t_trash_repos_by_owner_tmp) + 1

    #test empty_repo_trash
    api.empty_repo_trash()
    t_trash_repos = api.get_trash_repo_list(t_start, t_limit)
    assert len(t_trash_repos) == 0

    #test empty_repo_trash_by_owner
    t_repo_id = api.create_repo('test_trashed_repos', '', USER, passwd=None)
    api.remove_repo(t_repo_id)
    t_trash_repos_by_owner = api.get_trash_repos_by_owner(USER)
    assert len(t_trash_repos_by_owner) != 0
    api.empty_repo_trash_by_owner(USER)
    t_trash_repos_by_owner = api.get_trash_repos_by_owner(USER)
    assert len(t_trash_repos_by_owner) == 0
