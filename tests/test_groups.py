import pytest
from seaserv import seafile_api as api
from seaserv import ccnet_api

from tests.config import USER, USER2

def test_multi_tier_groups(repo):
    id1 = ccnet_api.create_group('group1', USER, parent_group_id=-1)
    id2 = ccnet_api.create_group('group2', USER2, parent_group_id = id1)
    id3 = ccnet_api.create_group('group3', USER, parent_group_id = id1)
    id4 = ccnet_api.create_group('group4', USER2, parent_group_id = id3)
    assert id1 != -1 and id2 != -1 and id3 != -1 and id4 != -1

    group1 = ccnet_api.get_group(id1)
    group2 = ccnet_api.get_group(id2)
    group3 = ccnet_api.get_group(id3)
    group4 = ccnet_api.get_group(id4)
    assert group1.parent_group_id == -1
    assert group2.parent_group_id == id1
    assert group3.parent_group_id == id1
    assert group4.parent_group_id == id3

    ances_order = [id4, id3, id2, id1]
    user2_groups_with_ancestors = ccnet_api.get_groups (USER2, return_ancestors = True)
    assert len(user2_groups_with_ancestors) == 4
    i = 0
    for g in user2_groups_with_ancestors:
        assert g.id == ances_order[i]
        i = i + 1

    order = [id4, id2]
    i = 0
    user2_groups = ccnet_api.get_groups (USER2)
    assert len(user2_groups) == 2
    for g in user2_groups:
        assert g.id == order[i]
        i = i + 1

    top_groups = ccnet_api.get_top_groups()
    assert len(top_groups) == 1
    for g in top_groups:
        assert g.parent_group_id == -1

    child_order = [id2, id3]
    i = 0
    id1_children = ccnet_api.get_child_groups(id1)
    assert len(id1_children) == 2
    for g in id1_children:
        assert g.id == child_order[i]
        i = i + 1

    group4_order = [id1, id3, id4]
    i = 0
    group4_ancestors = ccnet_api.get_ancestor_groups(id4)
    assert len(group4_ancestors) == 3
    for g in group4_ancestors:
        assert g.id == group4_order[i]
        i = i + 1

    rm4 = ccnet_api.remove_group(id4)
    rm3 = ccnet_api.remove_group(id3)
    rm2 = ccnet_api.remove_group(id2)
    rm1 = ccnet_api.remove_group(id1)
    assert rm4 == 0 and rm3 == 0 and rm2 == 0 and rm1 == 0
