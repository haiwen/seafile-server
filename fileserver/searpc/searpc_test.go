package searpc

import (
	"os"
	"testing"
)

const (
	repoName   = "repo"
	userName   = "seafile@seafile.com"
	encVersion = 2
	pipePath   = "/root/runtime/seafile.sock"
	service    = "seafserv-threaded-rpcserver"
)

var client *Client

func TestMain(m *testing.M) {
	client = Init(pipePath, service)
	code := m.Run()
	os.Exit(code)
}

func TestCallRpc(t *testing.T) {
	repoID, err := client.Call("seafile_create_repo", repoName, "", userName, nil, encVersion)
	if err != nil {
		t.Errorf("failed to create repo.\n")
	}
	if repoID == nil {
		t.Errorf("repo id is nil.\n")
		t.FailNow()
	}

	repo, err := client.Call("seafile_get_repo", repoID)
	if err != nil {
		t.Errorf("failed to get repo.\n")
	}
	if repo == nil {
		t.Errorf("repo is nil.\n")
		t.FailNow()
	}
	repoMap, ok := repo.(map[string]interface{})
	if !ok {
		t.Errorf("failed to assert the type.\n")
		t.FailNow()
	}
	if repoMap["id"] != repoID {
		t.Errorf("wrong repo id.\n")
	}

	repoList, err := client.Call("seafile_get_repo_list", -1, -1, "")
	if err != nil {
		t.Errorf("failed to get repo list.\n")
	}
	if repoList == nil {
		t.Errorf("repo list is nil.\n")
		t.FailNow()
	}
	var exists bool
	repos, ok := repoList.([]interface{})
	if !ok {
		t.Errorf("failed to assert the type.\n")
		t.FailNow()
	}
	for _, v := range repos {
		repo, ok := v.(map[string]interface{})
		if !ok {
			t.Errorf("failed to assert the type.\n")
			t.FailNow()
		}
		if repo["id"] == repoID {
			exists = true
			break
		}
	}
	if exists != true {
		t.Errorf("can't find repo %s in repo list.\n", repoID)
	}

	client.Call("seafile_destroy_repo", repoID)
}
