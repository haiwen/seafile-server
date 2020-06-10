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
	repoID := client.Call("seafile_create_repo", repoName, "", userName, nil, encVersion)
	if repoID == nil {
		t.Errorf("failed to create repo.\n")
		t.FailNow()
	}
	repo := client.Call("seafile_get_repo", repoID)
	if repo == nil {
		t.Errorf("failed to get repo.\n")
	}
	repoMap := repo.(map[string]interface{})
	if repoMap["id"] != repoID {
		t.Errorf("wrong repo id.\n")
	}
	repoList := client.Call("seafile_get_repo_list", -1, -1, "")
	if repoList == nil {
		t.Errorf("failed to get repo list.\n")
	}
	var exists bool
	for _, v := range repoList.([]interface{}) {
		repo := v.(map[string]interface{})
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
