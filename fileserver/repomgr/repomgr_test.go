package repomgr

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/searpc"
	"github.com/haiwen/seafile-server/fileserver/utils"
)

const (
	//	repoID          = "9646f13e-bbab-4eaf-9a84-fb6e1cd776b3"
	user            = "seafile"
	password        = "seafile"
	host            = "127.0.0.1"
	port            = 3306
	dbName          = "seafile-db"
	useTLS          = false
	seafileConfPath = "/root/conf"
	seafileDataDir  = "/root/conf/seafile-data"
	repoName        = "repo"
	userName        = "seafile@seafile.com"
	encVersion      = 2
	pipePath        = "/root/runtime/seafile.sock"
	service         = "seafserv-threaded-rpcserver"
)

var repoID string
var client *searpc.Client

func createRepo() string {
	id, err := client.Call("seafile_create_repo", repoName, "", userName, nil, encVersion)
	if err != nil {
		fmt.Printf("failed to create repo.\n")
	}
	if id == nil {
		fmt.Printf("repo id is nil.\n")
		os.Exit(1)
	}

	repoid, ok := id.(string)
	if !ok {
		fmt.Printf("returned value isn't repo id.\n")
	}
	return repoid
}

func delRepo() {
	_, err := client.Call("seafile_destroy_repo", repoID)
	if err != nil {
		fmt.Printf("failed to del repo.\n")
		os.Exit(1)
	}
}

func TestMain(m *testing.M) {
	client = searpc.Init(pipePath, service)
	repoID = createRepo()
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t", user, password, host, port, dbName, useTLS)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("Failed to open database: %v", err)
	}
	seafDB := &utils.DB{DB: db}
	Init(seafDB)
	commitmgr.Init(seafileConfPath, seafileDataDir)
	code := m.Run()
	delRepo()
	os.Exit(code)
}

func TestGet(t *testing.T) {
	repo := Get(repoID)
	if repo == nil {
		t.Errorf("failed to get repo : %s.\n", repoID)
		t.FailNow()
	}

	if repo.ID != repoID {
		t.Errorf("failed to get repo : %s.\n", repoID)
	}
}
