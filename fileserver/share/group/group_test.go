package group

import (
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

const (
	user        = "seafile"
	password    = "seafile"
	host        = "127.0.0.1"
	port        = 3306
	ccnetDBName = "ccnet-db"
	seafDBName  = "seafile-db"
	useTLS      = false
	userName    = "test@test.com"
	repoID1     = "657f5929-ad2d-49ea-b197-dddd014e01a4"
	repoID2     = "169c559b-3a42-439a-b6ae-1d3d542376ff"
)

func TestMain(m *testing.M) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t", user, password, host, port, ccnetDBName, useTLS)
	ccnetDB, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("Failed to open database: %v", err)
	}
	dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t", user, password, host, port, seafDBName, useTLS)
	seafDB, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("Failed to open database: %v", err)
	}

	defer func() {
		ccnetDB.Close()
		seafDB.Close()
	}()

	Init(ccnetDB, seafDB, "Group")
	m.Run()
}

func TestCheckGroupPermissionByUser(t *testing.T) {
	perm, err := CheckGroupPermissionByUser(repoID1, userName)
	if err != nil {
		t.Errorf("Failed to get groups by user %s:%s", userName, err)
	}
	if perm != "r" {
		t.Errorf("Check group permission for repo(%s) error: %s", repoID1, perm)
	}
	perm, err = CheckGroupPermissionByUser(repoID2, userName)
	if err != nil {
		t.Errorf("Failed to get groups by user %s:%s", userName, err)
	}
	if perm != "rw" {
		t.Errorf("Check group permission for repo(%s) error: %s", repoID2, perm)
	}
}
