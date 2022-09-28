package commitmgr

import (
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	commitID        = "0401fc662e3bc87a41f299a907c056aaf8322a27"
	rootID          = "6a1608dc2a1248838464e9b194800d35252e2ce3"
	repoID          = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	seafileConfPath = "/tmp/conf"
	seafileDataDir  = "/tmp/conf/seafile-data"
)

func delFile() error {
	err := os.RemoveAll(seafileConfPath)
	if err != nil {
		return err
	}

	return nil
}

func TestMain(m *testing.M) {
	code := m.Run()
	err := delFile()
	if err != nil {
		fmt.Printf("Failed to remove test file : %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func assertEqual(t *testing.T, a, b interface{}) {
	if a != b {
		t.Errorf("Not Equal.%t,%t", a, b)
	}
}

func TestCommit(t *testing.T) {
	Init(seafileConfPath, seafileDataDir)
	newCommit := new(Commit)
	newCommit.CommitID = commitID
	newCommit.RepoID = repoID
	newCommit.RootID = rootID
	newCommit.CreatorName = "seafile"
	newCommit.CreatorID = commitID
	newCommit.Desc = "This is a commit"
	newCommit.Ctime = time.Now().Unix()
	newCommit.ParentID.SetValid(commitID)
	newCommit.DeviceName = "Linux"
	err := Save(newCommit)
	if err != nil {
		t.Errorf("Failed to save commit.\n")
	}

	commit, err := Load(repoID, commitID)
	if err != nil {
		t.Errorf("Failed to load commit: %v.\n", err)
	}
	assertEqual(t, commit.CommitID, commitID)
	assertEqual(t, commit.RepoID, repoID)
	assertEqual(t, commit.CreatorName, "seafile")
	assertEqual(t, commit.CreatorID, commitID)
	assertEqual(t, commit.ParentID.String, commitID)
}
