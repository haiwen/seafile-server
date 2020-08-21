package main

import (
	"fmt"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"os"
	"testing"
	"time"
)

const (
	commitID        = "0401fc662e3bc87a41f299a907c056aaf8322a27"
	repoID          = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	seafileConfPath = "/tmp/conf"
	seafileDataDir  = "/tmp/conf/seafile-data"
)

var baseID string
var headID string
var remoteID string

// baseDir /aaa/bbb/ccc
// headDir /aaa/bbb
// remoteDir /aaa
func createTestDir() error {
	dir1, err := getSeafdir("", "ccc")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}
	dir2, err := getSeafdir(dir1, "bbb")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}
	dir3, err := getSeafdir(dir2, "aaa")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	dir4, err := getSeafdir("", "bbb")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	dir5, err := getSeafdir(dir4, "aaa")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	dir6, err := getSeafdir("", "aaa")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	baseID = dir3
	headID = dir5
	remoteID = dir6

	return nil
}

func getSeafdir(dirID string, name string) (string, error) {
	var seafdir *fsmgr.SeafDir
	if dirID == "" {
		dir, err := fsmgr.NewSeafdir(1, nil)
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v.\n", err)
			return "", err
		}
		seafdir = dir
	} else {
		dent := fsmgr.SeafDirent{ID: dirID, Name: name, Mode: 0x4000}
		dir, err := fsmgr.NewSeafdir(1, []*fsmgr.SeafDirent{&dent})
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v.\n", err)
			return "", err
		}
		seafdir = dir
	}
	err := fsmgr.SaveSeafdir(repoID, seafdir)
	if err != nil {
		return "", err
	}

	return seafdir.DirID, nil
}

func createCommit() error {
	newCommit := new(commitmgr.Commit)
	newCommit.CommitID = commitID
	newCommit.RepoID = repoID
	newCommit.CreatorName = "seafile"
	newCommit.CreatorID = commitID
	newCommit.Desc = "This is a commit"
	newCommit.Ctime = time.Now().Unix()
	newCommit.ParentID = commitID
	newCommit.DeviceName = "Linux"
	err := commitmgr.Save(newCommit)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v.\n", err)
		return err
	}
	return nil
}

func delFile() error {
	err := os.RemoveAll(seafileConfPath)
	if err != nil {
		return err
	}

	return nil
}

func TestMain(m *testing.M) {
	commitmgr.Init(seafileConfPath, seafileDataDir)
	fsmgr.Init(seafileConfPath, seafileDataDir)
	err := createCommit()
	if err != nil {
		fmt.Printf("failed to create commit: %v.\n", err)
		os.Exit(1)
	}
	err = createTestDir()
	if err != nil {
		fmt.Printf("failed to create test dir: %v.\n", err)
		os.Exit(1)
	}
	code := m.Run()
	err = delFile()
	if err != nil {
		fmt.Printf("failed to remove test file : %v\n", err)
	}
	os.Exit(code)
}

func TestMergeTrees1(t *testing.T) {
	commit, err := commitmgr.Load(repoID, commitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{baseID, headID, remoteID}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
}

func TestMergeTrees2(t *testing.T) {
	commit, err := commitmgr.Load(repoID, commitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{headID, baseID, remoteID}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
}

func TestMergeTrees3(t *testing.T) {
	commit, err := commitmgr.Load(repoID, commitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{remoteID, baseID, headID}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
}
