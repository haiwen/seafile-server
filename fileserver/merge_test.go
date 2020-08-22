package main

import (
	"fmt"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"os"
	"syscall"
	"testing"
)

const (
	commitID        = "0401fc662e3bc87a41f299a907c056aaf8322a27"
	repoID          = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	seafileConfPath = "/tmp/conf"
	seafileDataDir  = "/tmp/conf/seafile-data"
	mergedRoot      = "8f7b21d4ae3568dcccd215c58defe27d4c037b14"
)

var tree1 string
var tree2 string
var tree3 string
var tree4 string
var tree1CommitID string
var tree2CommitID string
var tree3CommitID string

// baseDir /aaa/bbb/ccc
// headDir /aaa/bbb
// remoteDir /aaa
func createTestDir() error {
	modeDir := uint32(syscall.S_IFDIR | 0644)
	modeFile := uint32(syscall.S_IFREG | 0644)

	emptyDir, err := getSeafdir(nil, "empty")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}
	dentEmpty := fsmgr.SeafDirent{ID: emptyDir, Name: "empty", Mode: modeDir}

	file1, err := fsmgr.NewSeafile(1, 1, nil)
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v.\n", err)
		return err
	}
	err = fsmgr.SaveSeafile(repoID, file1)
	if err != nil {
		err := fmt.Errorf("failed to save seafile: %v.\n", err)
		return err
	}

	dent1 := fsmgr.SeafDirent{ID: file1.FileID, Name: "testfile", Mode: modeFile, Size: 1}
	dir1, err := getSeafdir([]*fsmgr.SeafDirent{&dent1}, "bbb")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}
	dent2 := fsmgr.SeafDirent{ID: dir1, Name: "bbb", Mode: modeDir}
	dir2, err := getSeafdir([]*fsmgr.SeafDirent{&dentEmpty, &dent2}, "aaa")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	tree1 = dir2

	commit1 := commitmgr.NewCommit(repoID, "", tree1, "seafile", "this is the first commit.\n")
	err = commitmgr.Save(commit1)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v.\n", err)
		return err
	}
	tree1CommitID = commit1.CommitID

	file2, err := fsmgr.NewSeafile(1, 10, nil)
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v.\n", err)
		return err
	}
	err = fsmgr.SaveSeafile(repoID, file2)
	if err != nil {
		err := fmt.Errorf("failed to save seafile: %v.\n", err)
		return err
	}

	dent3 := fsmgr.SeafDirent{ID: file2.FileID, Name: "testfile", Mode: modeFile, Size: 10}
	dir3, err := getSeafdir([]*fsmgr.SeafDirent{&dent3}, "bbb")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	dent4 := fsmgr.SeafDirent{ID: dir3, Name: "bbb", Mode: modeDir}
	dir4, err := getSeafdir([]*fsmgr.SeafDirent{&dent4}, "aaa")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	tree2 = dir4

	commit2 := commitmgr.NewCommit(repoID, "", tree2, "seafile", "this is the second commit.\n")
	err = commitmgr.Save(commit2)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v.\n", err)
		return err
	}
	tree2CommitID = commit2.CommitID

	file3, err := fsmgr.NewSeafile(1, 100, nil)
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v.\n", err)
		return err
	}
	err = fsmgr.SaveSeafile(repoID, file3)
	if err != nil {
		err := fmt.Errorf("failed to save seafile: %v.\n", err)
		return err
	}

	dent5 := fsmgr.SeafDirent{ID: file3.FileID, Name: "testfile", Mode: modeFile, Size: 100}
	dir5, err := getSeafdir([]*fsmgr.SeafDirent{&dent5}, "bbb")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	dent6 := fsmgr.SeafDirent{ID: dir5, Name: "bbb", Mode: modeDir}
	dir6, err := getSeafdir([]*fsmgr.SeafDirent{&dent6}, "aaa")
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v.\n", err)
		return err
	}

	tree3 = dir6

	commit3 := commitmgr.NewCommit(repoID, "", tree3, "seafile", "this is the third commit.\n")
	err = commitmgr.Save(commit3)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v.\n", err)
		return err
	}
	tree3CommitID = commit3.CommitID

	return nil
}

func getSeafdir(dents []*fsmgr.SeafDirent, name string) (string, error) {
	seafdir, err := fsmgr.NewSeafdir(1, dents)
	if err != nil {
		err := fmt.Errorf("failed to new seafdir: %v.\n", err)
		return "", err
	}
	err = fsmgr.SaveSeafdir(repoID, seafdir)
	if err != nil {
		return "", err
	}

	return seafdir.DirID, nil
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
	err := createTestDir()
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
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree1, tree1}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}

	if opt.mergedRoot != tree1 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, tree1)
	}
}

func TestMergeTrees2(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree1, tree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}

	if opt.mergedRoot != tree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, tree2)
	}
}

func TestMergeTrees3(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree1, tree3}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}

	if opt.mergedRoot != tree3 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, tree2)
	}
}

func TestMergeTrees4(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree2, tree1}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != tree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, tree2)
	}
}

func TestMergeTrees5(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree2, tree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != tree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, tree2)
	}
}

func TestMergeTrees6(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree2, tree3}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot == tree1 || opt.mergedRoot == tree2 || opt.mergedRoot == tree3 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergedRoot)
	}
}

func TestMergeTrees7(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree3, tree1}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != tree3 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergedRoot)
	}
}

func TestMergeTrees8(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree3, tree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot == tree1 || opt.mergedRoot == tree2 || opt.mergedRoot == tree3 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergedRoot)
	}
}

func TestMergeTrees9(t *testing.T) {
	commit, err := commitmgr.Load(repoID, tree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{tree1, tree3, tree3}
	opt := new(mergeOptions)
	opt.remoteRepoID = repoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(repoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != tree3 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergedRoot)
	}
}
