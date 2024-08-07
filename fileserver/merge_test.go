package main

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/option"
)

const (
	mergeTestCommitID        = "0401fc662e3bc87a41f299a907c056aaf8322a27"
	mergeTestRepoID          = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	mergeTestSeafileConfPath = "/tmp/conf"
	mergeTestSeafileDataDir  = "/tmp/conf/seafile-data"
)

var mergeTestTree1 string
var mergeTestTree2 string
var mergeTestTree3 string
var mergeTestTree4 string
var mergeTestTree5 string
var mergeTestTree1CommitID string
var mergeTestTree2CommitID string
var mergeTestTree3CommitID string
var mergeTestTree4CommitID string

/*
test directory structure:
tree1
|--bbb

	|-- testfile(size:1)

tree2
|--bbb

	|-- testfile(size:10)

tree3
|--bbb

tree4
|--bbb

	|-- testfile(size:100)

tree5
|--
*/
func mergeTestCreateTestDir() error {
	modeDir := uint32(syscall.S_IFDIR | 0644)
	modeFile := uint32(syscall.S_IFREG | 0644)

	emptyDir, err := mergeTestCreateSeafdir(nil)
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}
	mergeTestTree5 = emptyDir

	file1, err := fsmgr.NewSeafile(1, 1, []string{"4f616f98d6a264f75abffe1bc150019c880be239"})
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v", err)
		return err
	}
	err = fsmgr.SaveSeafile(mergeTestRepoID, file1)
	if err != nil {
		err := fmt.Errorf("failed to save seafile: %v", err)
		return err
	}

	dent1 := fsmgr.SeafDirent{ID: file1.FileID, Name: "testfile", Mode: modeFile, Size: 1}
	dir1, err := mergeTestCreateSeafdir([]*fsmgr.SeafDirent{&dent1})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}
	dent2 := fsmgr.SeafDirent{ID: dir1, Name: "bbb", Mode: modeDir}
	dir2, err := mergeTestCreateSeafdir([]*fsmgr.SeafDirent{&dent2})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}

	mergeTestTree1 = dir2

	commit1 := commitmgr.NewCommit(mergeTestRepoID, "", mergeTestTree1, "seafile", "this is the first commit.\n")
	err = commitmgr.Save(commit1)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v", err)
		return err
	}
	mergeTestTree1CommitID = commit1.CommitID

	file2, err := fsmgr.NewSeafile(1, 10, []string{"4f616f98d6a264f75abffe1bc150019c880be239"})
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v", err)
		return err
	}
	err = fsmgr.SaveSeafile(mergeTestRepoID, file2)
	if err != nil {
		err := fmt.Errorf("failed to save seafile: %v", err)
		return err
	}

	dent3 := fsmgr.SeafDirent{ID: file2.FileID, Name: "testfile", Mode: modeFile, Size: 10}
	dir3, err := mergeTestCreateSeafdir([]*fsmgr.SeafDirent{&dent3})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}

	dent4 := fsmgr.SeafDirent{ID: dir3, Name: "bbb", Mode: modeDir}
	dir4, err := mergeTestCreateSeafdir([]*fsmgr.SeafDirent{&dent4})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}

	mergeTestTree2 = dir4

	commit2 := commitmgr.NewCommit(mergeTestRepoID, "", mergeTestTree2, "seafile", "this is the second commit.\n")
	err = commitmgr.Save(commit2)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v", err)
		return err
	}
	mergeTestTree2CommitID = commit2.CommitID

	dir5, err := mergeTestCreateSeafdir(nil)
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}

	dent6 := fsmgr.SeafDirent{ID: dir5, Name: "bbb", Mode: modeDir}
	dir6, err := mergeTestCreateSeafdir([]*fsmgr.SeafDirent{&dent6})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}

	mergeTestTree3 = dir6

	commit3 := commitmgr.NewCommit(mergeTestRepoID, "", mergeTestTree3, "seafile", "this is the third commit.\n")
	err = commitmgr.Save(commit3)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v", err)
		return err
	}
	mergeTestTree3CommitID = commit3.CommitID

	file3, err := fsmgr.NewSeafile(1, 100, []string{"4f616f98d6a264f75abffe1bc150019c880be240"})
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v", err)
		return err
	}
	err = fsmgr.SaveSeafile(mergeTestRepoID, file3)
	if err != nil {
		err := fmt.Errorf("failed to save seafile: %v", err)
		return err
	}
	dent7 := fsmgr.SeafDirent{ID: file3.FileID, Name: "testfile", Mode: modeFile, Size: 100}
	dir7, err := mergeTestCreateSeafdir([]*fsmgr.SeafDirent{&dent7})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}

	dent8 := fsmgr.SeafDirent{ID: dir7, Name: "bbb", Mode: modeDir}
	dir8, err := mergeTestCreateSeafdir([]*fsmgr.SeafDirent{&dent8})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}

	mergeTestTree4 = dir8

	commit4 := commitmgr.NewCommit(mergeTestRepoID, "", mergeTestTree3, "seafile", "this is the fourth commit.\n")
	err = commitmgr.Save(commit4)
	if err != nil {
		err := fmt.Errorf("failed to save commit: %v", err)
		return err
	}
	mergeTestTree4CommitID = commit4.CommitID

	return nil
}

func mergeTestCreateSeafdir(dents []*fsmgr.SeafDirent) (string, error) {
	seafdir, err := fsmgr.NewSeafdir(1, dents)
	if err != nil {
		err := fmt.Errorf("failed to new seafdir: %v", err)
		return "", err
	}
	err = fsmgr.SaveSeafdir(mergeTestRepoID, seafdir)
	if err != nil {
		return "", err
	}

	return seafdir.DirID, nil
}

func mergeTestDelFile() error {
	err := os.RemoveAll(mergeTestSeafileConfPath)
	if err != nil {
		return err
	}

	return nil
}

func TestMergeTrees(t *testing.T) {
	commitmgr.Init(mergeTestSeafileConfPath, mergeTestSeafileDataDir)
	fsmgr.Init(mergeTestSeafileConfPath, mergeTestSeafileDataDir, option.FsCacheLimit)
	err := mergeTestCreateTestDir()
	if err != nil {
		fmt.Printf("failed to create test dir: %v", err)
		os.Exit(1)
	}

	t.Run("test1", testMergeTrees1)
	t.Run("test2", testMergeTrees2)
	t.Run("test3", testMergeTrees3)
	t.Run("test4", testMergeTrees4)
	t.Run("test5", testMergeTrees5)
	t.Run("test6", testMergeTrees6)
	t.Run("test7", testMergeTrees7)
	t.Run("test8", testMergeTrees8)
	t.Run("test9", testMergeTrees9)
	t.Run("test10", testMergeTrees10)
	t.Run("test11", testMergeTrees11)
	t.Run("test12", testMergeTrees12)

	err = mergeTestDelFile()
	if err != nil {
		fmt.Printf("failed to remove test file : %v", err)
		os.Exit(1)
	}
}

// head add file
func testMergeTrees1(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree3CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree3, mergeTestTree2, mergeTestTree3}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}

	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// remote add file
func testMergeTrees2(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree3CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree3, mergeTestTree3, mergeTestTree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}

	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// head modify file
func testMergeTrees3(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree1, mergeTestTree2, mergeTestTree1}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}

	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// remote modify file
func testMergeTrees4(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree1, mergeTestTree1, mergeTestTree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}

	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// head and remote add file
func testMergeTrees5(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree3CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree3, mergeTestTree1, mergeTestTree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if !opt.conflict {
		t.Errorf("merge error %s.\n", opt.mergedRoot)
	}
}

// head and remote modify file
func testMergeTrees6(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree1, mergeTestTree2, mergeTestTree4}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if !opt.conflict {
		t.Errorf("merge error %s.\n", opt.mergedRoot)
	}
}

// head modify file and remote delete file
func testMergeTrees7(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree1, mergeTestTree2, mergeTestTree3}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// head delete file and remote modify file
func testMergeTrees8(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree1, mergeTestTree3, mergeTestTree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// head modify file and remote delete dir of this file
func testMergeTrees9(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree1, mergeTestTree2, mergeTestTree5}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// remote modify file and head delete dir of this file
func testMergeTrees10(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree1CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree1, mergeTestTree5, mergeTestTree2}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != mergeTestTree2 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree2)
	}
}

// head add file and remote delete dir of thie file
func testMergeTrees11(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree3CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree3, mergeTestTree1, mergeTestTree5}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != mergeTestTree1 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree1)
	}
}

// remote add file and head delete dir of this file
func testMergeTrees12(t *testing.T) {
	commit, err := commitmgr.Load(mergeTestRepoID, mergeTestTree3CommitID)
	if err != nil {
		t.Errorf("failed to load commit.\n")
	}
	roots := []string{mergeTestTree3, mergeTestTree5, mergeTestTree1}
	opt := new(mergeOptions)
	opt.remoteRepoID = mergeTestRepoID
	opt.remoteHead = commit.CommitID

	err = mergeTrees(mergeTestRepoID, roots, opt)
	if err != nil {
		t.Errorf("failed to merge.\n")
	}
	if opt.mergedRoot != mergeTestTree1 {
		t.Errorf("merge error %s/%s.\n", opt.mergedRoot, mergeTestTree1)
	}
}
