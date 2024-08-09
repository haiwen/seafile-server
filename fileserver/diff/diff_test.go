package diff

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/haiwen/seafile-server/fileserver/fsmgr"
)

const (
	emptySHA1               = "0000000000000000000000000000000000000000"
	diffTestSeafileConfPath = "/tmp/conf"
	diffTestSeafileDataDir  = "/tmp/conf/seafile-data"
	diffTestRepoID          = "0d18a711-c988-4f7b-960c-211b34705ce3"
)

var diffTestTree1 string
var diffTestTree2 string
var diffTestTree3 string
var diffTestTree4 string
var diffTestFileID string
var diffTestDirID1 string
var diffTestDirID2 string

/*
   test directory structure:

   tree1
   |--

   tree2
   |--file

   tree3
   |--dir

   tree4
   |--dir
      |-- file

*/

func TestDiffTrees(t *testing.T) {
	fsmgr.Init(diffTestSeafileConfPath, diffTestSeafileDataDir, 2<<30)

	err := diffTestCreateTestDir()
	if err != nil {
		fmt.Printf("failed to create test dir: %v", err)
		os.Exit(1)
	}

	t.Run("test1", testDiffTrees1)
	t.Run("test2", testDiffTrees2)
	t.Run("test3", testDiffTrees3)
	t.Run("test4", testDiffTrees4)
	t.Run("test5", testDiffTrees5)

	err = diffTestDelFile()
	if err != nil {
		fmt.Printf("failed to remove test file : %v", err)
	}
}

func diffTestCreateTestDir() error {
	modeDir := uint32(syscall.S_IFDIR | 0644)
	modeFile := uint32(syscall.S_IFREG | 0644)

	dir1, err := diffTestCreateSeafdir(nil)
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}
	diffTestTree1 = dir1
	file1, err := fsmgr.NewSeafile(1, 1, nil)
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v", err)
		return err
	}
	diffTestFileID = file1.FileID
	err = fsmgr.SaveSeafile(diffTestRepoID, file1)
	if err != nil {
		err := fmt.Errorf("failed to save seafile: %v", err)
		return err
	}
	dent1 := fsmgr.SeafDirent{ID: file1.FileID, Name: "file", Mode: modeFile, Size: 1}
	dir2, err := diffTestCreateSeafdir([]*fsmgr.SeafDirent{&dent1})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}
	diffTestTree2 = dir2

	dent2 := fsmgr.SeafDirent{ID: dir1, Name: "dir", Mode: modeDir}
	diffTestDirID1 = dir1
	dir3, err := diffTestCreateSeafdir([]*fsmgr.SeafDirent{&dent2})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}
	diffTestTree3 = dir3

	dent3 := fsmgr.SeafDirent{ID: dir2, Name: "dir", Mode: modeDir}
	diffTestDirID2 = dir2
	dir4, err := diffTestCreateSeafdir([]*fsmgr.SeafDirent{&dent3})
	if err != nil {
		err := fmt.Errorf("failed to get seafdir: %v", err)
		return err
	}
	diffTestTree4 = dir4

	return nil
}

func testDiffTrees1(t *testing.T) {
	var results []interface{}
	opt := &DiffOptions{
		FileCB: diffTestFileCB,
		DirCB:  diffTestDirCB,
		RepoID: diffTestRepoID}
	opt.Data = &results
	DiffTrees([]string{diffTestTree2, diffTestTree1}, opt)
	if len(results) != 1 {
		t.Errorf("data length is %d not 1", len(results))
	}
	var ret = make([]string, len(results))
	for k, v := range results {
		ret[k] = fmt.Sprintf("%s", v)
	}
	if ret[0] != diffTestFileID {
		t.Errorf("result %s != %s", ret[0], diffTestFileID)
	}
}

func testDiffTrees2(t *testing.T) {
	var results []interface{}
	opt := &DiffOptions{
		FileCB: diffTestFileCB,
		DirCB:  diffTestDirCB,
		RepoID: diffTestRepoID}
	opt.Data = &results
	DiffTrees([]string{diffTestTree3, diffTestTree1}, opt)
	if len(results) != 1 {
		t.Errorf("data length is %d not 1", len(results))
	}
	var ret = make([]string, len(results))
	for k, v := range results {
		ret[k] = fmt.Sprintf("%s", v)
	}
	if ret[0] != diffTestDirID1 {
		t.Errorf("result %s != %s", ret[0], diffTestDirID1)
	}

}

func testDiffTrees3(t *testing.T) {
	var results []interface{}
	opt := &DiffOptions{
		FileCB: diffTestFileCB,
		DirCB:  diffTestDirCB,
		RepoID: diffTestRepoID}
	opt.Data = &results
	DiffTrees([]string{diffTestTree4, diffTestTree1}, opt)
	if len(results) != 2 {
		t.Errorf("data length is %d not 1", len(results))
	}

	var ret = make([]string, len(results))
	for k, v := range results {
		ret[k] = fmt.Sprintf("%s", v)
	}
	if ret[0] != diffTestDirID2 {
		t.Errorf("result %s != %s", ret[0], diffTestDirID2)
	}
	if ret[1] != diffTestFileID {
		t.Errorf("result %s != %s", ret[1], diffTestFileID)
	}
}

func testDiffTrees4(t *testing.T) {
	var results []interface{}
	opt := &DiffOptions{
		FileCB: diffTestFileCB,
		DirCB:  diffTestDirCB,
		RepoID: diffTestRepoID}
	opt.Data = &results
	DiffTrees([]string{diffTestTree4, diffTestTree3}, opt)
	if len(results) != 2 {
		t.Errorf("data length is %d not 1", len(results))
	}

	var ret = make([]string, len(results))
	for k, v := range results {
		ret[k] = fmt.Sprintf("%s", v)
	}
	if ret[0] != diffTestDirID2 {
		t.Errorf("result %s != %s", ret[0], diffTestDirID2)
	}
	if ret[1] != diffTestFileID {
		t.Errorf("result %s != %s", ret[1], diffTestFileID)
	}
}

func testDiffTrees5(t *testing.T) {
	var results []interface{}
	opt := &DiffOptions{
		FileCB: diffTestFileCB,
		DirCB:  diffTestDirCB,
		RepoID: diffTestRepoID}
	opt.Data = &results
	DiffTrees([]string{diffTestTree3, diffTestTree2}, opt)
	if len(results) != 1 {
		t.Errorf("data length is %d not 1", len(results))
	}
	var ret = make([]string, len(results))
	for k, v := range results {
		ret[k] = fmt.Sprintf("%s", v)
	}
	if ret[0] != diffTestDirID1 {
		t.Errorf("result %s != %s", ret[0], diffTestDirID1)
	}
}

func diffTestCreateSeafdir(dents []*fsmgr.SeafDirent) (string, error) {
	seafdir, err := fsmgr.NewSeafdir(1, dents)
	if err != nil {
		return "", err
	}
	err = fsmgr.SaveSeafdir(diffTestRepoID, seafdir)
	if err != nil {
		return "", err
	}

	return seafdir.DirID, nil
}

func diffTestDelFile() error {
	err := os.RemoveAll(diffTestSeafileConfPath)
	if err != nil {
		return err
	}

	return nil
}

func diffTestFileCB(ctx context.Context, baseDir string, files []*fsmgr.SeafDirent, data interface{}) error {
	file1 := files[0]
	file2 := files[1]
	results, ok := data.(*[]interface{})
	if !ok {
		err := fmt.Errorf("failed to assert results")
		return err
	}

	if file1 != nil &&
		(file2 == nil || file1.ID != file2.ID) {
		*results = append(*results, file1.ID)
	}

	return nil
}

func diffTestDirCB(ctx context.Context, baseDir string, dirs []*fsmgr.SeafDirent, data interface{}, recurse *bool) error {
	dir1 := dirs[0]
	dir2 := dirs[1]
	results, ok := data.(*[]interface{})
	if !ok {
		err := fmt.Errorf("failed to assert results")
		return err
	}

	if dir1 != nil &&
		(dir2 == nil || dir1.ID != dir2.ID) {
		*results = append(*results, dir1.ID)
	}

	return nil
}
