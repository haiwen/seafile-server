package fsmgr

import (
	"fmt"
	"os"
	"testing"
)

const (
	seafileConfPath = "/tmp/conf"
	seafileDataDir  = "/tmp/conf/seafile-data"
	repoID          = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	fileID          = "0401fc662e3bc87a41f299a907c056aaf8322a26"
	dirID           = "0401fc662e3bc87a41f299a907c056aaf8322a27"
)

func createFile() error {
	seafile := new(Seafile)
	seafile.Version = 1
	seafile.FileSize = 100
	for i := 0; i < 2; i++ {
		blkshal := fileID
		seafile.BlkIDs = append(seafile.BlkIDs, blkshal)
	}

	err := SaveSeafile(repoID, fileID, seafile)
	if err != nil {
		return err
	}

	seafdir := new(SeafDir)
	seafdir.Version = 1
	for i := 0; i < 2; i++ {
		dirent := SeafDirent{ID: dirID}
		seafdir.Entries = append(seafdir.Entries, dirent)
	}
	err = SaveSeafdir(repoID, dirID, seafdir)
	if err != nil {
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
	Init(seafileConfPath, seafileDataDir)
	err := createFile()
	if err != nil {
		fmt.Printf("Failed to create test file : %v.\n", err)
		os.Exit(1)
	}
	code := m.Run()
	err = delFile()
	if err != nil {
		fmt.Printf("Failed to remove test file : %v\n", err)
	}
	os.Exit(code)
}

func TestGetSeafile(t *testing.T) {
	exists, err := Exists(repoID, fileID)
	if !exists {
		t.Errorf("seafile is not exists : %v.\n", err)
	}
	seafile, err := GetSeafile(repoID, fileID)
	if err != nil || seafile == nil {
		t.Errorf("Failed to get seafile : %v.\n", err)
		t.FailNow()
	}

	for _, v := range seafile.BlkIDs {
		if v != fileID {
			t.Errorf("Wrong file content.\n")
		}
	}
}

func TestGetSeafdir(t *testing.T) {
	exists, err := Exists(repoID, dirID)
	if !exists {
		t.Errorf("seafile is not exists : %v.\n", err)
	}
	seafdir, err := GetSeafdir(repoID, dirID)
	if err != nil || seafdir == nil {
		t.Errorf("Failed to get seafdir : %v.\n", err)
		t.FailNow()
	}

	for _, v := range seafdir.Entries {
		if v.ID != dirID {
			t.Errorf("Wrong file content.\n")
		}
	}

}
