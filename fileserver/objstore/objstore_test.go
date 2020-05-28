package objstore

import (
	"fmt"
	"os"
	"path"
	"testing"
)

const (
	testFile        = "output.data"
	seafileConfPath = "/tmp/conf"
	seafileDataDir  = "/tmp/conf/seafile-data"
	repoID          = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	objID           = "0401fc662e3bc87a41f299a907c056aaf8322a27"
)

func createFile() error {
	outputFile, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	outputString := "hello world!\n"
	for i := 0; i < 10; i++ {
		outputFile.WriteString(outputString)
	}

	return nil
}

func delFile() error {
	err := os.Remove(testFile)
	if err != nil {
		return err
	}

	err = os.RemoveAll(seafileConfPath)
	if err != nil {
		return err
	}

	return nil
}

func TestMain(m *testing.M) {
	err := createFile()
	if err != nil {
		fmt.Printf("Failed to create test file : %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	err = delFile()
	if err != nil {
		fmt.Printf("Failed to remove test file : %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func testWrite(t *testing.T) {
	inputFile, err := os.Open(testFile)
	if err != nil {
		t.Errorf("Failed to open test file : %v\n", err)
	}
	defer inputFile.Close()

	bend := New(seafileConfPath, seafileDataDir, "commit")
	bend.Write(repoID, objID, inputFile, true)
}

func testRead(t *testing.T) {
	outputFile, err := os.OpenFile(testFile, os.O_WRONLY, 0666)
	if err != nil {
		t.Errorf("Failed to open test file:%v\n", err)
	}
	defer outputFile.Close()

	bend := New(seafileConfPath, seafileDataDir, "commit")
	err = bend.Read(repoID, objID, outputFile)
	if err != nil {
		t.Errorf("Failed to read backend : %s\n", err)
	}
}

func testExists(t *testing.T) {
	bend := New(seafileConfPath, seafileDataDir, "commit")
	ret, _ := bend.Exists(repoID, objID)
	if !ret {
		t.Errorf("File is not exist\n")
	}

	filePath := path.Join(seafileDataDir, "storage", "commit", repoID, objID[:2], objID[2:])
	fileInfo, _ := os.Stat(filePath)
	if fileInfo.Size() != 130 {
		t.Errorf("File is exist, but the size of file is incorrect.\n")
	}
}

func TestObjStore(t *testing.T) {
	testWrite(t)
	testRead(t)
	testExists(t)
}
