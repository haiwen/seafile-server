package blockmgr

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"testing"
)

const (
	blockID         = "0401fc662e3bc87a41f299a907c056aaf8322a27"
	repoID          = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	seafileConfPath = "/tmp/conf"
	seafileDataDir  = "/tmp/conf/seafile-data"
	testFile        = "output.data"
)

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

func testBlockRead(t *testing.T) {
	var buf bytes.Buffer
	err := Read(repoID, blockID, &buf)
	if err != nil {
		t.Errorf("Failed to read block.\n")
	}
}

func testBlockWrite(t *testing.T) {
	inputFile, err := os.Open(testFile)
	if err != nil {
		t.Errorf("Failed to open test file : %v\n", err)
	}
	defer inputFile.Close()

	err = Write(repoID, blockID, inputFile)
	if err != nil {
		t.Errorf("Failed to write block.\n")
	}
}

func testBlockExists(t *testing.T) {
	ret := Exists(repoID, blockID)
	if !ret {
		t.Errorf("Block is not exist\n")
	}

	filePath := path.Join(seafileDataDir, "storage", "blocks", repoID, blockID[:2], blockID[2:])
	fileInfo, _ := os.Stat(filePath)
	if fileInfo.Size() != 130 {
		t.Errorf("Block is exist, but the size of file is incorrect.\n")
	}

}

func TestBlock(t *testing.T) {
	Init(seafileConfPath, seafileDataDir)
	testBlockWrite(t)
	testBlockRead(t)
	testBlockExists(t)
}
