package objstore

import (
	"bufio"
	"fmt"
	"os"
	"testing"
)

const (
	testfile        = "output.data"
	seafileConfPath = "/tmp/conf"
	seafileDataDir  = "/tmp/conf/seafile-data"
	repo_id         = "b1f2ad61-9164-418a-a47f-ab805dbd5694"
	obj_id          = "0401fc662e3bc87a41f299a907c056aaf8322a27"
)

func createFile() error {
	outputFile, err := os.OpenFile(testfile, os.O_WRONLY|os.O_CREATE, 0666)
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
	err := os.Remove(testfile)
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
	inputFile, err := os.Open(testfile)
	if err != nil {
		t.Errorf("Failed to open test file : %v\n", err)
		t.Fail()
	}
	defer inputFile.Close()

	inputReader := bufio.NewReader(inputFile)

	bend := New(seafileConfPath, seafileDataDir, "commit")
	bend.write(repo_id, obj_id, inputReader, true)
}

func testRead(t *testing.T) {
	outputFile, err := os.OpenFile(testfile, os.O_WRONLY, 0666)
	if err != nil {
		t.Errorf("Failed to open test file:%v\n", err)
		t.Fail()
	}
	defer outputFile.Close()

	outputWriter := bufio.NewWriter(outputFile)

	bend := New(seafileConfPath, seafileDataDir, "commit")
	err = bend.read(repo_id, obj_id, outputWriter)
	if err != nil {
		t.Errorf("Failed to read backend : %s\n", err)
		t.Fail()
	}
	outputWriter.Flush()
}

func testExists(t *testing.T) {
	bend := New(seafileConfPath, seafileDataDir, "commit")
	ret, _ := bend.exists(repo_id, obj_id)
	if !ret {
		t.Errorf("File is not exist\n")
		t.Fail()
	}
}

func TestObjStore(t *testing.T) {
	testWrite(t)
	testRead(t)
	testExists(t)
}
