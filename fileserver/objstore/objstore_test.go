package objstore

import (
	"bufio"
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

func TestCreateFile(t *testing.T) {
	outputFile, err := os.OpenFile(testfile, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		t.Log("Failed to create test file")
		t.Fail()
	}
	defer outputFile.Close()

	outputWriter := bufio.NewWriter(outputFile)
	outputString := "hello world!\n"
	for i := 0; i < 10; i++ {
		outputWriter.WriteString(outputString)
	}
	outputWriter.Flush()
}

func TestWrite(t *testing.T) {
	inputFile, err := os.Open(testfile)
	if err != nil {
		t.Log("Failed to open test file")
		t.Fail()
	}
	defer inputFile.Close()

	inputReader := bufio.NewReader(inputFile)

	bend := New(seafileConfPath, seafileDataDir, "commit")
	bend.write(repo_id, obj_id, inputReader, true)
}

func TestRead(t *testing.T) {
	outputFile, err := os.OpenFile(testfile, os.O_WRONLY, 0666)
	if err != nil {
		t.Log("Failed to open test file")
		t.Fail()
	}
	defer outputFile.Close()

	outputWriter := bufio.NewWriter(outputFile)

	bend := New(seafileConfPath, seafileDataDir, "commit")
	err = bend.read(repo_id, obj_id, outputWriter)
	if err != nil {
		t.Log("Failed to read backend")
		t.Fail()
	}
	outputWriter.Flush()
}

func TestExists(t *testing.T) {
	bend := New(seafileConfPath, seafileDataDir, "commit")
	ret, _ := bend.exists(repo_id, obj_id)
	if !ret {
		t.Log("File is not exist")
		t.Fail()
	}
}

func TestDelFile(t *testing.T) {
	err := os.Remove(testfile)
	if err != nil {
		t.Log("Failed to remove test file")
		t.Fail()
	}

	err = os.RemoveAll(seafileConfPath)
	if err != nil {
		t.Log("Failed to remove test file")
		t.Fail()
	}
}
