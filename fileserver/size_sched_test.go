package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"github.com/haiwen/seafile-server/fileserver/searpc"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"testing"
	"time"
)

var repoID string
var client *searpc.Client

const (
	user           = "seafile"
	password       = "seafile"
	host           = "127.0.0.1"
	port           = 3306
	dbName         = "seafile-db"
	useTLS         = false
	seafileDataDir = "/root/conf/seafile-data"
	repoName       = "repo_size"
	userName       = "seafile@seafile.com"
	encVersion     = 2
	pipePath       = "/root/runtime/seafile.sock"
	service        = "seafserv-threaded-rpcserver"
	testFile       = "testfile"
	updateFile     = "updatefile"
)

func createRepo() string {
	repoName := "repo_size"
	id, err := client.Call("seafile_create_repo", repoName, "", userName, nil, encVersion)
	if err != nil {
		fmt.Printf("failed to create repo")
		os.Exit(1)
	}
	if id == nil {
		fmt.Printf("repo id is nil")
		os.Exit(1)
	}

	repoid, ok := id.(string)
	if !ok {
		fmt.Printf("returned value isn't repo id")
	}
	return repoid
}

func delRepo() {
	_, err := client.Call("seafile_destroy_repo", repoID)
	if err != nil {
		fmt.Printf("failed to del repo")
		os.Exit(1)
	}
}

func createFile() error {
	outputFile1, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer outputFile1.Close()

	outputString := "hello world!\n"
	for i := 0; i < 1; i++ {
		outputFile1.WriteString(outputString)
	}

	outputFile2, err := os.OpenFile(updateFile, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer outputFile2.Close()

	for i := 0; i < 2; i++ {
		outputFile2.WriteString(outputString)
	}

	return nil
}

func delFile() error {
	err := os.Remove(testFile)
	if err != nil {
		return err
	}

	err = os.Remove(updateFile)
	if err != nil {
		return err
	}

	return nil
}

func TestMain(m *testing.M) {
	absDataDir = seafileDataDir
	client = searpc.Init(pipePath, service)
	repoID = createRepo()

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t", user, password, host, port, dbName, useTLS)
	seafDB, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("failed to open database: %v", err)
	}
	seafileDB = seafDB
	err = createFile()
	if err != nil {
		fmt.Printf("failed to create test file: %v", err)
	}

	code := m.Run()

	err = delFile()
	if err != nil {
		fmt.Printf("failed to delete test file: %v", err)
	}

	delRepo()
	os.Exit(code)
}

func postFile(url, filename string, isUpdate bool) error {
	file, err := os.Open(filename)
	if err != nil {
		err := fmt.Errorf("failed to open file: %v", err)
		return err
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("file", "testfile")
	if err != nil {
		fmt.Errorf("failed to create form file: %v", err)
		return err
	}
	_, err = io.Copy(formFile, file)
	if err != nil {
		err := fmt.Errorf("failed to copy file")
		return err
	}

	if isUpdate {
		writer.WriteField("target_file", "/testfile")
	} else {
		writer.WriteField("parent_dir", "/")
	}

	writer.Close()
	req, err := http.NewRequest("POST", url, buf)
	if err != nil {
		err := fmt.Errorf("failed to new post request: %v", err)
		return err
	}

	req.Header.Add("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		err := fmt.Errorf("failed to send request: %v", err)
		return err
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err := fmt.Errorf("failed to read response: %v", err)
		return err
	}

	_ = content

	return nil
}

func TestComputeRepoSize(t *testing.T) {
	// add file
	objID := "{\"parent_dir\":\"/\"}"
	accessToken, err := client.Call("seafile_web_get_access_token", repoID, objID, "upload", userName, 1)
	if err != nil {
		t.Errorf("failed to get web access token: %v", err)
	}
	token, ok := accessToken.(string)
	if !ok {
		t.Errorf("failed to assert access token")
	}

	url := "http://127.0.0.1:8082/upload-api/" + token
	err = postFile(url, testFile, false)
	if err != nil {
		t.Errorf("failed to post file:%v", err)
	}
	time.Sleep(1 * time.Second)

	info, err := getOldRepoInfo(repoID)
	if err != nil || info == nil {
		t.Errorf("failed to get old repo info: %v", err)
	}
	fileInfo, err := os.Stat(testFile)
	if err != nil {
		t.Errorf("failed to stat file")
	}
	if info.Size != fileInfo.Size() {
		t.Errorf("failed to compute repo size")
	}

	// update file
	accessToken, err = client.Call("seafile_web_get_access_token", repoID, objID, "update", userName, 1)
	if err != nil {
		t.Errorf("failed to get web access token: %v", err)
	}
	token, ok = accessToken.(string)
	if !ok {
		t.Errorf("failed to assert access token")
	}

	url = "http://127.0.0.1:8082/update-api/" + token
	err = postFile(url, updateFile, true)
	if err != nil {
		t.Errorf("failed to update file:%v", err)
	}
	time.Sleep(1 * time.Second)

	info, err = getOldRepoInfo(repoID)
	if err != nil || info == nil {
		t.Errorf("failed to get old repo info: %v", err)
	}
	fileInfo, err = os.Stat(updateFile)
	if err != nil {
		t.Errorf("failed to stat file")
	}
	if info.Size != fileInfo.Size() {
		t.Errorf("failed to compute repo size")
	}

}
