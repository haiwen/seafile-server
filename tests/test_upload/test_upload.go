package main

import "fmt"
import "io"
import "sync"
import "flag"
import "log"
import "encoding/json"
import "bytes"
import "net/http"
import "mime/multipart"
import "path/filepath"

import "gopkg.in/ini.v1"
import "github.com/haiwen/seafile-server/fileserver/searpc"

type Options struct {
	server    string
	username  string
	password  string
	repoID    string
	threadNum int
}

var confPath string
var rpcPipePath string
var options Options
var rpcclient *searpc.Client

func init() {
	flag.StringVar(&confPath, "c", "", "config file path")
	flag.StringVar(&rpcPipePath, "p", "", "rpc pipe path")
}

func main() {
	flag.Parse()

	pipePath := filepath.Join(rpcPipePath, "seafile.sock")
	rpcclient = searpc.Init(pipePath, "seafserv-threaded-rpcserver")

	config, err := ini.Load(confPath)
	if err != nil {
		log.Fatalf("Failed to load config file: %v", err)
	}
	section, err := config.GetSection("account")
	if err != nil {
		log.Fatal("No account section in config file.")
	}

	key, err := section.GetKey("server")
	if err == nil {
		options.server = key.String()
	}

	key, err = section.GetKey("username")
	if err == nil {
		options.username = key.String()
	}

	key, err = section.GetKey("password")
	if err == nil {
		options.password = key.String()
	}
	key, err = section.GetKey("repoid")
	if err == nil {
		options.repoID = key.String()
	}
	key, err = section.GetKey("thread_num")
	if err == nil {
		options.threadNum, _ = key.Int()
	}

	objID := "{\"parent_dir\":\"/\"}"
	token, err := rpcclient.Call("seafile_web_get_access_token", options.repoID, objID, "upload", options.username, false)
	if err != nil {
		log.Fatal("Failed to get web access token\n")
	}
	accessToken, _ := token.(string)

	url := fmt.Sprintf("%s:8082/upload-api/%s", options.server, accessToken)
	content := []byte("123456")

	var group sync.WaitGroup
	for i := 0; i < options.threadNum; i++ {
		group.Add(1)
		go func(i int) {
			values := make(map[string]io.Reader)
			values["file"] = bytes.NewReader(content)
			values["parent_dir"] = bytes.NewBuffer([]byte("/"))
			// values["relative_path"] = bytes.NewBuffer([]byte(relativePath))
			values["replace"] = bytes.NewBuffer([]byte("0"))
			form, contentType, err := createForm(values, "111.md")
			if err != nil {
				log.Fatal("Failed to create multipart form: %v", err)
			}
			headers := make(map[string][]string)
			headers["Content-Type"] = []string{contentType}
			// headers["Authorization"] = []string{"Token " + accessToken.(string)}
			status, body, err := HttpCommon("POST", url, headers, form)

			log.Printf("[%d]upload status: %d return body: %s error: %v\n", i, status, string(body), err)
			group.Done()
		}(i)
	}
	group.Wait()
}

func createForm(values map[string]io.Reader, name string) (io.Reader, string, error) {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	defer w.Close()

	for k, v := range values {
		var fw io.Writer
		var err error
		if k == "file" {
			if fw, err = w.CreateFormFile(k, name); err != nil {
				return nil, "", err
			}
		} else {
			if fw, err = w.CreateFormField(k); err != nil {
				return nil, "", err
			}
		}
		if _, err = io.Copy(fw, v); err != nil {
			return nil, "", err
		}
	}

	return buf, w.FormDataContentType(), nil
}

func HttpCommon(method, url string, header map[string][]string, reader io.Reader) (int, []byte, error) {
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return -1, nil, err
	}
	req.Header = header

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusNotFound {
		return rsp.StatusCode, nil, fmt.Errorf("url %s not found", url)
	}
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return rsp.StatusCode, nil, err
	}

	return rsp.StatusCode, body, nil
}

func getToken() string {
	url := fmt.Sprintf("%s:8000/api2/auth-token/", options.server)
	header := make(map[string][]string)
	header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	data := []byte(fmt.Sprintf("username=%s&password=%s", options.username, options.password))
	_, body, err := HttpCommon("POST", url, header, bytes.NewReader(data))
	if err != nil {
		return ""
	}
	tokenMap := make(map[string]interface{})
	err = json.Unmarshal(body, &tokenMap)
	if err != nil {
		return ""
	}
	token, _ := tokenMap["token"].(string)
	return token
}
