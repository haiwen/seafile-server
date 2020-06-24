// Main package for Seafile file server.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/searpc"
	"gopkg.in/ini.v1"
)

var ccnetDir string
var dataDir, absDataDir string
var logFile, absLogFile string
var rpcPipePath string

var dbType string
var seafileDB, ccnetDB *sql.DB

// when SQLite is used, user and group db are separated.
var userDB, groupDB *sql.DB

type fileServerOptions struct {
	host               string
	port               uint32
	maxUploadSize      uint64
	maxDownloadDirSize uint64
	// Block size for indexing uploaded files
	fixedBlockSize uint64
	// Maximum number of goroutines to index uploaded files
	maxIndexingThreads uint32
	webTokenExpireTime uint32
	// File mode for temp files
	clusterSharedTempFileMode uint32
	windowsEncoding           string
	// Timeout for fs-id-list requests.
	fsIDListRequestTimeout uint32
}

var options fileServerOptions

func init() {
	flag.StringVar(&ccnetDir, "c", "", "ccnet config directory")
	flag.StringVar(&dataDir, "d", "", "seafile data directory")
	flag.StringVar(&logFile, "l", "", "log file path")
	flag.StringVar(&rpcPipePath, "p", "", "rpc pipe path")
}

func loadCcnetDB() {
	// TODO: load database configurations from ccnet.conf and create ccnetDB or userDB/groupDB
}

func loadSeafileDB() {
	seafileConfPath := filepath.Join(absDataDir, "seafile.conf")
	config, err := ini.Load(seafileConfPath)
	if err != nil {
		log.Fatalf("Failed to load seafile.conf: %v", err)
	}

	section, err := config.GetSection("database")
	if err != nil {
		log.Fatal("No database section in seafile.conf.")
	}
	key, err := section.GetKey("type")
	if err != nil {
		log.Fatal("No database type in seafile.conf.")
	}
	dbEngine := key.String()
	if strings.EqualFold(dbEngine, "mysql") {
		if key, err = section.GetKey("host"); err != nil {
			log.Fatal("No database host in seafile.conf.")
		}
		host := key.String()
		if key, err = section.GetKey("user"); err != nil {
			log.Fatal("No database user in seafile.conf.")
		}
		user := key.String()
		if key, err = section.GetKey("password"); err != nil {
			log.Fatal("No database password in seafile.conf.")
		}
		password := key.String()
		if key, err = section.GetKey("db_name"); err != nil {
			log.Fatal("No database db_name in seafile.conf.")
		}
		dbName := key.String()
		port := 3306
		if key, err = section.GetKey("port"); err == nil {
			port, _ = key.Int()
		}
		unixSocket := ""
		if key, err = section.GetKey("unix_socket"); err == nil {
			unixSocket = key.String()
		}
		useTLS := false
		if key, err = section.GetKey("use_ssl"); err == nil {
			useTLS, _ = key.Bool()
		}

		var dsn string
		if unixSocket == "" {
			dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t", user, password, host, port, dbName, useTLS)
		} else {
			dsn = fmt.Sprintf("%s:%s@unix(%s)/%s", user, password, unixSocket, dbName)
		}

		seafileDB, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
	} else if strings.EqualFold(dbEngine, "sqlite") {
		// TODO: create sqlite database
	} else {
		log.Fatalf("Unsupported database %s.", dbEngine)
	}
	dbType = dbEngine
}

func loadFileServerOptions() {
	// TODO: load fileserver options from seafile.conf
}

func main() {
	flag.Parse()

	if ccnetDir == "" {
		log.Fatal("ccnet config directory must be specified.")
	}
	_, err := os.Stat(ccnetDir)
	if os.IsNotExist(err) {
		log.Fatalf("ccnet config directory %s doesn't exist: %v.", ccnetDir, err)
	}
	loadCcnetDB()

	if dataDir == "" {
		log.Fatal("seafile data directory must be specified.")
	}
	_, err = os.Stat(dataDir)
	if os.IsNotExist(err) {
		log.Fatalf("seafile data directory %s doesn't exist: %v.", dataDir, err)
	}
	absDataDir, err = filepath.Abs(dataDir)
	if err != nil {
		log.Fatalf("Failed to convert seafile data dir to absolute path: %v.", err)
	}
	loadSeafileDB()
	loadFileServerOptions()

	if logFile == "" {
		absLogFile = filepath.Join(absDataDir, "seafile.log")
		fp, err := os.OpenFile(absLogFile, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open or create log file: %v", err)
		}
		log.SetOutput(fp)
	} else if logFile != "-" {
		absLogFile, err = filepath.Abs(logFile)
		if err != nil {
			log.Fatalf("Failed to convert log file path to absolute path: %v", err)
		}
		fp, err := os.OpenFile(absLogFile, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open or create log file: %v", err)
		}
		log.SetOutput(fp)
	}
	// When logFile is "-", use default output (StdOut)

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	repomgr.Init(seafileDB)

	fsmgr.Init(ccnetDir, dataDir)

	blockmgr.Init(ccnetDir, dataDir)

	commitmgr.Init(ccnetDir, dataDir)

	rpcClientInit()

	registerHTTPHandlers(client)

	log.Print("Seafile file server started.")

	err = http.ListenAndServe("127.0.0.1:8082", nil)
	if err != nil {
		log.Printf("File server exiting: %v", err)
	}
}

var client *searpc.Client

func rpcClientInit() {
	var pipePath string
	if rpcPipePath != "" {
		pipePath = filepath.Join(rpcPipePath, "seafile.sock")
	} else {
		pipePath = filepath.Join(absDataDir, "seafile.sock")
	}
	client = searpc.Init(pipePath, "seafserv-threaded-rpcserver")
}

func registerHTTPHandlers(client *searpc.Client) {
	http.HandleFunc("/protocol-version", handleProtocolVersion)
	http.HandleFunc("/", handleHttpRequest)
}

func handleProtocolVersion(rsp http.ResponseWriter, r *http.Request) {
	io.WriteString(rsp, "{\"version\": 2}")
}
