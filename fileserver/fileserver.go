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
	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/searpc"
	"github.com/haiwen/seafile-server/fileserver/share"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/ini.v1"
)

var dataDir, absDataDir string
var centralDir string
var logFile, absLogFile string
var rpcPipePath string

var dbType string
var groupTableName string
var cloudMode bool
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
	flag.StringVar(&centralDir, "F", "", "central config directory")
	flag.StringVar(&dataDir, "d", "", "seafile data directory")
	flag.StringVar(&logFile, "l", "", "log file path")
	flag.StringVar(&rpcPipePath, "p", "", "rpc pipe path")
}

func loadCcnetDB() {
	ccnetConfPath := filepath.Join(centralDir, "ccnet.conf")
	config, err := ini.Load(ccnetConfPath)
	if err != nil {
		log.Fatalf("Failed to load ccnet.conf: %v", err)
	}

	section, err := config.GetSection("Database")
	if err != nil {
		log.Fatal("No database section in ccnet.conf.")
	}

	var dbEngine string = "sqlite"
	key, err := section.GetKey("ENGINE")
	if err == nil {
		dbEngine = key.String()
	}

	if strings.EqualFold(dbEngine, "mysql") {
		if key, err = section.GetKey("HOST"); err != nil {
			log.Fatal("No database host in ccnet.conf.")
		}
		host := key.String()
		if key, err = section.GetKey("USER"); err != nil {
			log.Fatal("No database user in ccnet.conf.")
		}
		user := key.String()
		if key, err = section.GetKey("PASSWD"); err != nil {
			log.Fatal("No database password in ccnet.conf.")
		}
		password := key.String()
		if key, err = section.GetKey("DB"); err != nil {
			log.Fatal("No database db_name in ccnet.conf.")
		}
		dbName := key.String()
		port := 3306
		if key, err = section.GetKey("PORT"); err == nil {
			port, _ = key.Int()
		}
		unixSocket := ""
		if key, err = section.GetKey("UNIX_SOCKET"); err == nil {
			unixSocket = key.String()
		}
		useTLS := false
		if key, err = section.GetKey("USE_SSL"); err == nil {
			useTLS, _ = key.Bool()
		}
		var dsn string
		if unixSocket == "" {
			dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t", user, password, host, port, dbName, useTLS)
		} else {
			dsn = fmt.Sprintf("%s:%s@unix(%s)/%s", user, password, unixSocket, dbName)
		}
		ccnetDB, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
	} else if strings.EqualFold(dbEngine, "sqlite") {
		ccnetDBPath := filepath.Join(centralDir, "groupmgr.db")
		ccnetDB, err = sql.Open("sqlite3", ccnetDBPath)
		if err != nil {
			log.Fatalf("Failed to open database %s: %v", ccnetDBPath, err)
		}
	} else {
		log.Fatalf("Unsupported database %s.", dbEngine)
	}
}

func loadSeafileDB() {
	var seafileConfPath string
	seafileConfPath = filepath.Join(centralDir, "seafile.conf")

	config, err := ini.Load(seafileConfPath)
	if err != nil {
		log.Fatalf("Failed to load seafile.conf: %v", err)
	}

	section, err := config.GetSection("database")
	if err != nil {
		log.Fatal("No database section in seafile.conf.")
	}

	var dbEngine string = "sqlite"
	key, err := section.GetKey("type")
	if err == nil {
		dbEngine = key.String()
	}
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
		seafileDBPath := filepath.Join(absDataDir, "seafile.db")
		seafileDB, err = sql.Open("sqlite3", seafileDBPath)
		if err != nil {
			log.Fatalf("Failed to open database %s: %v", seafileDBPath, err)
		}
	} else {
		log.Fatalf("Unsupported database %s.", dbEngine)
	}
	dbType = dbEngine
}

func loadFileServerOptions() {
	var seafileConfPath string
	seafileConfPath = filepath.Join(centralDir, "seafile.conf")

	config, err := ini.Load(seafileConfPath)
	if err != nil {
		log.Fatalf("Failed to load seafile.conf: %v", err)
	}
	cloudMode = false
	if section, err := config.GetSection("general"); err == nil {
		if key, err := section.GetKey("cloud_mode"); err == nil {
			cloudMode, _ = key.Bool()
		}
	}

	initDefaultOptions()
	if section, err := config.GetSection("fileserver"); err == nil {
		if key, err := section.GetKey("host"); err == nil {
			options.host = key.String()
		}
		if key, err := section.GetKey("port"); err == nil {
			port, err := key.Uint()
			if err == nil {
				options.port = uint32(port)
			}
		}
		if key, err := section.GetKey("max_indexing_threads"); err == nil {
			threads, err := key.Uint()
			if err == nil {
				options.maxIndexingThreads = uint32(threads)
			}
		}
		if key, err := section.GetKey("fixed_block_size"); err == nil {
			blkSize, err := key.Uint64()
			if err == nil {
				options.fixedBlockSize = blkSize
			}
		}
		if key, err := section.GetKey("web_token_expire_time"); err == nil {
			expire, err := key.Uint()
			if err == nil {
				options.webTokenExpireTime = uint32(expire)
			}
		}
		if key, err := section.GetKey("cluster_shared_temp_file_mode"); err == nil {
			fileMode, err := key.Uint()
			if err == nil {
				options.clusterSharedTempFileMode = uint32(fileMode)
			}
		}
	}

	ccnetConfPath := filepath.Join(centralDir, "ccnet.conf")
	config, err = ini.Load(ccnetConfPath)
	if err != nil {
		log.Fatalf("Failed to load ccnet.conf: %v", err)
	}
	groupTableName = "Group"
	if section, err := config.GetSection("GROUP"); err == nil {
		if key, err := section.GetKey("TABLE_NAME"); err == nil {
			groupTableName = key.String()
		}
	}
}

func initDefaultOptions() {
	options.host = "0.0.0.0"
	options.port = 8082
	options.maxDownloadDirSize = 100 * (1 << 20)
	options.fixedBlockSize = 1 << 23
	options.maxIndexingThreads = 1
	options.webTokenExpireTime = 7200
	options.clusterSharedTempFileMode = 0600
}

func main() {
	flag.Parse()

	if centralDir == "" {
		log.Fatal("central config directory must be specified.")
	}
	_, err := os.Stat(centralDir)
	if os.IsNotExist(err) {
		log.Fatalf("central config directory %s doesn't exist: %v.", centralDir, err)
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

	fsmgr.Init(centralDir, dataDir)

	blockmgr.Init(centralDir, dataDir)

	commitmgr.Init(centralDir, dataDir)

	share.Init(ccnetDB, seafileDB, groupTableName, cloudMode)

	rpcClientInit()

	fileopInit()

	syncAPIInit()

	sizeSchedulerInit()

	initUpload()

	router := newHTTPRouter()

	log.Print("Seafile file server started.")

	addr := fmt.Sprintf("%s:%d", options.host, options.port)
	err = http.ListenAndServe(addr, router)
	if err != nil {
		log.Printf("File server exiting: %v", err)
	}
}

var rpcclient *searpc.Client

func rpcClientInit() {
	var pipePath string
	if rpcPipePath != "" {
		pipePath = filepath.Join(rpcPipePath, "seafile.sock")
	} else {
		pipePath = filepath.Join(absDataDir, "seafile.sock")
	}
	rpcclient = searpc.Init(pipePath, "seafserv-threaded-rpcserver")
}

func newHTTPRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/protocol-version", handleProtocolVersion)
	r.Handle("/files/{.*}/{.*}", appHandler(accessCB))
	r.Handle("/blks/{.*}/{.*}", appHandler(accessBlksCB))
	r.Handle("/zip/{.*}", appHandler(accessZipCB))
	r.Handle("/upload-api/{.*}", appHandler(uploadAPICB))
	r.Handle("/upload-aj/{.*}", appHandler(uploadAjaxCB))
	r.Handle("/update-api/{.*}", appHandler(updateAPICB))
	r.Handle("/update-aj/{.*}", appHandler(updateAjaxCB))
	r.Handle("/upload-blks-api/{.*}", appHandler(uploadBlksAPICB))
	r.Handle("/upload-raw-blks-api/{.*}", appHandler(uploadRawBlksAPICB))
	// file syncing api
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/permission-check/",
		appHandler(permissionCheckCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/commit/{HEAD:HEAD\\/?}",
		appHandler(headCommitOperCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/commit/{id:[\\da-z]{40}}",
		appHandler(commitOperCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/block/{id:[\\da-z]{40}}",
		appHandler(blockOperCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/fs-id-list/",
		appHandler(getFsObjIDCB))
	r.Handle("/repo/head-commits-multi/",
		appHandler(headCommitsMultiCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/pack-fs/",
		appHandler(packFSCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/check-fs/",
		appHandler(checkFSCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/check-blocks/",
		appHandler(checkBlockCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/recv-fs/",
		appHandler(recvFSCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/quota-check/",
		appHandler(getCheckQuotaCB))

	// seadrive api
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/block-map/{id:[\\da-z]{40}}",
		appHandler(getBlockMapCB))
	r.Handle("/accessible-repos", appHandler(getAccessibleRepoListCB))
	return r
}

func handleProtocolVersion(rsp http.ResponseWriter, r *http.Request) {
	io.WriteString(rsp, "{\"version\": 2}")
}

type appError struct {
	Error   error
	Message string
	Code    int
}

type appHandler func(http.ResponseWriter, *http.Request) *appError

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil {
		if e.Error != nil && e.Code == http.StatusInternalServerError {
			log.Printf("path %s internal server error: %v\n", r.URL.Path, e.Error)
		}
		http.Error(w, e.Message, e.Code)
	}
}
