// Main package for Seafile file server.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/searpc"
	"github.com/haiwen/seafile-server/fileserver/share"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"

	"net/http/pprof"
)

var dataDir, absDataDir string
var centralDir string
var logFile, absLogFile string
var rpcPipePath string
var pidFilePath string
var logFp *os.File

var dbType string
var groupTableName string
var cloudMode bool
var seafileDB, ccnetDB *sql.DB

// when SQLite is used, user and group db are separated.
var userDB, groupDB *sql.DB

// Storage unit.
const (
	KB = 1000
	MB = 1000000
	GB = 1000000000
	TB = 1000000000000
)

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
	defaultQuota           int64
	// Profile password
	profilePassword string
	enableProfiling bool
}

var options fileServerOptions

func init() {
	flag.StringVar(&centralDir, "F", "", "central config directory")
	flag.StringVar(&dataDir, "d", "", "seafile data directory")
	flag.StringVar(&logFile, "l", "", "log file path")
	flag.StringVar(&rpcPipePath, "p", "", "rpc pipe path")
	flag.StringVar(&pidFilePath, "P", "", "pid file path")

	log.SetFormatter(&LogFormatter{})
}

const (
	timestampFormat = "[2006-01-02 15:04:05] "
)

type LogFormatter struct{}

func (f *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	buf := make([]byte, 0, len(timestampFormat)+len(entry.Message)+1)
	buf = entry.Time.AppendFormat(buf, timestampFormat)
	buf = append(buf, entry.Message...)
	buf = append(buf, '\n')
	return buf, nil
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
	seafileConfPath := filepath.Join(centralDir, "seafile.conf")

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

func parseQuota(quotaStr string) int64 {
	var quota int64
	var multiplier int64 = GB
	if end := strings.Index(quotaStr, "kb"); end > 0 {
		multiplier = KB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "mb"); end > 0 {
		multiplier = MB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "gb"); end > 0 {
		multiplier = GB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "tb"); end > 0 {
		multiplier = TB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else {
		quotaInt, err := strconv.ParseInt(quotaStr, 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	}

	return quota
}

func loadFileServerOptions() {
	seafileConfPath := filepath.Join(centralDir, "seafile.conf")

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

	if section, err := config.GetSection("httpserver"); err == nil {
		parseFileServerSection(section)
	}
	if section, err := config.GetSection("fileserver"); err == nil {
		parseFileServerSection(section)
	}

	if section, err := config.GetSection("quota"); err == nil {
		if key, err := section.GetKey("default"); err == nil {
			quotaStr := key.String()
			options.defaultQuota = parseQuota(quotaStr)
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

func parseFileServerSection(section *ini.Section) {
	if key, err := section.GetKey("host"); err == nil {
		options.host = key.String()
	}
	if key, err := section.GetKey("port"); err == nil {
		port, err := key.Uint()
		if err == nil {
			options.port = uint32(port)
		}
	}
	if key, err := section.GetKey("max_upload_size"); err == nil {
		size, err := key.Uint()
		if err == nil {
			options.maxUploadSize = uint64(size) * (1 << 20)
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
	if key, err := section.GetKey("enable_profiling"); err == nil {
		options.enableProfiling, _ = key.Bool()
	}
	if options.enableProfiling {
		if key, err := section.GetKey("profile_password"); err == nil {
			options.profilePassword = key.String()
		} else {
			log.Fatal("password of profiling must be specified.")
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
	options.defaultQuota = InfiniteQuota
}

func writePidFile(pid_file_path string) error {
	file, err := os.OpenFile(pid_file_path, os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		return err
	}
	defer file.Close()

	pid := os.Getpid()
	str := fmt.Sprintf("%d", pid)
	_, err = file.Write([]byte(str))

	if err != nil {
		return err
	}
	return nil
}

func removePidfile(pid_file_path string) error {
	err := os.Remove(pid_file_path)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()

	if centralDir == "" {
		log.Fatal("central config directory must be specified.")
	}

	if pidFilePath != "" {
		if writePidFile(pidFilePath) != nil {
			log.Fatal("write pid file failed.")
		}
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
		absLogFile = filepath.Join(absDataDir, "fileserver.log")
		fp, err := os.OpenFile(absLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open or create log file: %v", err)
		}
		logFp = fp
		log.SetOutput(fp)
	} else if logFile != "-" {
		absLogFile, err = filepath.Abs(logFile)
		if err != nil {
			log.Fatalf("Failed to convert log file path to absolute path: %v", err)
		}
		fp, err := os.OpenFile(absLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open or create log file: %v", err)
		}
		logFp = fp
		log.SetOutput(fp)
	}
	// When logFile is "-", use default output (StdOut)

	log.SetLevel(log.InfoLevel)

	if absLogFile != "" {
		errorLogFile := filepath.Join(filepath.Dir(absLogFile), "fileserver-error.log")
		fp, err := os.OpenFile(errorLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open or create error log file: %v", err)
		}
		syscall.Dup3(int(fp.Fd()), int(os.Stderr.Fd()), 0)
	}

	repomgr.Init(seafileDB)

	fsmgr.Init(centralDir, dataDir)

	blockmgr.Init(centralDir, dataDir)

	commitmgr.Init(centralDir, dataDir)

	share.Init(ccnetDB, seafileDB, groupTableName, cloudMode)

	rpcClientInit()

	fileopInit()

	syncAPIInit()

	sizeSchedulerInit()

	virtualRepoInit()

	initUpload()

	router := newHTTPRouter()

	go handleSignals()
	go handleUser1Singal()

	log.Print("Seafile file server started.")

	addr := fmt.Sprintf("%s:%d", options.host, options.port)
	err = http.ListenAndServe(addr, router)
	if err != nil {
		log.Printf("File server exiting: %v", err)
	}
}

func handleSignals() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-signalChan
	removePidfile(pidFilePath)
	os.Exit(0)
}

func handleUser1Singal() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGUSR1)
	<-signalChan

	for {
		select {
		case <-signalChan:
			logRotate()
		}
	}
}

func logRotate() {
	// reopen fileserver log
	fp, err := os.OpenFile(absLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Failed to reopen fileserver log: %v", err)
	}
	log.SetOutput(fp)
	if logFp != nil {
		logFp.Close()
		logFp = fp
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
	r.HandleFunc("/protocol-version{slash:\\/?}", handleProtocolVersion)
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
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/permission-check{slash:\\/?}",
		appHandler(permissionCheckCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/commit/HEAD{slash:\\/?}",
		appHandler(headCommitOperCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/commit/{id:[\\da-z]{40}}",
		appHandler(commitOperCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/block/{id:[\\da-z]{40}}",
		appHandler(blockOperCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/fs-id-list{slash:\\/?}",
		appHandler(getFsObjIDCB))
	r.Handle("/repo/head-commits-multi{slash:\\/?}",
		appHandler(headCommitsMultiCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/pack-fs{slash:\\/?}",
		appHandler(packFSCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/check-fs{slash:\\/?}",
		appHandler(checkFSCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/check-blocks{slash:\\/?}",
		appHandler(checkBlockCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/recv-fs{slash:\\/?}",
		appHandler(recvFSCB))
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/quota-check{slash:\\/?}",
		appHandler(getCheckQuotaCB))

	// seadrive api
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/block-map/{id:[\\da-z]{40}}",
		appHandler(getBlockMapCB))
	r.Handle("/accessible-repos{slash:\\/?}", appHandler(getAccessibleRepoListCB))

	// pprof
	r.Handle("/debug/pprof", &profileHandler{http.HandlerFunc(pprof.Index)})
	r.Handle("/debug/pprof/cmdline", &profileHandler{http.HandlerFunc(pprof.Cmdline)})
	r.Handle("/debug/pprof/profile", &profileHandler{http.HandlerFunc(pprof.Profile)})
	r.Handle("/debug/pprof/symbol", &profileHandler{http.HandlerFunc(pprof.Symbol)})
	r.Handle("/debug/pprof/heap", &profileHandler{pprof.Handler("heap")})
	r.Handle("/debug/pprof/block", &profileHandler{pprof.Handler("block")})
	r.Handle("/debug/pprof/goroutine", &profileHandler{pprof.Handler("goroutine")})
	r.Handle("/debug/pprof/threadcreate", &profileHandler{pprof.Handler("threadcreate")})
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

func RecoverWrapper(f func()) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("panic: %v\n%s", err, debug.Stack())
		}
	}()

	f()
}

type profileHandler struct {
	pHandler http.Handler
}

func (p *profileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	queries := r.URL.Query()
	password := queries.Get("password")
	if !options.enableProfiling || password != options.profilePassword {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	p.pHandler.ServeHTTP(w, r)
}
