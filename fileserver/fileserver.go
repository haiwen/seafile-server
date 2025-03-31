// Main package for Seafile file server.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/metrics"
	"github.com/haiwen/seafile-server/fileserver/option"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/searpc"
	"github.com/haiwen/seafile-server/fileserver/share"
	"github.com/haiwen/seafile-server/fileserver/utils"
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

var seafileDB, ccnetDB *sql.DB

var logToStdout bool

func init() {
	flag.StringVar(&centralDir, "F", "", "central config directory")
	flag.StringVar(&dataDir, "d", "", "seafile data directory")
	flag.StringVar(&logFile, "l", "", "log file path")
	flag.StringVar(&rpcPipePath, "p", "", "rpc pipe path")
	flag.StringVar(&pidFilePath, "P", "", "pid file path")

	env := os.Getenv("SEAFILE_LOG_TO_STDOUT")
	if env == "true" {
		logToStdout = true
	}

	log.SetFormatter(&LogFormatter{})
}

const (
	timestampFormat = "[2006-01-02 15:04:05] "
)

type LogFormatter struct{}

func (f *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	levelStr := entry.Level.String()
	if levelStr == "fatal" {
		levelStr = "ERROR"
	} else {
		levelStr = strings.ToUpper(levelStr)
	}
	level := fmt.Sprintf("[%s] ", levelStr)
	appName := ""
	if logToStdout {
		appName = "[fileserver] "
	}
	buf := make([]byte, 0, len(appName)+len(timestampFormat)+len(level)+len(entry.Message)+1)
	if logToStdout {
		buf = append(buf, appName...)
	}
	buf = entry.Time.AppendFormat(buf, timestampFormat)
	buf = append(buf, level...)
	buf = append(buf, entry.Message...)
	buf = append(buf, '\n')
	return buf, nil
}

func loadCcnetDB() {
	dbOpt, err := loadDBOption()
	if err != nil {
		log.Fatalf("Failed to load database: %v", err)
	}

	var dsn string
	timeout := "&readTimeout=60s" + "&writeTimeout=60s"
	if dbOpt.UseTLS && dbOpt.SkipVerify {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=skip-verify%s", dbOpt.User, dbOpt.Password, dbOpt.Host, dbOpt.Port, dbOpt.CcnetDbName, timeout)
	} else if dbOpt.UseTLS && !dbOpt.SkipVerify {
		registerCA(dbOpt.CaPath)
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=custom%s", dbOpt.User, dbOpt.Password, dbOpt.Host, dbOpt.Port, dbOpt.CcnetDbName, timeout)
	} else {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t%s", dbOpt.User, dbOpt.Password, dbOpt.Host, dbOpt.Port, dbOpt.CcnetDbName, dbOpt.UseTLS, timeout)
	}
	if dbOpt.Charset != "" {
		dsn = fmt.Sprintf("%s&charset=%s", dsn, dbOpt.Charset)
	}
	ccnetDB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	ccnetDB.SetConnMaxLifetime(5 * time.Minute)
	ccnetDB.SetMaxOpenConns(8)
	ccnetDB.SetMaxIdleConns(8)
}

func loadDBOption() (*DBOption, error) {
	dbOpt, err := loadDBOptionFromFile()
	if err != nil {
		log.Warnf("failed to load database config: %v", err)
	}
	dbOpt = loadDBOptionFromEnv(dbOpt)

	if dbOpt.Host == "" {
		return nil, fmt.Errorf("no database host in seafile.conf.")
	}
	if dbOpt.User == "" {
		return nil, fmt.Errorf("no database user in seafile.conf.")
	}
	if dbOpt.Password == "" {
		return nil, fmt.Errorf("no database password in seafile.conf.")
	}

	return dbOpt, nil
}

type DBOption struct {
	User          string
	Password      string
	Host          string
	Port          int
	CcnetDbName   string
	SeafileDbName string
	CaPath        string
	UseTLS        bool
	SkipVerify    bool
	Charset       string
}

func loadDBOptionFromEnv(dbOpt *DBOption) *DBOption {
	user := os.Getenv("SEAFILE_MYSQL_DB_USER")
	password := os.Getenv("SEAFILE_MYSQL_DB_PASSWORD")
	host := os.Getenv("SEAFILE_MYSQL_DB_HOST")
	ccnetDbName := os.Getenv("SEAFILE_MYSQL_DB_CCNET_DB_NAME")
	seafileDbName := os.Getenv("SEAFILE_MYSQL_DB_SEAFILE_DB_NAME")

	if dbOpt == nil {
		dbOpt = new(DBOption)
	}
	if user != "" {
		dbOpt.User = user
	}
	if password != "" {
		dbOpt.Password = password
	}
	if host != "" {
		dbOpt.Host = host
	}
	if dbOpt.Port == 0 {
		dbOpt.Port = 3306
	}
	if ccnetDbName != "" {
		dbOpt.CcnetDbName = ccnetDbName
	} else if dbOpt.CcnetDbName == "" {
		dbOpt.CcnetDbName = "ccnet_db"
		log.Infof("Failed to read SEAFILE_MYSQL_DB_CCNET_DB_NAME, use ccnet_db by default")
	}
	if seafileDbName != "" {
		dbOpt.SeafileDbName = seafileDbName
	} else if dbOpt.SeafileDbName == "" {
		dbOpt.SeafileDbName = "seafile_db"
		log.Infof("Failed to read SEAFILE_MYSQL_DB_SEAFILE_DB_NAME, use seafile_db by default")
	}
	return dbOpt
}

func loadDBOptionFromFile() (*DBOption, error) {
	dbOpt := new(DBOption)

	seafileConfPath := filepath.Join(centralDir, "seafile.conf")
	opts := ini.LoadOptions{}
	opts.SpaceBeforeInlineComment = true
	config, err := ini.LoadSources(opts, seafileConfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load seafile.conf: %v", err)
	}

	section, err := config.GetSection("database")
	if err != nil {
		return nil, fmt.Errorf("no database section in seafile.conf.")
	}

	dbEngine := ""
	key, err := section.GetKey("type")
	if err == nil {
		dbEngine = key.String()
	}
	if dbEngine != "mysql" {
		return nil, fmt.Errorf("unsupported database %s.", dbEngine)
	}
	if key, err = section.GetKey("host"); err == nil {
		dbOpt.Host = key.String()
	}
	// user is required.
	if key, err = section.GetKey("user"); err == nil {
		dbOpt.User = key.String()
	}

	if key, err = section.GetKey("password"); err == nil {
		dbOpt.Password = key.String()
	}

	if key, err = section.GetKey("db_name"); err == nil {
		dbOpt.SeafileDbName = key.String()
	}
	port := 3306
	if key, err = section.GetKey("port"); err == nil {
		port, _ = key.Int()
	}
	dbOpt.Port = port
	useTLS := false
	if key, err = section.GetKey("use_ssl"); err == nil {
		useTLS, _ = key.Bool()
	}
	dbOpt.UseTLS = useTLS
	skipVerify := false
	if key, err = section.GetKey("skip_verify"); err == nil {
		skipVerify, _ = key.Bool()
	}
	dbOpt.SkipVerify = skipVerify
	if key, err = section.GetKey("ca_path"); err == nil {
		dbOpt.CaPath = key.String()
	}
	if key, err = section.GetKey("connection_charset"); err == nil {
		dbOpt.Charset = key.String()
	}

	return dbOpt, nil
}

// registerCA registers CA to verify server cert.
func registerCA(capath string) {
	rootCertPool := x509.NewCertPool()
	pem, err := os.ReadFile(capath)
	if err != nil {
		log.Fatal(err)
	}
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		log.Fatal("Failed to append PEM.")
	}
	mysql.RegisterTLSConfig("custom", &tls.Config{
		RootCAs: rootCertPool,
	})
}

func loadSeafileDB() {
	dbOpt, err := loadDBOption()
	if err != nil {
		log.Fatalf("Failed to load database: %v", err)
	}

	var dsn string
	timeout := "&readTimeout=60s" + "&writeTimeout=60s"
	if dbOpt.UseTLS && dbOpt.SkipVerify {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=skip-verify%s", dbOpt.User, dbOpt.Password, dbOpt.Host, dbOpt.Port, dbOpt.SeafileDbName, timeout)
	} else if dbOpt.UseTLS && !dbOpt.SkipVerify {
		registerCA(dbOpt.CaPath)
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=custom%s", dbOpt.User, dbOpt.Password, dbOpt.Host, dbOpt.Port, dbOpt.SeafileDbName, timeout)
	} else {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t%s", dbOpt.User, dbOpt.Password, dbOpt.Host, dbOpt.Port, dbOpt.SeafileDbName, dbOpt.UseTLS, timeout)
	}
	if dbOpt.Charset != "" {
		dsn = fmt.Sprintf("%s&charset=%s", dsn, dbOpt.Charset)
	}

	seafileDB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	seafileDB.SetConnMaxLifetime(5 * time.Minute)
	seafileDB.SetMaxOpenConns(8)
	seafileDB.SetMaxIdleConns(8)
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
	option.LoadFileServerOptions(centralDir)

	if logToStdout {
		// Use default output (StdOut)
	} else if logFile == "" {
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

	if absLogFile != "" && !logToStdout {
		utils.Dup(int(logFp.Fd()), int(os.Stderr.Fd()))
	}
	// When logFile is "-", use default output (StdOut)

	level, err := log.ParseLevel(option.LogLevel)
	if err != nil {
		log.Info("use the default log level: info")
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(level)
	}

	if err := option.LoadSeahubConfig(); err != nil {
		log.Fatalf("Failed to read seahub config: %v", err)
	}

	repomgr.Init(seafileDB)

	fsmgr.Init(centralDir, dataDir, option.FsCacheLimit)

	blockmgr.Init(centralDir, dataDir)

	commitmgr.Init(centralDir, dataDir)

	share.Init(ccnetDB, seafileDB, option.GroupTableName, option.CloudMode)

	rpcClientInit()

	fileopInit()

	syncAPIInit()

	sizeSchedulerInit()

	virtualRepoInit()

	initUpload()

	metrics.Init()

	router := newHTTPRouter()

	go handleSignals()
	go handleUser1Signal()

	log.Print("Seafile file server started.")

	server := new(http.Server)
	server.Addr = fmt.Sprintf("%s:%d", option.Host, option.Port)
	server.Handler = router

	err = server.ListenAndServe()
	if err != nil {
		log.Errorf("File server exiting: %v", err)
	}
}

func handleSignals() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-signalChan
	metrics.Stop()
	removePidfile(pidFilePath)
	os.Exit(0)
}

func handleUser1Signal() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGUSR1)

	for {
		<-signalChan
		logRotate()
	}
}

func logRotate() {
	if logToStdout {
		return
	}
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

	utils.Dup(int(logFp.Fd()), int(os.Stderr.Fd()))
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

	// links api
	//r.Handle("/u/{.*}", appHandler(uploadLinkCB))
	r.Handle("/f/{.*}{slash:\\/?}", appHandler(accessLinkCB))
	//r.Handle("/d/{.*}", appHandler(accessDirLinkCB))

	r.Handle("/repos/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/files/{filepath:.*}", appHandler(accessV2CB))

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
	r.Handle("/repo/{repoid:[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}}/jwt-token{slash:\\/?}",
		appHandler(getJWTTokenCB))

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
	r.Handle("/debug/pprof/trace", &traceHandler{})

	if option.HasRedisOptions {
		r.Use(metrics.MetricMiddleware)
	}
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
			log.Errorf("path %s internal server error: %v\n", r.URL.Path, e.Error)
		}
		http.Error(w, e.Message, e.Code)
	}
}

func RecoverWrapper(f func()) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panic: %v\n%s", err, debug.Stack())
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
	if !option.EnableProfiling || password != option.ProfilePassword {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	p.pHandler.ServeHTTP(w, r)
}

type traceHandler struct {
}

func (p *traceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	queries := r.URL.Query()
	password := queries.Get("password")
	if !option.EnableProfiling || password != option.ProfilePassword {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	pprof.Trace(w, r)
}
