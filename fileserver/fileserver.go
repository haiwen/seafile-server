// Main package for Seafile file server.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	"github.com/haiwen/seafile-server/fileserver/option"
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
var seafileDB, ccnetDB *sql.DB

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
	level := fmt.Sprintf("[%s] ", entry.Level.String())
	buf := make([]byte, 0, len(timestampFormat)+len(level)+len(entry.Message)+1)
	buf = entry.Time.AppendFormat(buf, timestampFormat)
	buf = append(buf, level...)
	buf = append(buf, entry.Message...)
	buf = append(buf, '\n')
	return buf, nil
}

func loadCcnetDB() {
	ccnetConfPath := filepath.Join(centralDir, "ccnet.conf")
	opts := ini.LoadOptions{}
	opts.SpaceBeforeInlineComment = true
	config, err := ini.LoadSources(opts, ccnetConfPath)
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
		unixSocket := ""
		if key, err = section.GetKey("UNIX_SOCKET"); err == nil {
			unixSocket = key.String()
		}
		host := ""
		if key, err = section.GetKey("HOST"); err == nil {
			host = key.String()
		} else if unixSocket == "" {
			log.Fatal("No database host in ccnet.conf.")
		}
		// user is required.
		if key, err = section.GetKey("USER"); err != nil {
			log.Fatal("No database user in ccnet.conf.")
		}
		user := key.String()
		password := ""
		if key, err = section.GetKey("PASSWD"); err == nil {
			password = key.String()
		} else if unixSocket == "" {
			log.Fatal("No database password in ccnet.conf.")
		}
		if key, err = section.GetKey("DB"); err != nil {
			log.Fatal("No database db_name in ccnet.conf.")
		}
		dbName := key.String()
		port := 3306
		if key, err = section.GetKey("PORT"); err == nil {
			port, _ = key.Int()
		}
		useTLS := false
		if key, err = section.GetKey("USE_SSL"); err == nil {
			useTLS, _ = key.Bool()
		}
		skipVerify := false
		if key, err = section.GetKey("SKIP_VERIFY"); err == nil {
			skipVerify, _ = key.Bool()
		}
		var dsn string
		timeout := "&readTimeout=60s" + "&writeTimeout=60s"
		if unixSocket == "" {
			if useTLS && skipVerify {
				dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=skip-verify%s", user, password, host, port, dbName, timeout)
			} else if useTLS && !skipVerify {
				capath := ""
				if key, err = section.GetKey("CA_PATH"); err == nil {
					capath = key.String()
				}
				registerCA(capath)
				dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=custom%s", user, password, host, port, dbName, timeout)
			} else {
				dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t%s", user, password, host, port, dbName, useTLS, timeout)
			}
		} else {
			dsn = fmt.Sprintf("%s:%s@unix(%s)/%s?readTimeout=60s&writeTimeout=60s", user, password, unixSocket, dbName)
		}
		ccnetDB, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		ccnetDB.SetConnMaxLifetime(5 * time.Minute)
		ccnetDB.SetMaxOpenConns(8)
		ccnetDB.SetMaxIdleConns(8)
	} else {
		log.Fatalf("Unsupported database %s.", dbEngine)
	}
}

// registerCA registers CA to verify server cert.
func registerCA(capath string) {
	rootCertPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile(capath)
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
	seafileConfPath := filepath.Join(centralDir, "seafile.conf")

	opts := ini.LoadOptions{}
	opts.SpaceBeforeInlineComment = true
	config, err := ini.LoadSources(opts, seafileConfPath)
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
		unixSocket := ""
		if key, err = section.GetKey("unix_socket"); err == nil {
			unixSocket = key.String()
		}
		host := ""
		if key, err = section.GetKey("host"); err == nil {
			host = key.String()
		} else if unixSocket == "" {
			log.Fatal("No database host in seafile.conf.")
		}
		// user is required.
		if key, err = section.GetKey("user"); err != nil {
			log.Fatal("No database user in seafile.conf.")
		}
		user := key.String()

		password := ""
		if key, err = section.GetKey("password"); err == nil {
			password = key.String()
		} else if unixSocket == "" {
			log.Fatal("No database password in seafile.conf.")
		}
		if key, err = section.GetKey("db_name"); err != nil {
			log.Fatal("No database db_name in seafile.conf.")
		}
		dbName := key.String()
		port := 3306
		if key, err = section.GetKey("port"); err == nil {
			port, _ = key.Int()
		}
		useTLS := false
		if key, err = section.GetKey("use_ssl"); err == nil {
			useTLS, _ = key.Bool()
		}
		skipVerify := false
		if key, err = section.GetKey("skip_verify"); err == nil {
			skipVerify, _ = key.Bool()
		}

		var dsn string
		timeout := "&readTimeout=60s" + "&writeTimeout=60s"
		if unixSocket == "" {
			if useTLS && skipVerify {
				dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=skip-verify%s", user, password, host, port, dbName, timeout)
			} else if useTLS && !skipVerify {
				capath := ""
				if key, err = section.GetKey("ca_path"); err == nil {
					capath = key.String()
				}
				registerCA(capath)
				dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=custom%s", user, password, host, port, dbName, timeout)
			} else {
				dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t%s", user, password, host, port, dbName, useTLS, timeout)
			}
		} else {
			dsn = fmt.Sprintf("%s:%s@unix(%s)/%s?readTimeout=60s&writeTimeout=60s", user, password, unixSocket, dbName)
		}

		seafileDB, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		seafileDB.SetConnMaxLifetime(5 * time.Minute)
		seafileDB.SetMaxOpenConns(8)
		seafileDB.SetMaxIdleConns(8)
	} else {
		log.Fatalf("Unsupported database %s.", dbEngine)
	}
	dbType = dbEngine
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

	level, err := log.ParseLevel(option.LogLevel)
	if err != nil {
		log.Info("use the default log level: info")
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(level)
	}

	if absLogFile != "" {
		errorLogFile := filepath.Join(filepath.Dir(absLogFile), "fileserver-error.log")
		fp, err := os.OpenFile(errorLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open or create error log file: %v", err)
		}
		syscall.Dup3(int(fp.Fd()), int(os.Stderr.Fd()), 0)
		// We need to close the old fp, because it has beed duped.
		fp.Close()
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

	router := newHTTPRouter()

	go handleSignals()
	go handleUser1Signal()

	log.Print("Seafile file server started.")

	addr := fmt.Sprintf("%s:%d", option.Host, option.Port)
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

func handleUser1Signal() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGUSR1)

	for {
		<-signalChan
		logRotate()
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

	errorLogFile := filepath.Join(filepath.Dir(absLogFile), "fileserver-error.log")
	errFp, err := os.OpenFile(errorLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Failed to reopen fileserver error log: %v", err)
	}
	syscall.Dup3(int(errFp.Fd()), int(os.Stderr.Fd()), 0)
	errFp.Close()
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
