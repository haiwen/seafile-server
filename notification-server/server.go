package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
)

var configDir string
var logFile, absLogFile string
var privateKey string
var host string
var port uint32
var logFp *os.File

var ccnetDB *sql.DB

func init() {
	flag.StringVar(&configDir, "c", "", "config directory")
	flag.StringVar(&logFile, "l", "", "log file path")

	log.SetFormatter(&LogFormatter{})
}

func loadNotifConfig() {
	notifyConfPath := filepath.Join(configDir, "seafile.conf")

	opts := ini.LoadOptions{}
	opts.SpaceBeforeInlineComment = true
	config, err := ini.LoadSources(opts, notifyConfPath)
	if err != nil {
		log.Fatalf("Failed to load notification.conf: %v", err)
	}

	section, err := config.GetSection("notification")
	if err != nil {
		log.Fatal("No notification section in seafile.conf.")
	}

	host = "0.0.0.0"
	port = 8083
	logLevel := "info"
	if key, err := section.GetKey("host"); err == nil {
		host = key.String()
	}

	if key, err := section.GetKey("port"); err == nil {
		n, err := key.Uint()
		if err == nil {
			port = uint32(n)
		}
	}

	if key, err := section.GetKey("log_level"); err == nil {
		logLevel = key.String()
	}

	if key, err := section.GetKey("jwt_private_key"); err == nil {
		privateKey = key.String()
	}

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Info("use the default log level: info")
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(level)
	}
}

func loadCcnetDB() {
	ccnetConfPath := filepath.Join(configDir, "ccnet.conf")
	config, err := ini.Load(ccnetConfPath)
	if err != nil {
		log.Fatalf("Failed to load ccnet.conf: %v", err)
	}

	section, err := config.GetSection("Database")
	if err != nil {
		log.Fatal("No database section in ccnet.conf.")
	}

	var dbEngine string = "mysql"
	key, err := section.GetKey("ENGINE")
	if err == nil {
		dbEngine = key.String()
	}

	if !strings.EqualFold(dbEngine, "mysql") {
		log.Fatalf("Unsupported database %s.", dbEngine)
	}

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
	if err := ccnetDB.Ping(); err != nil {
		log.Fatalf("Failed to connected to mysql: %v", err)
	}
}

func main() {
	flag.Parse()

	if configDir == "" {
		log.Fatal("config directory must be specified.")
	}

	_, err := os.Stat(configDir)
	if os.IsNotExist(err) {
		log.Fatalf("config directory %s doesn't exist: %v.", configDir, err)
	}

	if logFile == "" {
		absLogFile = filepath.Join(configDir, "notification.log")
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

	if absLogFile != "" {
		errorLogFile := filepath.Join(filepath.Dir(absLogFile), "notification_server_error.log")
		fp, err := os.OpenFile(errorLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Failed to open or create error log file: %v", err)
		}
		syscall.Dup3(int(fp.Fd()), int(os.Stderr.Fd()), 0)
		fp.Close()
	}

	loadNotifConfig()
	loadCcnetDB()

	Init()

	go handleUser1Signal()

	router := newHTTPRouter()

	log.Info("notification server started.")

	addr := fmt.Sprintf("%s:%d", host, port)
	err = http.ListenAndServe(addr, router)
	if err != nil {
		log.Info("notificationserver exiting: %v", err)
	}
}

func handleUser1Signal() {
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
	fp, err := os.OpenFile(absLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Failed to reopen notification log: %v", err)
	}
	log.SetOutput(fp)
	if logFp != nil {
		logFp.Close()
		logFp = fp
	}

	errorLogFile := filepath.Join(filepath.Dir(absLogFile), "notification_server_error.log")
	errFp, err := os.OpenFile(errorLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Failed to reopen notification error log: %v", err)
	}
	syscall.Dup3(int(errFp.Fd()), int(os.Stderr.Fd()), 0)
	errFp.Close()
}

func newHTTPRouter() *mux.Router {
	r := mux.NewRouter()
	r.Handle("/", appHandler(messageCB))
	r.Handle("/events{slash:\\/?}", appHandler(eventCB))
	r.Handle("/ping{slash:\\/?}", appHandler(pingCB))

	return r
}

// Any http request will be automatically upgraded to websocket.
func messageCB(rsp http.ResponseWriter, r *http.Request) *appError {
	upgrader := newUpgrader()
	conn, err := upgrader.Upgrade(rsp, r, nil)
	if err != nil {
		log.Warnf("failed to upgrade http to websocket: %v", err)
		// Don't return eror here, because the upgrade fails, then Upgrade replies to the client with an HTTP error response.
		return nil
	}

	addr := r.Header.Get("x-forwarded-for")
	if addr == "" {
		addr = conn.RemoteAddr().String()
	}
	client := NewClient(conn, addr)
	RegisterClient(client)
	client.HandleMessages()

	return nil
}

func eventCB(rsp http.ResponseWriter, r *http.Request) *appError {
	msg := Message{}

	token := r.Header.Get("Seafile-Repo-Token")
	if !checkAuthToken(token) {
		return &appError{Error: nil,
			Message: "Notification token not match",
			Code:    http.StatusBadRequest,
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &appError{Error: err,
			Message: "",
			Code:    http.StatusInternalServerError,
		}
	}

	if err := json.Unmarshal(body, &msg); err != nil {
		return &appError{Error: err,
			Message: "",
			Code:    http.StatusInternalServerError,
		}
	}

	Notify(&msg)

	return nil
}

func checkAuthToken(tokenString string) bool {
	if len(tokenString) == 0 {
		return false
	}
	claims := new(myClaims)
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	if err != nil {
		return false
	}

	if !token.Valid {
		return false
	}

	now := time.Now()

	return claims.Exp > now.Unix()
}

func newUpgrader() *websocket.Upgrader {
	upgrader := &websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	return upgrader
}

func pingCB(rsp http.ResponseWriter, r *http.Request) *appError {
	fmt.Fprintln(rsp, "{\"ret\": \"pong\"}")
	return nil
}

type appError struct {
	Error   error
	Message string
	Code    int
}

type appHandler func(http.ResponseWriter, *http.Request) *appError

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e := fn(w, r)
	if e != nil {
		if e.Error != nil && e.Code == http.StatusInternalServerError {
			log.Infof("path %s internal server error: %v\n", r.URL.Path, e.Error)
		}
		http.Error(w, e.Message, e.Code)
	}
}
