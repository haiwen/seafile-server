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
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

var configDir string
var logFile, absLogFile string
var privateKey string
var host string
var port uint32
var logFp *os.File

var ccnetDB *sql.DB

var logToStdout bool

func init() {
	flag.StringVar(&configDir, "c", "", "config directory")
	flag.StringVar(&logFile, "l", "", "log file path")

	env := os.Getenv("SEAFILE_LOG_TO_STDOUT")
	if env == "true" {
		logToStdout = true
	}

	log.SetFormatter(&LogFormatter{})
}

func loadNotifConfig() {
	host = os.Getenv("NOTIFICATION_SERVER_HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	port = 8083
	if os.Getenv("NOTIFICATION_SERVER_PORT") != "" {
		i, err := strconv.Atoi(os.Getenv("NOTIFICATION_SERVER_PORT"))
		if err == nil {
			port = uint32(i)
		}
	}

	logLevel := os.Getenv("NOTIFICATION_SERVER_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
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
	option, err := loadDBOptionFromEnv()
	if err != nil {
		log.Fatalf("Failed to load database from env: %v", err)
	}

	var dsn string
	if option.UnixSocket == "" {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%t&readTimeout=60s&writeTimeout=60s", option.User, option.Password, option.Host, option.Port, option.CcnetDbName, option.UseTLS)
	} else {
		dsn = fmt.Sprintf("%s:%s@unix(%s)/%s?readTimeout=60s&writeTimeout=60s", option.User, option.Password, option.UnixSocket, option.CcnetDbName)
	}
	ccnetDB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	if err := ccnetDB.Ping(); err != nil {
		log.Fatalf("Failed to connected to mysql: %v", err)
	}
	ccnetDB.SetConnMaxLifetime(5 * time.Minute)
	ccnetDB.SetMaxOpenConns(8)
	ccnetDB.SetMaxIdleConns(8)
}

type DBOption struct {
	User          string
	Password      string
	Host          string
	Port          int
	CcnetDbName   string
	SeafileDbName string
	UnixSocket    string
	UseTLS        bool
}

func loadDBOptionFromEnv() (*DBOption, error) {
	user := os.Getenv("SEAFILE_MYSQL_DB_USER")
	if user == "" {
		return nil, fmt.Errorf("failed to read SEAFILE_MYSQL_DB_USER")
	}
	password := os.Getenv("SEAFILE_MYSQL_DB_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("failed to read SEAFILE_MYSQL_DB_PASSWORD")
	}
	host := os.Getenv("SEAFILE_MYSQL_DB_HOST")
	if host == "" {
		return nil, fmt.Errorf("failed to read SEAFILE_MYSQL_DB_HOST")
	}
	ccnetDbName := os.Getenv("SEAFILE_MYSQL_DB_CCNET_DB_NAME")
	if ccnetDbName == "" {
		ccnetDbName = "ccnet_db"
		log.Infof("Failed to read SEAFILE_MYSQL_DB_CCNET_DB_NAME, use ccnet_db by default")
	}
	seafileDbName := os.Getenv("SEAFILE_MYSQL_DB_SEAFILE_DB_NAME")
	if seafileDbName == "" {
		seafileDbName = "seafile_db"
		log.Infof("Failed to read SEAFILE_MYSQL_DB_SEAFILE_DB_NAME, use seafile_db by default")
	}

	log.Infof("Database: user = %s", user)
	log.Infof("Database: host = %s", host)
	log.Infof("Database: ccnet_db_name = %s", ccnetDbName)
	log.Infof("Database: seafile_db_name = %s", seafileDbName)

	option := new(DBOption)
	option.User = user
	option.Password = password
	option.Host = host
	option.Port = 3306
	option.CcnetDbName = ccnetDbName
	option.SeafileDbName = seafileDbName
	return option, nil
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

	if logToStdout {
		// Use default output (StdOut)
	} else if logFile == "" {
		absLogFile = filepath.Join(configDir, "notification-server.log")
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
		Dup(int(logFp.Fd()), int(os.Stderr.Fd()))
	}

	if err := loadJwtPrivateKey(); err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	loadNotifConfig()
	loadCcnetDB()

	Init()

	go handleUser1Signal()

	router := newHTTPRouter()

	log.Info("notification server started.")

	server := new(http.Server)
	server.Addr = fmt.Sprintf("%s:%d", host, port)
	server.Handler = router

	err = server.ListenAndServe()
	if err != nil {
		log.Infof("notificationserver exiting: %v", err)
	}
}

func loadJwtPrivateKey() error {
	privateKey = os.Getenv("JWT_PRIVATE_KEY")
	if privateKey == "" {
		return fmt.Errorf("failed to read JWT_PRIVATE_KEY")
	}

	return nil
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
	fp, err := os.OpenFile(absLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Failed to reopen notification log: %v", err)
	}
	log.SetOutput(fp)
	if logFp != nil {
		logFp.Close()
		logFp = fp
	}

	Dup(int(logFp.Fd()), int(os.Stderr.Fd()))
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

	token := getAuthorizationToken(r.Header)
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

func getAuthorizationToken(h http.Header) string {
	auth := h.Get("Authorization")
	splitResult := strings.Split(auth, " ")
	if len(splitResult) > 1 {
		return splitResult[1]
	}
	return ""
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
