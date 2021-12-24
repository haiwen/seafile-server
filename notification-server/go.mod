module github.com/haiwen/seafile-server/notification-server

go 1.17

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/haiwen/seafile-server/fileserver v0.0.0-20220114093911-524f227b02cc
	github.com/mattn/go-sqlite3 v1.14.0
	github.com/sirupsen/logrus v1.8.1
	gopkg.in/ini.v1 v1.66.2
)

require golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd // indirect
