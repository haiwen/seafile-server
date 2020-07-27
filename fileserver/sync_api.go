package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/share"
)

const (
	seafileServerChannelEvent = "seaf_server.event"
	seafileServerChannelStats = "seaf_server.stats"
	tokenExpireTime           = 7200
	permExpireTime            = 7200
	virtualRepoExpireTime     = 7200
	cleaningIntervalSec       = 300
	seafHTTPResRepoDeleted    = 444
	seafHTTPResRepoCorrupted  = 445
)

var (
	tokenCache           sync.Map
	permCache            sync.Map
	virtualRepoInfoCache sync.Map
)

type tokenInfo struct {
	repoID     string
	email      string
	expireTime int64
}

type permInfo struct {
	perm       string
	expireTime int64
}

type virtualRepoInfo struct {
	storeID    string
	expireTime int64
}

type repoEventData struct {
	eType      string
	user       string
	ip         string
	repoID     string
	path       string
	clientName string
}

type statusEventData struct {
	eType  string
	user   string
	repoID string
	bytes  uint64
}

func syncAPIInit() {
	ticker := time.NewTicker(time.Second * cleaningIntervalSec)
	go func() {
		for range ticker.C {
			removeExpireCache()
		}
	}()
}

func permissionCheckCB(rsp http.ResponseWriter, r *http.Request) *appError {
	queries := r.URL.Query()

	op := queries.Get("op")
	if op != "download" && op != "upload" {
		msg := "op is invalid"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	clientID := queries.Get("client_id")
	if clientID != "" && len(clientID) != 40 {
		msg := "client_id is invalid"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	clientVer := queries.Get("client_ver")
	if clientVer != "" {
		status := validateClientVer(clientVer)
		if status != http.StatusOK {
			msg := "client_ver is invalid"
			return &appError{nil, msg, status}
		}
	}

	clientName := queries.Get("client_name")
	if clientName != "" {
		clientName = html.UnescapeString(clientName)
	}

	vars := mux.Vars(r)
	repoID := vars["repoid"]
	repo := repomgr.GetEx(repoID)
	if repo == nil {
		msg := "repo was deleted"
		return &appError{nil, msg, seafHTTPResRepoDeleted}
	}

	if repo.IsCorrupted {
		msg := "repo was corrupted"
		return &appError{nil, msg, seafHTTPResRepoCorrupted}
	}

	user, err := validateToken(r, repoID, true)
	if err != nil {
		return err
	}
	err = checkPermission(repoID, user, op, true)
	if err != nil {
		return err
	}
	ip := getClientIPAddr(r)
	if ip == "" {
		token := r.Header.Get("Seafile-Repo-Token")
		err := fmt.Errorf("%s failed to get client ip", token)
		return &appError{err, "", http.StatusInternalServerError}
	}

	if op == "download" {
		onRepoOper("repo-download-sync", repoID, user, ip, clientName)
	}
	if clientID != "" && clientName != "" {
		token := r.Header.Get("Seafile-Repo-Token")
		exists, err := repomgr.TokenPeerInfoExists(token)
		if err != nil {
			err := fmt.Errorf("Failed to check whether token %s peer info exist: %v", token, err)
			return &appError{err, "", http.StatusInternalServerError}
		}
		if !exists {
			if err := repomgr.AddTokenPeerInfo(token, clientID, ip, clientName, clientVer, int64(time.Now().Second())); err != nil {
				err := fmt.Errorf("Failed to add token peer info: %v", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
		} else {
			if err := repomgr.UpdateTokenPeerInfo(token, clientID, clientVer, int64(time.Now().Second())); err != nil {
				err := fmt.Errorf("Failed to update token peer info: %v", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
		}
	}
	return nil
}

func headCommitOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getHeadCommit(rsp, r)
	} else if r.Method == http.MethodPut {
		// TODO: handle put
		return nil
	}
	return &appError{nil, "", http.StatusBadRequest}
}

func commitOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getCommitInfo(rsp, r)
	}
	return &appError{nil, "", http.StatusBadRequest}
}

func blockOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getBlockInfo(rsp, r)
	}
	return &appError{nil, "", http.StatusBadRequest}
}

func getBlockInfo(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	blockID := vars["id"]

	userName, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}

	storeID := getRepoStoreID(repoID)
	if storeID == "" {
		err := fmt.Errorf("Failed to get repo store id by repo id %s", repoID)
		return &appError{err, "", http.StatusInternalServerError}
	}

	blockSize, err := blockmgr.Stat(repoID, blockID)
	if err != nil {
		return &appError{err, "", http.StatusInternalServerError}
	}
	if blockSize <= 0 {
		err := fmt.Errorf("block %.8s:%s size invalid", storeID, blockID)
		return &appError{err, "", http.StatusInternalServerError}
	}

	blockLen := fmt.Sprintf("%d", blockSize)
	rsp.Header().Set("Content-Length", blockLen)
	rsp.WriteHeader(http.StatusOK)
	if err := blockmgr.Read(repoID, blockID, rsp); err != nil {
		return &appError{err, "", http.StatusInternalServerError}
	}

	sendStatisticMsg(repoID, userName, "sync-file-download", uint64(blockSize))
	return nil
}

func getRepoStoreID(repoID string) string {
	var storeID string

	if value, ok := virtualRepoInfoCache.Load(repoID); ok {
		if info, ok := value.(*virtualRepoInfo); ok {
			if info.storeID != "" {
				storeID = info.storeID
			} else {
				storeID = repoID
			}
			info.expireTime = time.Now().Unix() + virtualRepoExpireTime
		}
	}
	if storeID != "" {
		return storeID
	}

	var vInfo virtualRepoInfo
	sqlStr := "SELECT repo_id, origin_repo FROM VirtualRepo where repo_id = ?"
	row := seafileDB.QueryRow(sqlStr, repoID)
	if err := row.Scan(&vInfo); err != nil {
		if err == sql.ErrNoRows {
			vInfo.expireTime = time.Now().Unix() + virtualRepoExpireTime
			virtualRepoInfoCache.Store(repoID, &vInfo)
			return repoID
		}
		return ""
	}

	virtualRepoInfoCache.Store(repoID, &vInfo)
	return vInfo.storeID
}

func sendStatisticMsg(repoID, user, operation string, bytes uint64) {
	rData := &statusEventData{operation, user, repoID, bytes}

	publishStatusEvent(rData)
}

func publishStatusEvent(rData *statusEventData) {
	buf := fmt.Sprintf("%s\t%s\t%s\t%d",
		rData.eType, rData.user,
		rData.repoID, rData.bytes)
	if _, err := rpcclient.Call("publish_event", seafileServerChannelStats, buf); err != nil {
		log.Printf("Failed to publish event: %v", err)
	}
}

func getCommitInfo(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	commitID := vars["id"]
	if _, err := validateToken(r, repoID, false); err != nil {
		return err
	}
	if exists, _ := commitmgr.Exists(repoID, commitID); !exists {
		log.Printf("%s:%s is missing", repoID, commitID)
		return &appError{nil, "", http.StatusNotFound}
	}

	var data bytes.Buffer
	err := commitmgr.ReadRaw(repoID, commitID, &data)
	if err != nil {
		err := fmt.Errorf("Failed to read commit %s:%s: %v", repoID, commitID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	dataLen := strconv.Itoa(data.Len())
	rsp.Header().Set("Content-Length", dataLen)
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(data.Bytes())

	return nil
}

func getHeadCommit(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	sqlStr := "SELECT EXISTS(SELECT 1 FROM Repo WHERE repo_id=?)"
	var exists bool
	row := seafileDB.QueryRow(sqlStr, repoID)
	if err := row.Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("DB error when check repo %s existence: %v", repoID, err)
			msg := `{"is_corrupted": 1}`
			rsp.WriteHeader(http.StatusOK)
			rsp.Write([]byte(msg))
			return nil
		}
	}
	if !exists {
		return &appError{nil, "", seafHTTPResRepoDeleted}
	}

	if _, err := validateToken(r, repoID, false); err != nil {
		return err
	}

	var commitID string
	sqlStr = "SELECT commit_id FROM Branch WHERE name='master' AND repo_id=?"
	row = seafileDB.QueryRow(sqlStr, repoID)

	if err := row.Scan(&commitID); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("DB error when get branch master: %v", err)
			msg := `{"is_corrupted": 1}`
			rsp.WriteHeader(http.StatusOK)
			rsp.Write([]byte(msg))
			return nil
		}
	}
	if commitID == "" {
		return &appError{nil, "", http.StatusBadRequest}
	}

	msg := fmt.Sprintf("{\"is_corrupted\": 0, \"head_commit_id\": \"%s\"}", commitID)
	rsp.WriteHeader(http.StatusOK)
	rsp.Write([]byte(msg))
	return nil
}

func checkPermission(repoID, user, op string, skipCache bool) *appError {
	var info *permInfo
	if !skipCache {
		if value, ok := permCache.Load(fmt.Sprintf("%s:%s", repoID, user)); ok {
			info = value.(*permInfo)
		}
	}
	if info != nil {
		if info.perm == "r" && op == "upload" {
			return &appError{nil, "", http.StatusForbidden}
		}
		return nil
	}

	status, err := repomgr.GetRepoStatus(repoID)
	if err != nil {
		msg := fmt.Sprintf("Failed to get repo status by repo id %s: %v", repoID, err)
		return &appError{nil, msg, http.StatusForbidden}
	}
	if status != repomgr.RepoStatusNormal && status != -1 {
		return &appError{nil, "", http.StatusForbidden}
	}

	perm := share.CheckPerm(repoID, user)
	if perm != "" {
		info = new(permInfo)
		info.perm = perm
		info.expireTime = time.Now().Unix() + permExpireTime
		permCache.Store(fmt.Sprintf("%s:%s", repoID, user), info)
		if perm == "r" && op == "upload" {
			return &appError{nil, "", http.StatusForbidden}
		}
		return nil
	}

	permCache.Delete(fmt.Sprintf("%s:%s", repoID, user))

	return &appError{nil, "", http.StatusForbidden}
}

func validateToken(r *http.Request, repoID string, skipCache bool) (string, *appError) {
	token := r.Header.Get("Seafile-Repo-Token")
	if token == "" {
		msg := "token is null"
		return "", &appError{nil, msg, http.StatusBadRequest}
	}

	if value, ok := tokenCache.Load(token); ok {
		if info, ok := value.(*tokenInfo); ok {
			return info.email, nil
		}
	}

	email, err := repomgr.GetEmailByToken(repoID, token)
	if err != nil {
		log.Printf("Failed to get email by token %s: %v", token, err)
		tokenCache.Delete(token)
		return email, &appError{err, "", http.StatusInternalServerError}
	}
	if email == "" {
		msg := "email is null"
		return email, &appError{nil, msg, http.StatusForbidden}
	}

	info := new(tokenInfo)
	info.email = email
	info.expireTime = time.Now().Unix() + tokenExpireTime
	info.repoID = repoID
	tokenCache.Store(token, info)

	return email, nil
}

func validateClientVer(clientVer string) int {
	versions := strings.Split(clientVer, ".")
	if len(versions) != 3 {
		return http.StatusBadRequest
	}
	if _, err := strconv.Atoi(versions[0]); err != nil {
		return http.StatusBadRequest
	}
	if _, err := strconv.Atoi(versions[1]); err != nil {
		return http.StatusBadRequest
	}
	if _, err := strconv.Atoi(versions[2]); err != nil {
		return http.StatusBadRequest
	}

	return http.StatusOK
}

func getClientIPAddr(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	addr := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	ip := net.ParseIP(addr)
	if ip != nil {
		return ip.String()
	}

	addr = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	ip = net.ParseIP(addr)
	if ip != nil {
		return ip.String()
	}

	if addr, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		ip = net.ParseIP(addr)
		if ip != nil {
			return ip.String()
		}
	}

	return ""
}

func onRepoOper(eType, repoID, user, ip, clientName string) {
	rData := new(repoEventData)
	vInfo, err := repomgr.GetVirtualRepoInfo(repoID)

	if err != nil {
		log.Printf("Failed to get virtual repo info by repo id %s: %v", repoID, err)
		return
	}
	if vInfo != nil {
		rData.repoID = vInfo.OriginRepoID
		rData.path = vInfo.Path
	} else {
		rData.repoID = repoID
	}
	rData.eType = eType
	rData.user = user
	rData.ip = ip
	rData.clientName = clientName

	publishRepoEvent(rData)
}

func publishRepoEvent(rData *repoEventData) {
	if rData.path == "" {
		rData.path = "/"
	}
	buf := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s",
		rData.eType, rData.user, rData.ip,
		rData.clientName, rData.repoID, rData.path)
	if _, err := rpcclient.Call("publish_event", seafileServerChannelEvent, buf); err != nil {
		log.Printf("Failed to publish event: %v", err)
	}
}

func removeExpireCache() {
	deleteTokens := func(key interface{}, value interface{}) bool {
		if info, ok := value.(*tokenInfo); ok {
			if info.expireTime <= time.Now().Unix() {
				tokenCache.Delete(key)
			}
		}
		return true
	}

	deletePerms := func(key interface{}, value interface{}) bool {
		if info, ok := value.(*permInfo); ok {
			if info.expireTime <= time.Now().Unix() {
				permCache.Delete(key)
			}
		}
		return true
	}

	deleteVirtualRepoInfo := func(key interface{}, value interface{}) bool {
		if info, ok := value.(*virtualRepoInfo); ok {
			if info.expireTime <= time.Now().Unix() {
				virtualRepoInfoCache.Delete(key)
			}
		}
		return true
	}

	tokenCache.Range(deleteTokens)
	permCache.Range(deletePerms)
	virtualRepoInfoCache.Range(deleteVirtualRepoInfo)
}
