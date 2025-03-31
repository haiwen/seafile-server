package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/diff"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/option"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/share"
	"github.com/haiwen/seafile-server/fileserver/utils"
	"github.com/haiwen/seafile-server/fileserver/workerpool"
	log "github.com/sirupsen/logrus"
)

type checkExistType int32

const (
	checkFSExist    checkExistType = 0
	checkBlockExist checkExistType = 1
)

const (
	seafileServerChannelEvent  = "seaf_server.event"
	seafileServerChannelStats  = "seaf_server.stats"
	emptySHA1                  = "0000000000000000000000000000000000000000"
	tokenExpireTime            = 7200
	permExpireTime             = 7200
	virtualRepoExpireTime      = 7200
	syncAPICleaningIntervalSec = 300
	maxObjectPackSize          = 1 << 20 // 1MB
	fsIdWorkers                = 10
)

var (
	tokenCache           sync.Map
	permCache            sync.Map
	virtualRepoInfoCache sync.Map
	calFsIdPool          *workerpool.WorkPool
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

type statsEventData struct {
	eType  string
	user   string
	repoID string
	bytes  uint64
}

func syncAPIInit() {
	ticker := time.NewTicker(time.Second * syncAPICleaningIntervalSec)
	go RecoverWrapper(func() {
		for range ticker.C {
			removeSyncAPIExpireCache()
		}
	})

	calFsIdPool = workerpool.CreateWorkerPool(getFsId, fsIdWorkers)
}

type calResult struct {
	user string
	err  *appError
}

func getFsId(args ...interface{}) error {
	if len(args) < 3 {
		return nil
	}

	resChan := args[0].(chan *calResult)
	rsp := args[1].(http.ResponseWriter)
	r := args[2].(*http.Request)

	queries := r.URL.Query()

	serverHead := queries.Get("server-head")
	if !utils.IsObjectIDValid(serverHead) {
		msg := "Invalid server-head parameter."
		appErr := &appError{nil, msg, http.StatusBadRequest}
		resChan <- &calResult{"", appErr}
		return nil
	}

	clientHead := queries.Get("client-head")
	if clientHead != "" && !utils.IsObjectIDValid(clientHead) {
		msg := "Invalid client-head parameter."
		appErr := &appError{nil, msg, http.StatusBadRequest}
		resChan <- &calResult{"", appErr}
		return nil
	}

	dirOnlyArg := queries.Get("dir-only")
	var dirOnly bool
	if dirOnlyArg != "" {
		dirOnly = true
	}

	vars := mux.Vars(r)
	repoID := vars["repoid"]
	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		resChan <- &calResult{user, appErr}
		return nil
	}
	appErr = checkPermission(repoID, user, "download", false)
	if appErr != nil {
		resChan <- &calResult{user, appErr}
		return nil
	}
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("Failed to find repo %.8s", repoID)
		appErr := &appError{err, "", http.StatusInternalServerError}
		resChan <- &calResult{user, appErr}
		return nil
	}
	ret, err := calculateSendObjectList(r.Context(), repo, serverHead, clientHead, dirOnly)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			err := fmt.Errorf("Failed to get fs id list: %w", err)
			appErr := &appError{err, "", http.StatusInternalServerError}
			resChan <- &calResult{user, appErr}
			return nil
		}
		appErr := &appError{nil, "", http.StatusInternalServerError}
		resChan <- &calResult{user, appErr}
		return nil
	}

	var objList []byte
	if ret != nil {
		objList, err = json.Marshal(ret)
		if err != nil {
			appErr := &appError{err, "", http.StatusInternalServerError}
			resChan <- &calResult{user, appErr}
			return nil
		}
	} else {
		// when get obj list is nil, return []
		objList = []byte{'[', ']'}
	}

	rsp.Header().Set("Content-Length", strconv.Itoa(len(objList)))
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(objList)

	resChan <- &calResult{user, nil}

	return nil
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
			if err := repomgr.AddTokenPeerInfo(token, clientID, ip, clientName, clientVer, int64(time.Now().Unix())); err != nil {
				err := fmt.Errorf("Failed to add token peer info: %v", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
		} else {
			if err := repomgr.UpdateTokenPeerInfo(token, clientID, clientVer, int64(time.Now().Unix())); err != nil {
				err := fmt.Errorf("Failed to update token peer info: %v", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
		}
	}
	return nil
}
func getBlockMapCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	fileID := vars["id"]

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}
	appErr = checkPermission(repoID, user, "download", false)
	if appErr != nil {
		return appErr
	}

	storeID, err := getRepoStoreID(repoID)
	if err != nil {
		err := fmt.Errorf("Failed to get repo store id by repo id %s: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	seafile, err := fsmgr.GetSeafile(storeID, fileID)
	if err != nil {
		msg := fmt.Sprintf("Failed to get seafile object by file id %s: %v", fileID, err)
		return &appError{nil, msg, http.StatusNotFound}
	}

	var blockSizes []int64
	for _, blockID := range seafile.BlkIDs {
		blockSize, err := blockmgr.Stat(storeID, blockID)
		if err != nil {
			err := fmt.Errorf("Failed to find block %s/%s", storeID, blockID)
			return &appError{err, "", http.StatusInternalServerError}
		}
		blockSizes = append(blockSizes, blockSize)
	}

	var data []byte
	if blockSizes != nil {
		data, err = json.Marshal(blockSizes)
		if err != nil {
			err := fmt.Errorf("Failed to marshal json: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
	} else {
		data = []byte{'[', ']'}
	}

	rsp.Header().Set("Content-Length", strconv.Itoa(len(data)))
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(data)

	return nil
}

func getAccessibleRepoListCB(rsp http.ResponseWriter, r *http.Request) *appError {
	queries := r.URL.Query()
	repoID := queries.Get("repo_id")

	if repoID == "" || !utils.IsValidUUID(repoID) {
		msg := "Invalid repo id."
		return &appError{nil, msg, http.StatusBadRequest}
	}

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}

	obtainedRepos := make(map[string]string)

	repos, err := share.GetReposByOwner(user)
	if err != nil {
		err := fmt.Errorf("Failed to get repos by owner %s: %v", user, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	var repoObjects []*share.SharedRepo
	for _, repo := range repos {
		if repo.RepoType != "" {
			continue
		}
		if _, ok := obtainedRepos[repo.ID]; !ok {
			obtainedRepos[repo.ID] = repo.ID
		}
		repo.Permission = "rw"
		repo.Type = "repo"
		repo.Owner = user
		repoObjects = append(repoObjects, repo)
	}

	repos, err = share.ListShareRepos(user, "to_email")
	if err != nil {
		err := fmt.Errorf("Failed to get share repos by user %s: %v", user, err)
		return &appError{err, "", http.StatusInternalServerError}
	}
	for _, sRepo := range repos {
		if _, ok := obtainedRepos[sRepo.ID]; ok {
			continue
		}
		if sRepo.RepoType != "" {
			continue
		}
		sRepo.Type = "srepo"
		sRepo.Owner = strings.ToLower(sRepo.Owner)
		repoObjects = append(repoObjects, sRepo)
	}

	repos, err = share.GetGroupReposByUser(user, -1)
	if err != nil {
		err := fmt.Errorf("Failed to get group repos by user %s: %v", user, err)
		return &appError{err, "", http.StatusInternalServerError}
	}
	reposTable := filterGroupRepos(repos)

	for _, gRepo := range reposTable {
		if _, ok := obtainedRepos[gRepo.ID]; ok {
			continue
		}

		gRepo.Type = "grepo"
		gRepo.Owner = strings.ToLower(gRepo.Owner)
		repoObjects = append(repoObjects, gRepo)
	}

	repos, err = share.ListInnerPubRepos()
	if err != nil {
		err := fmt.Errorf("Failed to get inner public repos: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	for _, sRepo := range repos {
		if _, ok := obtainedRepos[sRepo.ID]; ok {
			continue
		}
		if sRepo.RepoType != "" {
			continue
		}

		sRepo.Type = "grepo"
		sRepo.Owner = "Organization"
		repoObjects = append(repoObjects, sRepo)
	}

	var data []byte
	if repoObjects != nil {
		data, err = json.Marshal(repoObjects)
		if err != nil {
			err := fmt.Errorf("Failed to marshal json: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
	} else {
		data = []byte{'[', ']'}
	}
	rsp.Header().Set("Content-Length", strconv.Itoa(len(data)))
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(data)
	return nil
}

func filterGroupRepos(repos []*share.SharedRepo) map[string]*share.SharedRepo {
	table := make(map[string]*share.SharedRepo)

	for _, repo := range repos {
		if repo.RepoType != "" {
			continue
		}
		if repoPrev, ok := table[repo.ID]; ok {
			if repo.Permission == "rw" && repoPrev.Permission == "r" {
				table[repo.ID] = repo
			}
		} else {
			table[repo.ID] = repo
		}
	}

	return table
}

func recvFSCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}

	appErr = checkPermission(repoID, user, "upload", false)
	if appErr != nil {
		return appErr
	}

	storeID, err := getRepoStoreID(repoID)
	if err != nil {
		err := fmt.Errorf("Failed to get repo store id by repo id %s: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}
	fsBuf, err := io.ReadAll(r.Body)
	if err != nil {
		return &appError{nil, err.Error(), http.StatusBadRequest}
	}

	for len(fsBuf) > 44 {
		objID := string(fsBuf[:40])
		if !utils.IsObjectIDValid(objID) {
			msg := fmt.Sprintf("Fs obj id %s is invalid", objID)
			return &appError{nil, msg, http.StatusBadRequest}
		}

		var objSize uint32
		sizeBuffer := bytes.NewBuffer(fsBuf[40:44])
		if err := binary.Read(sizeBuffer, binary.BigEndian, &objSize); err != nil {
			msg := fmt.Sprintf("Failed to read fs obj size: %v", err)
			return &appError{nil, msg, http.StatusBadRequest}
		}

		if len(fsBuf) < int(44+objSize) {
			msg := "Request body size invalid"
			return &appError{nil, msg, http.StatusBadRequest}
		}

		objBuffer := bytes.NewBuffer(fsBuf[44 : 44+objSize])
		if err := fsmgr.WriteRaw(storeID, objID, objBuffer); err != nil {
			err := fmt.Errorf("Failed to write fs obj %s:%s : %v", storeID, objID, err)
			return &appError{err, "", http.StatusInternalServerError}
		}
		fsBuf = fsBuf[44+objSize:]
	}
	if len(fsBuf) == 0 {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	msg := "Request body size invalid"
	return &appError{nil, msg, http.StatusBadRequest}
}
func checkFSCB(rsp http.ResponseWriter, r *http.Request) *appError {
	return postCheckExistCB(rsp, r, checkFSExist)
}

func checkBlockCB(rsp http.ResponseWriter, r *http.Request) *appError {
	return postCheckExistCB(rsp, r, checkBlockExist)
}

func postCheckExistCB(rsp http.ResponseWriter, r *http.Request, existType checkExistType) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}
	appErr = checkPermission(repoID, user, "download", false)
	if appErr != nil {
		return appErr
	}

	storeID, err := getRepoStoreID(repoID)
	if err != nil {
		err := fmt.Errorf("Failed to get repo store id by repo id %s: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	var objIDList []string
	if err := json.NewDecoder(r.Body).Decode(&objIDList); err != nil {
		return &appError{nil, err.Error(), http.StatusBadRequest}
	}

	var neededObjs []string
	var ret bool
	for i := 0; i < len(objIDList); i++ {
		if !utils.IsObjectIDValid(objIDList[i]) {
			continue
		}
		if existType == checkFSExist {
			ret, _ = fsmgr.Exists(storeID, objIDList[i])
		} else if existType == checkBlockExist {
			ret = blockmgr.Exists(storeID, objIDList[i])
		}
		if !ret {
			neededObjs = append(neededObjs, objIDList[i])
		}
	}

	var data []byte
	if neededObjs != nil {
		data, err = json.Marshal(neededObjs)
		if err != nil {
			err := fmt.Errorf("Failed to marshal json: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
	} else {
		data = []byte{'[', ']'}
	}
	rsp.Header().Set("Content-Length", strconv.Itoa(len(data)))
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(data)

	return nil
}

func packFSCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}
	appErr = checkPermission(repoID, user, "download", false)
	if appErr != nil {
		return appErr
	}

	storeID, err := getRepoStoreID(repoID)
	if err != nil {
		err := fmt.Errorf("Failed to get repo store id by repo id %s: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	var fsIDList []string
	if err := json.NewDecoder(r.Body).Decode(&fsIDList); err != nil {
		return &appError{nil, err.Error(), http.StatusBadRequest}
	}

	var totalSize int
	var data bytes.Buffer
	for i := 0; i < len(fsIDList); i++ {
		if !utils.IsObjectIDValid(fsIDList[i]) {
			msg := fmt.Sprintf("Invalid fs id %s", fsIDList[i])
			return &appError{nil, msg, http.StatusBadRequest}
		}
		data.WriteString(fsIDList[i])
		var tmp bytes.Buffer
		if err := fsmgr.ReadRaw(storeID, fsIDList[i], &tmp); err != nil {
			err := fmt.Errorf("Failed to read fs %s:%s: %v", storeID, fsIDList[i], err)
			return &appError{err, "", http.StatusInternalServerError}
		}
		tmpLen := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpLen, uint32(tmp.Len()))
		data.Write(tmpLen)
		data.Write(tmp.Bytes())

		totalSize += tmp.Len()
		if totalSize >= maxObjectPackSize {
			break
		}
	}

	rsp.Header().Set("Content-Length", strconv.Itoa(data.Len()))
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(data.Bytes())
	return nil
}

func headCommitsMultiCB(rsp http.ResponseWriter, r *http.Request) *appError {
	var repoIDList []string
	if err := json.NewDecoder(r.Body).Decode(&repoIDList); err != nil {
		return &appError{err, "", http.StatusBadRequest}
	}
	if len(repoIDList) == 0 {
		return &appError{nil, "", http.StatusBadRequest}
	}

	var repoIDs strings.Builder
	for i := 0; i < len(repoIDList); i++ {
		if !utils.IsValidUUID(repoIDList[i]) {
			return &appError{nil, "", http.StatusBadRequest}
		}
		if i == 0 {
			repoIDs.WriteString(fmt.Sprintf("'%s'", repoIDList[i]))
		} else {
			repoIDs.WriteString(fmt.Sprintf(",'%s'", repoIDList[i]))
		}
	}

	sqlStr := fmt.Sprintf(
		"SELECT repo_id, commit_id FROM Branch WHERE name='master' AND "+
			"repo_id IN (%s) LOCK IN SHARE MODE",
		repoIDs.String())

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	rows, err := seafileDB.QueryContext(ctx, sqlStr)
	if err != nil {
		err := fmt.Errorf("Failed to get commit id: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	defer rows.Close()

	commitIDMap := make(map[string]string)
	var repoID string
	var commitID string
	for rows.Next() {
		if err := rows.Scan(&repoID, &commitID); err == nil {
			commitIDMap[repoID] = commitID
		}
	}

	if err := rows.Err(); err != nil {
		err := fmt.Errorf("Failed to get commit id: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	data, err := json.Marshal(commitIDMap)
	if err != nil {
		err := fmt.Errorf("Failed to marshal json: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	rsp.Header().Set("Content-Length", strconv.Itoa(len(data)))
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(data)

	return nil
}

func getCheckQuotaCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]

	if _, err := validateToken(r, repoID, false); err != nil {
		return err
	}

	queries := r.URL.Query()
	delta := queries.Get("delta")
	if delta == "" {
		msg := "Invalid delta parameter"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	deltaNum, err := strconv.ParseInt(delta, 10, 64)
	if err != nil {
		msg := "Invalid delta parameter"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	ret, err := checkQuota(repoID, deltaNum)
	if err != nil {
		msg := "Internal error.\n"
		err := fmt.Errorf("failed to check quota: %v", err)
		return &appError{err, msg, http.StatusInternalServerError}
	}
	if ret == 1 {
		msg := "Out of quota.\n"
		return &appError{nil, msg, seafHTTPResNoQuota}
	}

	return nil
}

func getJWTTokenCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]

	if !option.EnableNotification {
		return &appError{nil, "", http.StatusNotFound}
	}

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}

	exp := time.Now().Add(time.Hour * 72).Unix()
	tokenString, err := utils.GenNotifJWTToken(repoID, user, exp)
	if err != nil {
		return &appError{err, "", http.StatusInternalServerError}
	}

	data := fmt.Sprintf("{\"jwt_token\":\"%s\"}", tokenString)

	rsp.Write([]byte(data))

	return nil
}

func getFsObjIDCB(rsp http.ResponseWriter, r *http.Request) *appError {
	recvChan := make(chan *calResult)

	calFsIdPool.AddTask(recvChan, rsp, r)
	result := <-recvChan
	return result.err
}

func headCommitOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getHeadCommit(rsp, r)
	} else if r.Method == http.MethodPut {
		return putUpdateBranchCB(rsp, r)
	}
	return &appError{nil, "", http.StatusBadRequest}
}

func commitOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getCommitInfo(rsp, r)
	} else if r.Method == http.MethodPut {
		return putCommitCB(rsp, r)
	}
	return &appError{nil, "", http.StatusBadRequest}
}

func blockOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getBlockInfo(rsp, r)
	} else if r.Method == http.MethodPut {
		return putSendBlockCB(rsp, r)
	}
	return &appError{nil, "", http.StatusBadRequest}
}

func putSendBlockCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	blockID := vars["id"]

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}

	appErr = checkPermission(repoID, user, "upload", false)
	if appErr != nil {
		return appErr
	}

	storeID, err := getRepoStoreID(repoID)
	if err != nil {
		err := fmt.Errorf("Failed to get repo store id by repo id %s: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	if err := blockmgr.Write(storeID, blockID, r.Body); err != nil {
		err := fmt.Errorf("Failed to write block %.8s:%s: %v", storeID, blockID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	sendStatisticMsg(storeID, user, "sync-file-upload", uint64(r.ContentLength))

	return nil
}

func getBlockInfo(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	blockID := vars["id"]

	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}

	appErr = checkPermission(repoID, user, "download", false)
	if appErr != nil {
		return appErr
	}

	storeID, err := getRepoStoreID(repoID)
	if err != nil {
		err := fmt.Errorf("Failed to get repo store id by repo id %s: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	blockSize, err := blockmgr.Stat(storeID, blockID)
	if err != nil {
		return &appError{err, "", http.StatusInternalServerError}
	}
	if blockSize <= 0 {
		err := fmt.Errorf("block %.8s:%s size invalid", storeID, blockID)
		return &appError{err, "", http.StatusInternalServerError}
	}

	blockLen := fmt.Sprintf("%d", blockSize)
	rsp.Header().Set("Content-Length", blockLen)
	if err := blockmgr.Read(storeID, blockID, rsp); err != nil {
		if !isNetworkErr(err) {
			log.Errorf("failed to read block %s: %v", blockID, err)
		}
		return nil
	}

	sendStatisticMsg(storeID, user, "sync-file-download", uint64(blockSize))
	return nil
}

func getRepoStoreID(repoID string) (string, error) {
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
		return storeID, nil
	}

	var vInfo virtualRepoInfo
	var rID, originRepoID sql.NullString
	sqlStr := "SELECT repo_id, origin_repo FROM VirtualRepo where repo_id = ?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&rID, &originRepoID); err != nil {
		if err == sql.ErrNoRows {
			vInfo.storeID = repoID
			vInfo.expireTime = time.Now().Unix() + virtualRepoExpireTime
			virtualRepoInfoCache.Store(repoID, &vInfo)
			return repoID, nil
		}
		return "", err
	}

	if !rID.Valid || !originRepoID.Valid {
		return "", nil
	}

	vInfo.storeID = originRepoID.String
	vInfo.expireTime = time.Now().Unix() + virtualRepoExpireTime
	virtualRepoInfoCache.Store(repoID, &vInfo)
	return originRepoID.String, nil
}

func sendStatisticMsg(repoID, user, operation string, bytes uint64) {
	rData := &statsEventData{operation, user, repoID, bytes}

	publishStatsEvent(rData)
}

func publishStatsEvent(rData *statsEventData) {
	data := make(map[string]interface{})
	data["msg_type"] = rData.eType
	data["user_name"] = rData.user
	data["repo_id"] = rData.repoID
	data["bytes"] = rData.bytes
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Warnf("Failed to publish event: %v", err)
		return
	}
	if _, err := rpcclient.Call("publish_event", seafileServerChannelStats, string(jsonData)); err != nil {
		log.Warnf("Failed to publish event: %v", err)
	}
}

func saveLastGCID(repoID, token string) error {
	repo := repomgr.Get(repoID)
	if repo == nil {
		return fmt.Errorf("failed to get repo: %s", repoID)
	}
	gcID, err := repomgr.GetCurrentGCID(repo.StoreID)
	if err != nil {
		return err
	}
	return repomgr.SetLastGCID(repoID, token, gcID)
}

func putCommitCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	commitID := vars["id"]
	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}
	appErr = checkPermission(repoID, user, "upload", true)
	if appErr != nil {
		return appErr
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return &appError{nil, err.Error(), http.StatusBadRequest}
	}

	commit := new(commitmgr.Commit)
	if err := commit.FromData(data); err != nil {
		return &appError{nil, err.Error(), http.StatusBadRequest}
	}

	if commit.RepoID != repoID {
		msg := "The repo id in commit does not match current repo id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if err := commitmgr.Save(commit); err != nil {
		err := fmt.Errorf("Failed to add commit %s: %v", commitID, err)
		return &appError{err, "", http.StatusInternalServerError}
	} else {
		token := r.Header.Get("Seafile-Repo-Token")
		if token == "" {
			token = utils.GetAuthorizationToken(r.Header)
		}
		if err := saveLastGCID(repoID, token); err != nil {
			err := fmt.Errorf("Failed to save gc id: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
	}

	return nil
}

func getCommitInfo(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	commitID := vars["id"]
	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}
	appErr = checkPermission(repoID, user, "download", false)
	if appErr != nil {
		return appErr
	}
	if exists, _ := commitmgr.Exists(repoID, commitID); !exists {
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

func putUpdateBranchCB(rsp http.ResponseWriter, r *http.Request) *appError {
	queries := r.URL.Query()
	newCommitID := queries.Get("head")
	if newCommitID == "" || !utils.IsObjectIDValid(newCommitID) {
		msg := fmt.Sprintf("commit id %s is invalid", newCommitID)
		return &appError{nil, msg, http.StatusBadRequest}
	}

	vars := mux.Vars(r)
	repoID := vars["repoid"]
	user, appErr := validateToken(r, repoID, false)
	if appErr != nil {
		return appErr
	}

	appErr = checkPermission(repoID, user, "upload", false)
	if appErr != nil && appErr.Code == http.StatusForbidden {
		return appErr
	}

	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("Repo %s is missing or corrupted", repoID)
		return &appError{err, "", http.StatusInternalServerError}
	}

	newCommit, err := commitmgr.Load(repoID, newCommitID)
	if err != nil {
		err := fmt.Errorf("Failed to get commit %s for repo %s", newCommitID, repoID)
		return &appError{err, "", http.StatusInternalServerError}
	}

	base, err := commitmgr.Load(repoID, newCommit.ParentID.String)
	if err != nil {
		err := fmt.Errorf("Failed to get commit %s for repo %s", newCommit.ParentID.String, repoID)
		return &appError{err, "", http.StatusInternalServerError}
	}

	if includeInvalidPath(base, newCommit) {
		msg := "Dir or file name is .."
		return &appError{nil, msg, http.StatusBadRequest}
	}

	ret, err := checkQuota(repoID, 0)
	if err != nil {
		err := fmt.Errorf("Failed to check quota: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}
	if ret == 1 {
		msg := "Out of quota.\n"
		return &appError{nil, msg, seafHTTPResNoQuota}
	}

	if option.VerifyClientBlocks {
		if body, err := checkBlocks(r.Context(), repo, base, newCommit); err != nil {
			return &appError{nil, body, seafHTTPResBlockMissing}
		}
	}

	token := r.Header.Get("Seafile-Repo-Token")
	if token == "" {
		token = utils.GetAuthorizationToken(r.Header)
	}
	if err := fastForwardOrMerge(user, token, repo, base, newCommit); err != nil {
		if errors.Is(err, ErrGCConflict) {
			return &appError{nil, "GC Conflict.\n", http.StatusConflict}
		} else {
			err := fmt.Errorf("Fast forward merge for repo %s is failed: %v", repoID, err)
			return &appError{err, "", http.StatusInternalServerError}
		}
	}

	go mergeVirtualRepoPool.AddTask(repoID, "")

	go updateSizePool.AddTask(repoID)

	rsp.WriteHeader(http.StatusOK)
	return nil
}

type checkBlockAux struct {
	storeID  string
	version  int
	fileList []string
}

func checkBlocks(ctx context.Context, repo *repomgr.Repo, base, remote *commitmgr.Commit) (string, error) {
	aux := new(checkBlockAux)
	aux.storeID = repo.StoreID
	aux.version = repo.Version
	opt := &diff.DiffOptions{
		FileCB: checkFileBlocks,
		DirCB:  checkDirCB,
		Ctx:    ctx,
		RepoID: repo.StoreID}
	opt.Data = aux

	trees := []string{base.RootID, remote.RootID}
	if err := diff.DiffTrees(trees, opt); err != nil {
		return "", err
	}

	if len(aux.fileList) == 0 {
		return "", nil
	}

	body, _ := json.Marshal(aux.fileList)

	return string(body), fmt.Errorf("block is missing")
}

func checkFileBlocks(ctx context.Context, baseDir string, files []*fsmgr.SeafDirent, data interface{}) error {
	select {
	case <-ctx.Done():
		return context.Canceled
	default:
	}

	file1 := files[0]
	file2 := files[1]

	aux, ok := data.(*checkBlockAux)
	if !ok {
		err := fmt.Errorf("failed to assert results")
		return err
	}

	if file2 == nil || file2.ID == emptySHA1 || (file1 != nil && file1.ID == file2.ID) {
		return nil
	}

	file, err := fsmgr.GetSeafile(aux.storeID, file2.ID)
	if err != nil {
		return err
	}
	for _, blkID := range file.BlkIDs {
		if !blockmgr.Exists(aux.storeID, blkID) {
			aux.fileList = append(aux.fileList, file2.Name)
			return nil
		}
	}

	return nil
}

func checkDirCB(ctx context.Context, baseDir string, dirs []*fsmgr.SeafDirent, data interface{}, recurse *bool) error {
	select {
	case <-ctx.Done():
		return context.Canceled
	default:
	}

	return nil
}

func includeInvalidPath(baseCommit, newCommit *commitmgr.Commit) bool {
	var results []*diff.DiffEntry
	if err := diff.DiffCommits(baseCommit, newCommit, &results, true); err != nil {
		log.Infof("Failed to diff commits: %v", err)
		return false
	}

	for _, entry := range results {
		if entry.NewName != "" {
			if shouldIgnore(entry.NewName) {
				return true
			}
		} else {
			if shouldIgnore(entry.Name) {
				return true
			}
		}
	}

	return false
}

func getHeadCommit(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	sqlStr := "SELECT EXISTS(SELECT 1 FROM Repo WHERE repo_id=?)"
	var exists bool
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			log.Errorf("DB error when check repo %s existence: %v", repoID, err)
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
	row = seafileDB.QueryRowContext(ctx, sqlStr, repoID)

	if err := row.Scan(&commitID); err != nil {
		if err != sql.ErrNoRows {
			log.Errorf("DB error when get branch master: %v", err)
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
		if value, ok := permCache.Load(fmt.Sprintf("%s:%s:%s", repoID, user, op)); ok {
			info = value.(*permInfo)
		}
	}
	if info != nil {
		return nil
	}

	permCache.Delete(fmt.Sprintf("%s:%s:%s", repoID, user, op))

	if op == "upload" {
		status, err := repomgr.GetRepoStatus(repoID)
		if err != nil {
			msg := fmt.Sprintf("Failed to get repo status by repo id %s: %v", repoID, err)
			return &appError{nil, msg, http.StatusForbidden}
		}
		if status != repomgr.RepoStatusNormal && status != -1 {
			return &appError{nil, "", http.StatusForbidden}
		}
	}

	perm := share.CheckPerm(repoID, user)
	if perm != "" {
		if perm == "r" && op == "upload" {
			return &appError{nil, "", http.StatusForbidden}
		}
		info = new(permInfo)
		info.perm = perm
		info.expireTime = time.Now().Unix() + permExpireTime
		permCache.Store(fmt.Sprintf("%s:%s:%s", repoID, user, op), info)
		return nil
	}

	return &appError{nil, "", http.StatusForbidden}
}

func validateToken(r *http.Request, repoID string, skipCache bool) (string, *appError) {
	token := r.Header.Get("Seafile-Repo-Token")
	if token == "" {
		token = utils.GetAuthorizationToken(r.Header)
		if token == "" {
			msg := "token is null"
			return "", &appError{nil, msg, http.StatusBadRequest}
		}
	}

	if !skipCache {
		if value, ok := tokenCache.Load(token); ok {
			if info, ok := value.(*tokenInfo); ok {
				if info.repoID != repoID {
					msg := "Invalid token"
					return "", &appError{nil, msg, http.StatusForbidden}
				}
				return info.email, nil
			}
		}
	}

	email, err := repomgr.GetEmailByToken(repoID, token)
	if err != nil {
		log.Errorf("Failed to get email by token %s: %v", token, err)
		tokenCache.Delete(token)
		return email, &appError{err, "", http.StatusInternalServerError}
	}
	if email == "" {
		tokenCache.Delete(token)
		msg := fmt.Sprintf("Failed to get email by token %s", token)
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
		log.Errorf("Failed to get virtual repo info by repo id %s: %v", repoID, err)
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
	data := make(map[string]interface{})
	data["msg_type"] = rData.eType
	data["user_name"] = rData.user
	data["ip"] = rData.ip
	data["user_agent"] = rData.clientName
	data["repo_id"] = rData.repoID
	data["file_path"] = rData.path
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Warnf("Failed to publish event: %v", err)
		return
	}
	if _, err := rpcclient.Call("publish_event", seafileServerChannelEvent, string(jsonData)); err != nil {
		log.Warnf("Failed to publish event: %v", err)
	}
}

func publishUpdateEvent(repoID string, commitID string) {
	data := make(map[string]interface{})
	data["msg_type"] = "repo-update"
	data["repo_id"] = repoID
	data["commit_id"] = commitID
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Warnf("Failed to publish event: %v", err)
		return
	}
	if _, err := rpcclient.Call("publish_event", seafileServerChannelEvent, string(jsonData)); err != nil {
		log.Warnf("Failed to publish event: %v", err)
	}
}

func removeSyncAPIExpireCache() {
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

type collectFsInfo struct {
	startTime int64
	isTimeout bool
	results   []interface{}
}

var ErrTimeout = fmt.Errorf("get fs id list timeout")

func calculateSendObjectList(ctx context.Context, repo *repomgr.Repo, serverHead string, clientHead string, dirOnly bool) ([]interface{}, error) {
	masterHead, err := commitmgr.Load(repo.ID, serverHead)
	if err != nil {
		err := fmt.Errorf("Failed to load server head commit %s:%s: %v", repo.ID, serverHead, err)
		return nil, err
	}
	var remoteHead *commitmgr.Commit
	remoteHeadRoot := emptySHA1
	if clientHead != "" {
		remoteHead, err = commitmgr.Load(repo.ID, clientHead)
		if err != nil {
			err := fmt.Errorf("Failed to load remote head commit %s:%s: %v", repo.ID, clientHead, err)
			return nil, err
		}
		remoteHeadRoot = remoteHead.RootID
	}

	info := new(collectFsInfo)
	info.startTime = time.Now().Unix()
	if remoteHeadRoot != masterHead.RootID && masterHead.RootID != emptySHA1 {
		info.results = append(info.results, masterHead.RootID)
	}

	var opt *diff.DiffOptions
	if !dirOnly {
		opt = &diff.DiffOptions{
			FileCB: collectFileIDs,
			DirCB:  collectDirIDs,
			Ctx:    ctx,
			RepoID: repo.StoreID}
		opt.Data = info
	} else {
		opt = &diff.DiffOptions{
			FileCB: collectFileIDsNOp,
			DirCB:  collectDirIDs,
			Ctx:    ctx,
			RepoID: repo.StoreID}
		opt.Data = info
	}
	trees := []string{masterHead.RootID, remoteHeadRoot}

	if err := diff.DiffTrees(trees, opt); err != nil {
		if info.isTimeout {
			return nil, ErrTimeout
		}
		return nil, err
	}
	return info.results, nil
}

func collectFileIDs(ctx context.Context, baseDir string, files []*fsmgr.SeafDirent, data interface{}) error {
	select {
	case <-ctx.Done():
		return context.Canceled
	default:
	}

	file1 := files[0]
	file2 := files[1]
	info, ok := data.(*collectFsInfo)
	if !ok {
		err := fmt.Errorf("failed to assert results")
		return err
	}

	if file1 != nil &&
		(file2 == nil || file1.ID != file2.ID) &&
		file1.ID != emptySHA1 {
		info.results = append(info.results, file1.ID)
	}

	return nil
}

func collectFileIDsNOp(ctx context.Context, baseDir string, files []*fsmgr.SeafDirent, data interface{}) error {
	return nil
}

func collectDirIDs(ctx context.Context, baseDir string, dirs []*fsmgr.SeafDirent, data interface{}, recurse *bool) error {
	select {
	case <-ctx.Done():
		return context.Canceled
	default:
	}

	info, ok := data.(*collectFsInfo)
	if !ok {
		err := fmt.Errorf("failed to assert fs info")
		return err
	}
	dir1 := dirs[0]
	dir2 := dirs[1]

	if dir1 != nil &&
		(dir2 == nil || dir1.ID != dir2.ID) &&
		dir1.ID != emptySHA1 {
		info.results = append(info.results, dir1.ID)
	}

	if option.FsIdListRequestTimeout > 0 {
		now := time.Now().Unix()
		if now-info.startTime > option.FsIdListRequestTimeout {
			info.isTimeout = true
			return ErrTimeout
		}
	}

	return nil
}
