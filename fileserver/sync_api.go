package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/diff"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/share"
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
	ticker := time.NewTicker(time.Second * syncAPICleaningIntervalSec)
	go func() {
		for range ticker.C {
			removeSyncAPIExpireCache()
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
func getBlockMapCB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	fileID := vars["id"]

	_, appErr := validateToken(r, repoID, false)
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

	if repoID == "" || !isValidUUID(repoID) {
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
	fsBuf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return &appError{nil, err.Error(), http.StatusBadRequest}
	}

	for len(fsBuf) > 44 {
		objID := string(fsBuf[:40])
		if !isObjectIDValid(objID) {
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

	_, appErr := validateToken(r, repoID, false)
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
		if !isObjectIDValid(objIDList[i]) {
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

	_, appErr := validateToken(r, repoID, false)
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

	var data bytes.Buffer
	for i := 0; i < len(fsIDList); i++ {
		if !isObjectIDValid(fsIDList[i]) {
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
		if !isValidUUID(repoIDList[i]) {
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

	rows, err := seafileDB.Query(sqlStr)
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

func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func getFsObjIDCB(rsp http.ResponseWriter, r *http.Request) *appError {
	queries := r.URL.Query()

	serverHead := queries.Get("server-head")
	if !isObjectIDValid(serverHead) {
		msg := "Invalid server-head parameter."
		return &appError{nil, msg, http.StatusBadRequest}
	}

	clientHead := queries.Get("client-head")
	if clientHead != "" && !isObjectIDValid(clientHead) {
		msg := "Invalid client-head parameter."
		return &appError{nil, msg, http.StatusBadRequest}
	}

	dirOnlyArg := queries.Get("dir-only")
	var dirOnly bool
	if dirOnlyArg != "" {
		dirOnly = true
	}

	vars := mux.Vars(r)
	repoID := vars["repoid"]
	if _, err := validateToken(r, repoID, false); err != nil {
		return err
	}
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("Failed to find repo %.8s", repoID)
		return &appError{err, "", http.StatusInternalServerError}
	}
	ret, err := calculateSendObjectList(r.Context(), repo, serverHead, clientHead, dirOnly)
	if err != nil {
		err := fmt.Errorf("Failed to get fs id list: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	var objList []byte
	if ret != nil {
		objList, err = json.Marshal(ret)
		if err != nil {
			return &appError{err, "", http.StatusInternalServerError}
		}
	} else {
		// when get obj list is nil, return []
		objList = []byte{'[', ']'}
	}

	rsp.Header().Set("Content-Length", strconv.Itoa(len(objList)))
	rsp.WriteHeader(http.StatusOK)
	rsp.Write(objList)

	return nil
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
		err := fmt.Errorf("Failed to close block %.8s:%s", storeID, blockID)
		return &appError{err, "", http.StatusInternalServerError}
	}

	rsp.WriteHeader(http.StatusOK)

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
	rsp.WriteHeader(http.StatusOK)
	if err := blockmgr.Read(storeID, blockID, rsp); err != nil {
		return &appError{err, "", http.StatusInternalServerError}
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
	row := seafileDB.QueryRow(sqlStr, repoID)
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

	data, err := ioutil.ReadAll(r.Body)
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
	}

	rsp.WriteHeader(http.StatusOK)

	return nil
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

func putUpdateBranchCB(rsp http.ResponseWriter, r *http.Request) *appError {
	queries := r.URL.Query()
	newCommitID := queries.Get("head")
	if newCommitID == "" || !isObjectIDValid(newCommitID) {
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

	base, err := commitmgr.Load(repoID, newCommit.ParentID)
	if err != nil {
		err := fmt.Errorf("Failed to get commit %s for repo %s", newCommit.ParentID, repoID)
		return &appError{err, "", http.StatusInternalServerError}
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

	if err := fastForwardOrMerge(user, repo, base, newCommit); err != nil {
		err := fmt.Errorf("Fast forward merge for repo %s is failed: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	mergeVirtualRepo(repoID, "")

	if err := computeRepoSize(repoID); err != nil {
		return &appError{err, "", http.StatusInternalServerError}
	}

	rsp.WriteHeader(http.StatusOK)
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

	var results []interface{}
	if remoteHeadRoot != masterHead.RootID && masterHead.RootID != emptySHA1 {
		results = append(results, masterHead.RootID)
	}

	var opt *diff.DiffOptions
	if !dirOnly {
		opt = &diff.DiffOptions{
			FileCB: collectFileIDs,
			DirCB:  collectDirIDs,
			Ctx:    ctx,
			RepoID: repo.ID}
		opt.Data = &results
	} else {
		opt = &diff.DiffOptions{
			FileCB: collectFileIDsNOp,
			DirCB:  collectDirIDs,
			Ctx:    ctx,
			RepoID: repo.ID}
		opt.Data = &results
	}
	trees := []string{masterHead.RootID, remoteHeadRoot}

	if err := diff.DiffTrees(trees, opt); err != nil {
		return nil, err
	}
	return results, nil
}

func collectFileIDs(ctx context.Context, baseDir string, files []*fsmgr.SeafDirent, data interface{}) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("request canceled")
	default:
	}

	file1 := files[0]
	file2 := files[1]
	results, ok := data.(*[]interface{})
	if !ok {
		err := fmt.Errorf("failed to assert results")
		return err
	}

	if file1 != nil &&
		(file2 == nil || file1.ID != file2.ID) &&
		file1.ID != emptySHA1 {
		*results = append(*results, file1.ID)
	}

	return nil
}

func collectFileIDsNOp(ctx context.Context, baseDir string, files []*fsmgr.SeafDirent, data interface{}) error {
	return nil
}

func collectDirIDs(ctx context.Context, baseDir string, dirs []*fsmgr.SeafDirent, data interface{}, recurse *bool) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("request canceled")
	default:
	}

	dir1 := dirs[0]
	dir2 := dirs[1]
	results, ok := data.(*[]interface{})
	if !ok {
		err := fmt.Errorf("failed to assert results")
		return err
	}

	if dir1 != nil &&
		(dir2 == nil || dir1.ID != dir2.ID) &&
		dir1.ID != emptySHA1 {
		*results = append(*results, dir1.ID)
	}

	return nil
}

func isObjectIDValid(objID string) bool {
	if len(objID) != 40 {
		return false
	}
	for i := 0; i < len(objID); i++ {
		c := objID[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
