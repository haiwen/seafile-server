package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

func headCommitOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getHeadCommit(r)
	} else if r.Method == http.MethodPut {

	}
	return &appError{nil, "", http.StatusBadRequest}
}

func putUpdateBranch(r *http.Request) *appError {
	quries := r.URL.Query()
	newCommitID := quries.Get("head")
	if newCommitID == "" || !isObjectIDValid(newCommitID) {
		return &appError{nil, "", http.StatusBadRequest}
	}

	var username string
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	tokenStatus, _ := validateToken(r, repoID, &username, false)
	if tokenStatus != http.StatusOK {
		return &appError{nil, "", tokenStatus}
	}
	permStatus := checkPermission(repoID, username, "upload", false)
	if permStatus != http.StatusOK {
		return &appError{nil, "", permStatus}
	}

	repo := repomgr.Get(repoID)
	if repo == nil {
		log.Printf("Repo %s is missing or corrupted.", repoID)
		return &appError{nil, "", http.StatusInternalServerError}
	}
	newCommit, err := commitmgr.Load(repoID, newCommitID)
	if err != nil {
		log.Println("Failed to get commit %s for repo %s: %v\n", newCommitID, repoID, err)
		return &appError{nil, "", http.StatusInternalServerError}
	}

	baseCommit, err := commitmgr.Load(repoID, newCommit.ParentID)
	if err != nil {
		log.Println("Failed to get commit %s for repo %s: %v\n", newCommit.ParentID, repoID, err)
		return &appError{nil, "", http.StatusInternalServerError}
	}

	ret, err := rpcclient.Call("seafile_check_quota", repoID, 0)
	return nil
}

func getHeadCommit(r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	sqlStr := "SELECT EXISTS(SELECT 1 FROM Repo WHERE repo_id=?)"
	var exists bool
	row := seafileDB.QueryRow(sqlStr, repoID)
	if err := row.Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("DB error when check repo %s existence: %v", repoID, err)
			msg := `{"is_corrupted": 1}`
			return &appError{nil, msg, http.StatusOK}
		}
	}
	if !exists {
		return &appError{nil, "", http.StatusBadRequest}
	}

	status, _ := validateToken(r, repoID, nil, false)
	if status != http.StatusOK {
		return &appError{nil, "", status}
	}

	var commitID string
	sqlStr = "SELECT commit_id FROM Branch WHERE name='master' AND repo_id=?"
	row = seafileDB.QueryRow(sqlStr, repoID)

	if err := row.Scan(&commitID); err != nil {
		if err != sql.ErrNoRows {
			log.Println("DB error when get branch master.")
			msg := `{"is_corrupted": 1}`
			return &appError{nil, msg, http.StatusOK}
		}
	}
	if commitID[0] == '0' {
		return &appError{nil, "", http.StatusBadRequest}
	}

	msg := fmt.Sprintf("{\"is_corrupted\": 0, \"head_commit_id\": \"%s\"}", commitID)
	return &appError{nil, msg, http.StatusOK}
}

func isObjectIDValid(objID string) bool {
	if objID == "" {
		return false
	}
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
