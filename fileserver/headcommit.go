package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func headCommitOperCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == http.MethodGet {
		return getHeadCommit(r)
	} else if r.Method == http.MethodPut {
		return nil
	}
	return &appError{nil, "", http.StatusBadRequest}
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

	if _, err := validateToken(r, repoID, false); err != nil {
		return err
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
