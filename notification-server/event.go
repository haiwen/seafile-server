package main

import (
	"context"
	"encoding/json"
	"reflect"
	"runtime/debug"
	"time"

	log "github.com/sirupsen/logrus"
)

type RepoUpdateEvent struct {
	RepoID   string `json:"repo_id"`
	CommitID string `json:"commit_id"`
}

type FileLockEvent struct {
	RepoID      string `json:"repo_id"`
	Path        string `json:"path"`
	ChangeEvent string `json:"change_event"`
	LockUser    string `json:"lock_user"`
}

type FolderPermEvent struct {
	RepoID      string `json:"repo_id"`
	Path        string `json:"path"`
	Type        string `json:"type"`
	ChangeEvent string `json:"change_event"`
	User        string `json:"user"`
	Group       int    `json:"group"`
	Perm        string `json:"perm"`
}

func Notify(msg *Message) {
	var repoID string
	// userList is the list of users who need to be notified, if it is nil, all subscribed users will be notified.
	var userList map[string]struct{}

	content := msg.Content
	switch msg.Type {
	case "repo-update":
		var event RepoUpdateEvent
		err := json.Unmarshal(content, &event)
		if err != nil {
			log.Warn(err)
			return
		}
		repoID = event.RepoID
	case "file-lock-changed":
		var event FileLockEvent
		err := json.Unmarshal(content, &event)
		if err != nil {
			log.Warn(err)
			return
		}
		repoID = event.RepoID
	case "folder-perm-changed":
		var event FolderPermEvent
		err := json.Unmarshal(content, &event)
		if err != nil {
			log.Warn(err)
			return
		}
		repoID = event.RepoID
		if event.User != "" {
			userList = make(map[string]struct{})
			userList[event.User] = struct{}{}
		} else if event.Group != -1 {
			userList = getGroupMembers(event.Group)
		}
	default:
		return
	}

	clients := make(map[uint64]*Client)

	subMutex.RLock()
	subscribers := subscriptions[repoID]
	if subscribers == nil {
		subMutex.RUnlock()
		return
	}
	subMutex.RUnlock()

	subscribers.Mutex.RLock()
	for clientID, client := range subscribers.Clients {
		clients[clientID] = client
	}
	subscribers.Mutex.RUnlock()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v\n%s", err, debug.Stack())
			}
		}()
		// In order to avoid being blocked on a Client for a long time, it is necessary to write WCh in a non-blocking way,
		// and the waiting WCh needs to be blocked and processed after other Clients have finished writing.
		value := reflect.ValueOf(msg)
		var branches []reflect.SelectCase
		for _, client := range clients {
			if !needToNotif(userList, client.User) {
				continue
			}
			branch := reflect.SelectCase{Dir: reflect.SelectSend, Chan: reflect.ValueOf(client.WCh), Send: value}
			branches = append(branches, branch)
		}

		for len(branches) != 0 {
			index, _, _ := reflect.Select(branches)
			branches = append(branches[:index], branches[index+1:]...)
		}
	}()
}

func getGroupMembers(group int) map[string]struct{} {
	query := `SELECT user_name FROM GroupUser WHERE group_id = ?`
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	stmt, err := ccnetDB.PrepareContext(ctx, query)
	if err != nil {
		log.Printf("failed to prepare sql: %s：%v", query, err)
		return nil
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, group)
	if err != nil {
		log.Printf("failed to query sql: %v", err)
		return nil
	}
	defer rows.Close()

	userList := make(map[string]struct{})
	var userName string

	for rows.Next() {
		if err := rows.Scan(&userName); err == nil {
			userList[userName] = struct{}{}
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("failed to scan sql rows: %v", err)
		return nil
	}

	return userList
}

func needToNotif(userList map[string]struct{}, user string) bool {
	if userList == nil {
		return true
	}

	_, ok := userList[user]
	return ok
}
