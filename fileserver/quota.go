package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/haiwen/seafile-server/fileserver/option"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

// InfiniteQuota indicates that the quota is unlimited.
const (
	InfiniteQuota = -2
)

func checkQuota(repoID string, delta int64) (int, error) {
	if repoID == "" {
		err := fmt.Errorf("bad argumets")
		return -1, err
	}

	vInfo, err := repomgr.GetVirtualRepoInfo(repoID)
	if err != nil {
		err := fmt.Errorf("failed to get virtual repo: %v", err)
		return -1, err
	}
	rRepoID := repoID
	if vInfo != nil {
		rRepoID = vInfo.OriginRepoID
	}

	user, err := repomgr.GetRepoOwner(rRepoID)
	if err != nil {
		err := fmt.Errorf("failed to get repo owner: %v", err)
		return -1, err
	}
	if user == "" {
		err := fmt.Errorf("repo %s has no owner", repoID)
		return -1, err
	}
	quota, err := getUserQuota(user)
	if err != nil {
		err := fmt.Errorf("failed to get user quota: %v", err)
		return -1, err
	}

	if quota == InfiniteQuota {
		return 0, nil
	}
	usage, err := getUserUsage(user)
	if err != nil || usage < 0 {
		err := fmt.Errorf("failed to get user usage: %v", err)
		return -1, err
	}
	usage += delta
	if usage >= quota {
		return 1, nil
	}

	return 0, nil
}

func getUserQuota(user string) (int64, error) {
	var quota int64
	sqlStr := "SELECT quota FROM UserQuota WHERE user=?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, user)
	if err := row.Scan(&quota); err != nil {
		if err != sql.ErrNoRows {
			return -1, err
		}
	}

	if quota <= 0 {
		quota = option.DefaultQuota
	}

	return quota, nil
}

func getUserUsage(user string) (int64, error) {
	var usage sql.NullInt64
	sqlStr := "SELECT SUM(size) FROM " +
		"RepoOwner o LEFT JOIN VirtualRepo v ON o.repo_id=v.repo_id, " +
		"RepoSize WHERE " +
		"owner_id=? AND o.repo_id=RepoSize.repo_id " +
		"AND v.repo_id IS NULL"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, user)
	if err := row.Scan(&usage); err != nil {
		if err != sql.ErrNoRows {
			return -1, err
		}
	}

	if usage.Valid {
		return usage.Int64, nil
	}

	return 0, nil
}
