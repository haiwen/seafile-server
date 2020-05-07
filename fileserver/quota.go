package main

import (
	"database/sql"
	"fmt"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"gopkg.in/ini.v1"
	"path/filepath"
	"strconv"
	"strings"
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
		err := fmt.Errorf("failed to get user usage")
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
	row := seafileDB.QueryRow(sqlStr, user)
	if err := row.Scan(&quota); err != nil {
		if err != sql.ErrNoRows {
			return -1, err
		}
	}

	if quota <= 0 {
		quota = getDefaultQuota()
	}

	return quota, nil
}

// Storage unit.
const (
	KB = 1000
	MB = 1000000
	GB = 1000000000
	TB = 1000000000000
)

func getDefaultQuota() int64 {
	seafileConfPath := filepath.Join(absDataDir, "seafile.conf")
	config, err := ini.Load(seafileConfPath)
	if err != nil {
		return InfiniteQuota
	}
	var quota int64
	section, err := config.GetSection("quota")
	if err != nil {
		return InfiniteQuota
	}
	key, err := section.GetKey("default")
	if err != nil {
		return InfiniteQuota
	}
	quotaStr := key.String()
	quota = parseQuota(quotaStr)

	return quota
}

func parseQuota(quotaStr string) int64 {
	var quota int64
	var multiplier int64 = GB
	if end := strings.Index(quotaStr, "kb"); end > 0 {
		multiplier = KB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "mb"); end > 0 {
		multiplier = MB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "gb"); end > 0 {
		multiplier = GB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "tb"); end > 0 {
		multiplier = TB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else {
		quotaInt, err := strconv.ParseInt(quotaStr, 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	}

	return quota
}

func getUserUsage(user string) (int64, error) {
	var usage int64
	sqlStr := "SELECT SUM(size) FROM " +
		"RepoOwner o LEFT JOIN VirtualRepo v ON o.repo_id=v.repo_id, " +
		"RepoSize WHERE " +
		"owner_id=? AND o.repo_id=RepoSize.repo_id " +
		"AND v.repo_id IS NULL"

	row := seafileDB.QueryRow(sqlStr, user)
	if err := row.Scan(&usage); err != nil {
		if err != sql.ErrNoRows {
			return -1, err
		}
	}

	return usage, nil
}
