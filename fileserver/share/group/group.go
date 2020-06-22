// Package group manages group membership and group shares.
package group

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

type group struct {
	id            int
	groupName     string
	creatorName   string
	timestamp     int64
	parentGroupID int
}

var ccnetDB *sql.DB
var seafileDB *sql.DB
var tableName string

// Init ccnet db and seafile db
func Init(cnDB *sql.DB, seafDB *sql.DB, tbName string) {
	ccnetDB = cnDB
	seafileDB = seafDB
	tableName = tbName
}

func getGroupsByUser(userName string, returnAncestors bool) ([]group, error) {
	sql := fmt.Sprintf("SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "+
		"`%s` g, GroupUser u WHERE g.group_id = u.group_id AND user_name=? ORDER BY g.group_id DESC",
		tableName)
	rows, err := ccnetDB.Query(sql, userName)
	if err != nil {
		return nil, err
	}
	var groups []group
	for rows.Next() {
		var g group
		rows.Scan(&g.id, &g.groupName, &g.creatorName, &g.timestamp, &g.parentGroupID)
		groups = append(groups, g)
	}

	if !returnAncestors {
		return groups, nil
	}
	return groups, nil
}

// CheckGroupPermissionByUser get group repo permission by user
func CheckGroupPermissionByUser(repoID string, userName string) (string, error) {
	groups, err := getGroupsByUser(userName, false)
	if err != nil {
		return "", err
	}
	if len(groups) == 0 {
		return "", nil
	}

	var sql strings.Builder
	sql.WriteString("SELECT permission FROM RepoGroup WHERE repo_id = ? AND group_id IN (")
	for i := 0; i < len(groups); i++ {
		sql.WriteString(strconv.Itoa(groups[i].id))
		if i+1 < len(groups) {
			sql.WriteString(",")
		}
	}
	sql.WriteString(")")

	rows, err := seafileDB.Query(sql.String(), repoID)
	if err != nil {
		return "", err
	}
	var perm string
	var origPerm string
	for rows.Next() {
		if err := rows.Scan(&perm); err != nil {
			return "", err
		}
		if perm == "rw" {
			origPerm = perm
		} else if perm == "r" && origPerm == "" {
			origPerm = perm
		}
	}
	return origPerm, nil
}
