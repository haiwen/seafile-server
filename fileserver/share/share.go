// Package share manages share relations.
// share: manages personal shares and provide high level permission check functions.
package share

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/haiwen/seafile-server/fileserver/repomgr"
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
var groupTableName string
var cloudMode bool

// Init ccnetDB, seafileDB, groupTableName, cloudMode
func Init(cnDB *sql.DB, seafDB *sql.DB, grpTableName string, clMode bool) {
	ccnetDB = cnDB
	seafileDB = seafDB
	groupTableName = grpTableName
	cloudMode = clMode
}

// CheckPerm get user's repo permission
func CheckPerm(repoID string, user string) string {
	var perm string
	vInfo, err := repomgr.GetVirtualRepoInfo(repoID)
	if err != nil {
		log.Printf("Failed to get virtual repo info by repo id %s: %v", repoID, err)
	}
	if vInfo != nil {
		perm = checkVirtualRepoPerm(repoID, vInfo.OriginRepoID, user, vInfo.Path)
		return perm
	}

	perm = checkRepoSharePerm(repoID, user)

	return perm
}

func checkVirtualRepoPerm(repoID, originRepoID, user, vPath string) string {
	owner := getRepoOwner(repoID)
	var perm string
	if owner != "" && owner == user {
		perm = "rw"
		return perm
	}
	perm = checkPermOnParentRepo(originRepoID, user, vPath)
	if perm != "" {
		return perm
	}
	perm = checkRepoSharePerm(repoID, user)
	return perm
}

func getUserGroups(sqlStr string, args ...interface{}) ([]group, error) {
	rows, err := ccnetDB.Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var groups []group
	var g group
	for rows.Next() {
		if err := rows.Scan(&g.id, &g.groupName, &g.creatorName, &g.timestamp, &g.parentGroupID); err != nil {
			continue
		}
		groups = append(groups, g)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

func getGroupsByUser(userName string, returnAncestors bool) []group {
	sqlStr := fmt.Sprintf("SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "+
		"`%s` g, GroupUser u WHERE g.group_id = u.group_id AND user_name=? ORDER BY g.group_id DESC",
		groupTableName)
	groups, err := getUserGroups(sqlStr, userName)
	if err != nil {
		log.Printf("Failed to get groups by user %s: %v", userName, err)
	}
	if !returnAncestors {
		return groups
	}

	sqlStr = ""
	var ret []group
	for _, group := range groups {
		parentGroupID := group.parentGroupID
		groupID := group.id
		if parentGroupID != 0 {
			if sqlStr == "" {
				sqlStr = fmt.Sprintf("SELECT path FROM GroupStructure WHERE group_id IN (%d",
					groupID)
			} else {
				sqlStr += fmt.Sprintf(", %d", groupID)
			}
		} else {
			ret = append(ret, group)
		}
	}
	if sqlStr != "" {
		sqlStr += ")"
		paths, err := getGroupPaths(sqlStr)
		if err != nil {
			log.Printf("Failed to get group paths: %v", err)
		}
		if paths == "" {
			return nil
		}

		sqlStr = fmt.Sprintf("SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "+
			"`%s` g WHERE g.group_id IN (%s) ORDER BY g.group_id DESC",
			groupTableName, paths)
		ret, err = getUserGroups(sqlStr)
		if err != nil {
			log.Printf("Failed to get groups: %v", err)
		}
	}
	return ret
}

func getGroupPaths(sqlStr string) (string, error) {
	var paths string
	rows, err := ccnetDB.Query(sqlStr)
	if err != nil {
		return paths, err
	}

	defer rows.Close()

	var path string
	for rows.Next() {
		rows.Scan(&path)
		if paths == "" {
			paths = path
		} else {
			paths += fmt.Sprintf(", %s", path)
		}
	}

	if err := rows.Err(); err != nil {
		return "", err
	}
	return paths, nil
}

func checkGroupPermByUser(repoID string, userName string) string {
	groups := getGroupsByUser(userName, false)
	if len(groups) == 0 {
		return ""
	}

	var sqlStr strings.Builder
	sqlStr.WriteString("SELECT permission FROM RepoGroup WHERE repo_id = ? AND group_id IN (")
	for i := 0; i < len(groups); i++ {
		sqlStr.WriteString(strconv.Itoa(groups[i].id))
		if i+1 < len(groups) {
			sqlStr.WriteString(",")
		}
	}
	sqlStr.WriteString(")")

	rows, err := seafileDB.Query(sqlStr.String(), repoID)
	if err != nil {
		log.Printf("Failed to get group permission by user %s: %v", userName, err)
		return ""
	}

	defer rows.Close()

	var perm string
	var origPerm string
	for rows.Next() {
		if err := rows.Scan(&perm); err != nil {
			log.Printf("Failed to get group permission for user %s: %v", userName, err)
			continue
		}
		if perm == "rw" {
			origPerm = perm
		} else if perm == "r" && origPerm == "" {
			origPerm = perm
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Failed to get group permission for user %s: %v", userName, err)
		return ""
	}

	return origPerm
}

func checkSharedRepoPerm(repoID string, email string) string {
	sqlStr := "SELECT permission FROM SharedRepo WHERE repo_id=? AND to_email=?"
	row := seafileDB.QueryRow(sqlStr, repoID, email)

	var perm string
	if err := row.Scan(&perm); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Failed to check shared repo permission: %v", err)
			return ""
		}
	}
	return perm
}

func checkInnerPubRepoPerm(repoID string) string {
	sqlStr := "SELECT permission FROM InnerPubRepo WHERE repo_id=?"
	row := seafileDB.QueryRow(sqlStr, repoID)

	var perm string
	if err := row.Scan(&perm); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Failed to check inner public repo permission: %v", err)
			return ""
		}
	}

	return perm
}

func checkRepoSharePerm(repoID string, userName string) string {
	var perm string
	owner := getRepoOwner(repoID)
	if owner != "" && owner == userName {
		perm = "rw"
		return perm
	}
	perm = checkSharedRepoPerm(repoID, userName)
	if perm != "" {
		return perm
	}
	perm = checkGroupPermByUser(repoID, userName)
	if perm != "" {
		return perm
	}
	if !cloudMode {
		return checkInnerPubRepoPerm(repoID)
	}
	return ""
}

func getRepoOwner(repoID string) string {
	sqlStr := "SELECT owner_id FROM RepoOwner WHERE repo_id=?"
	row := seafileDB.QueryRow(sqlStr, repoID)

	var owner string
	if err := row.Scan(&owner); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Failed to get repo owner: %v", err)
			return ""
		}
	}
	return strings.ToLower(owner)
}

func getSharedDirsToUser(originRepoID string, toEmail string) map[string]string {
	dirs := make(map[string]string)
	sqlStr := "SELECT v.path, s.permission FROM SharedRepo s, VirtualRepo v WHERE " +
		"s.repo_id = v.repo_id AND s.to_email = ? AND v.origin_repo = ?"

	rows, err := seafileDB.Query(sqlStr, toEmail, originRepoID)
	if err != nil {
		log.Printf("Failed to get shared directories by user %s: %v", toEmail, err)
		return nil
	}

	defer rows.Close()

	var path string
	var perm string
	for rows.Next() {
		if err := rows.Scan(&path, &perm); err != nil {
			log.Printf("Failed to get shared directories by user %s: %v", toEmail, err)
			continue
		}
		dirs[path] = perm
	}
	if err := rows.Err(); err != nil {
		log.Printf("Failed to get shared directories by user %s: %v", toEmail, err)
		return nil
	}

	return dirs
}

func getDirPerm(perms map[string]string, path string) string {
	tmp := path
	var perm string
	for tmp != "" {
		if perm, exists := perms[tmp]; exists {
			return perm
		}
		tmp = filepath.Dir(tmp)
	}
	return perm
}

func convertGroupListToStr(groups []group) string {
	var groupIDs strings.Builder

	for i, group := range groups {
		groupIDs.WriteString(strconv.Itoa(group.id))
		if i+1 < len(groups) {
			groupIDs.WriteString(",")
		}
	}
	return groupIDs.String()
}

func getSharedDirsToGroup(originRepoID string, groups []group) map[string]string {
	dirs := make(map[string]string)
	groupIDs := convertGroupListToStr(groups)

	sqlStr := fmt.Sprintf("SELECT v.path, s.permission "+
		"FROM RepoGroup s, VirtualRepo v WHERE "+
		"s.repo_id = v.repo_id AND v.origin_repo = ? "+
		"AND s.group_id in (%s)", groupIDs)

	rows, err := seafileDB.Query(sqlStr, originRepoID)
	if err != nil {
		log.Printf("Failed to get shared directories: %v", err)
		return nil
	}

	defer rows.Close()

	var path string
	var perm string
	for rows.Next() {
		if err := rows.Scan(&path, &perm); err != nil {
			log.Printf("Failed to get shared directories: %v", err)
			continue
		}
		dirs[path] = perm
	}

	if err := rows.Err(); err != nil {
		log.Printf("Failed to get shared directories: %v", err)
		return nil
	}

	return dirs
}

func checkPermOnParentRepo(originRepoID, user, vPath string) string {
	var perm string
	userPerms := getSharedDirsToUser(originRepoID, user)
	if len(userPerms) == 0 {
		return perm
	}

	perm = getDirPerm(userPerms, vPath)
	if perm != "" {
		return perm
	}

	groups := getGroupsByUser(user, false)
	if len(groups) == 0 {
		return perm
	}

	groupPerms := getSharedDirsToGroup(originRepoID, groups)
	if len(groupPerms) == 0 {
		return perm
	}

	perm = getDirPerm(groupPerms, vPath)

	return perm
}
