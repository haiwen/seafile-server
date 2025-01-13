// Package repomgr manages repo objects and file operations in repos.
package repomgr

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	// Change to non-blank imports when use
	_ "github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/option"
	log "github.com/sirupsen/logrus"
)

// Repo status
const (
	RepoStatusNormal = iota
	RepoStatusReadOnly
	NRepoStatus
)

// Repo contains information about a repo.
type Repo struct {
	ID                   string
	Name                 string
	Desc                 string
	LastModifier         string
	LastModificationTime int64
	HeadCommitID         string
	RootID               string
	IsCorrupted          bool

	// Set when repo is virtual
	VirtualInfo *VRepoInfo

	// ID for fs and block store
	StoreID string

	// Encrypted repo info
	IsEncrypted   bool
	EncVersion    int
	Magic         string
	RandomKey     string
	Salt          string
	PwdHash       string
	PwdHashAlgo   string
	PwdHashParams string
	Version       int
}

// VRepoInfo contains virtual repo information.
type VRepoInfo struct {
	RepoID       string
	OriginRepoID string
	Path         string
	BaseCommitID string
}

var seafileDB *sql.DB

// Init initialize status of repomgr package
func Init(seafDB *sql.DB) {
	seafileDB = seafDB
}

// Get returns Repo object by repo ID.
func Get(id string) *Repo {
	query := `SELECT r.repo_id, b.commit_id, v.origin_repo, v.path, v.base_commit FROM ` +
		`Repo r LEFT JOIN Branch b ON r.repo_id = b.repo_id ` +
		`LEFT JOIN VirtualRepo v ON r.repo_id = v.repo_id ` +
		`WHERE r.repo_id = ? AND b.name = 'master'`

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	stmt, err := seafileDB.PrepareContext(ctx, query)
	if err != nil {
		log.Errorf("failed to prepare sql : %s ：%v", query, err)
		return nil
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, id)
	if err != nil {
		log.Errorf("failed to query sql : %v", err)
		return nil
	}
	defer rows.Close()

	repo := new(Repo)

	var originRepoID sql.NullString
	var path sql.NullString
	var baseCommitID sql.NullString
	if rows.Next() {
		err := rows.Scan(&repo.ID, &repo.HeadCommitID, &originRepoID, &path, &baseCommitID)
		if err != nil {
			log.Errorf("failed to scan sql rows : %v", err)
			return nil
		}
	} else {
		return nil
	}

	if repo.HeadCommitID == "" {
		log.Errorf("repo %s is corrupted", id)
		return nil
	}

	if originRepoID.Valid {
		repo.VirtualInfo = new(VRepoInfo)
		repo.VirtualInfo.RepoID = id
		repo.VirtualInfo.OriginRepoID = originRepoID.String
		repo.StoreID = originRepoID.String

		if path.Valid {
			repo.VirtualInfo.Path = path.String
		}

		if baseCommitID.Valid {
			repo.VirtualInfo.BaseCommitID = baseCommitID.String
		}
	} else {
		repo.StoreID = repo.ID
	}

	commit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		log.Errorf("failed to load commit %s/%s : %v", repo.ID, repo.HeadCommitID, err)
		return nil
	}

	repo.Name = commit.RepoName
	repo.Desc = commit.RepoDesc
	repo.LastModifier = commit.CreatorName
	repo.LastModificationTime = commit.Ctime
	repo.RootID = commit.RootID
	repo.Version = commit.Version
	if commit.Encrypted == "true" {
		repo.IsEncrypted = true
		repo.EncVersion = commit.EncVersion
		if repo.EncVersion == 1 && commit.PwdHash == "" {
			repo.Magic = commit.Magic
		} else if repo.EncVersion == 2 {
			repo.RandomKey = commit.RandomKey
		} else if repo.EncVersion == 3 {
			repo.RandomKey = commit.RandomKey
			repo.Salt = commit.Salt
		} else if repo.EncVersion == 4 {
			repo.RandomKey = commit.RandomKey
			repo.Salt = commit.Salt
		}
		if repo.EncVersion >= 2 && commit.PwdHash == "" {
			repo.Magic = commit.Magic
		}
		if commit.PwdHash != "" {
			repo.PwdHash = commit.PwdHash
			repo.PwdHashAlgo = commit.PwdHashAlgo
			repo.PwdHashParams = commit.PwdHashParams
		}
	}

	return repo
}

// RepoToCommit converts Repo to Commit.
func RepoToCommit(repo *Repo, commit *commitmgr.Commit) {
	commit.RepoID = repo.ID
	commit.RepoName = repo.Name
	if repo.IsEncrypted {
		commit.Encrypted = "true"
		commit.EncVersion = repo.EncVersion
		if repo.EncVersion == 1 && repo.PwdHash == "" {
			commit.Magic = repo.Magic
		} else if repo.EncVersion == 2 {
			commit.RandomKey = repo.RandomKey
		} else if repo.EncVersion == 3 {
			commit.RandomKey = repo.RandomKey
			commit.Salt = repo.Salt
		} else if repo.EncVersion == 4 {
			commit.RandomKey = repo.RandomKey
			commit.Salt = repo.Salt
		}
		if repo.EncVersion >= 2 && repo.PwdHash == "" {
			commit.Magic = repo.Magic
		}
		if repo.PwdHash != "" {
			commit.PwdHash = repo.PwdHash
			commit.PwdHashAlgo = repo.PwdHashAlgo
			commit.PwdHashParams = repo.PwdHashParams
		}
	} else {
		commit.Encrypted = "false"
	}
	commit.Version = repo.Version
}

// GetEx return repo object even if it's corrupted.
func GetEx(id string) *Repo {
	query := `SELECT r.repo_id, b.commit_id, v.origin_repo, v.path, v.base_commit FROM ` +
		`Repo r LEFT JOIN Branch b ON r.repo_id = b.repo_id ` +
		`LEFT JOIN VirtualRepo v ON r.repo_id = v.repo_id ` +
		`WHERE r.repo_id = ? AND b.name = 'master'`

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	stmt, err := seafileDB.PrepareContext(ctx, query)
	if err != nil {
		log.Errorf("failed to prepare sql : %s ：%v", query, err)
		return nil
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, id)
	if err != nil {
		log.Errorf("failed to query sql : %v", err)
		return nil
	}
	defer rows.Close()

	repo := new(Repo)

	var originRepoID sql.NullString
	var path sql.NullString
	var baseCommitID sql.NullString
	if rows.Next() {
		err := rows.Scan(&repo.ID, &repo.HeadCommitID, &originRepoID, &path, &baseCommitID)
		if err != nil {
			log.Errorf("failed to scan sql rows : %v", err)
			return nil
		}
	} else {
		return nil
	}
	if originRepoID.Valid {
		repo.VirtualInfo = new(VRepoInfo)
		repo.VirtualInfo.RepoID = id
		repo.VirtualInfo.OriginRepoID = originRepoID.String
		repo.StoreID = originRepoID.String

		if path.Valid {
			repo.VirtualInfo.Path = path.String
		}

		if baseCommitID.Valid {
			repo.VirtualInfo.BaseCommitID = baseCommitID.String
		}
	} else {
		repo.StoreID = repo.ID
	}

	if repo.HeadCommitID == "" {
		repo.IsCorrupted = true
		return repo
	}

	commit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		log.Errorf("failed to load commit %s/%s : %v", repo.ID, repo.HeadCommitID, err)
		repo.IsCorrupted = true
		return nil
	}

	repo.Name = commit.RepoName
	repo.LastModifier = commit.CreatorName
	repo.LastModificationTime = commit.Ctime
	repo.RootID = commit.RootID
	repo.Version = commit.Version
	if commit.Encrypted == "true" {
		repo.IsEncrypted = true
		repo.EncVersion = commit.EncVersion
		if repo.EncVersion == 1 {
			repo.Magic = commit.Magic
		} else if repo.EncVersion == 2 {
			repo.Magic = commit.Magic
			repo.RandomKey = commit.RandomKey
		} else if repo.EncVersion == 3 {
			repo.Magic = commit.Magic
			repo.RandomKey = commit.RandomKey
			repo.Salt = commit.Salt
		} else if repo.EncVersion == 4 {
			repo.Magic = commit.Magic
			repo.RandomKey = commit.RandomKey
			repo.Salt = commit.Salt
		}
		if commit.PwdHash != "" {
			repo.PwdHash = commit.PwdHash
			repo.PwdHashAlgo = commit.PwdHashAlgo
			repo.PwdHashParams = commit.PwdHashParams
		}
	}

	return repo
}

// GetVirtualRepoInfo return virtual repo info by repo id.
func GetVirtualRepoInfo(repoID string) (*VRepoInfo, error) {
	sqlStr := "SELECT repo_id, origin_repo, path, base_commit FROM VirtualRepo WHERE repo_id = ?"
	vRepoInfo := new(VRepoInfo)

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&vRepoInfo.RepoID, &vRepoInfo.OriginRepoID, &vRepoInfo.Path, &vRepoInfo.BaseCommitID); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
		return nil, nil
	}
	return vRepoInfo, nil
}

// GetVirtualRepoInfoByOrigin return virtual repo info by origin repo id.
func GetVirtualRepoInfoByOrigin(originRepo string) ([]*VRepoInfo, error) {
	sqlStr := "SELECT repo_id, origin_repo, path, base_commit " +
		"FROM VirtualRepo WHERE origin_repo=?"
	var vRepos []*VRepoInfo
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row, err := seafileDB.QueryContext(ctx, sqlStr, originRepo)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	for row.Next() {
		vRepoInfo := new(VRepoInfo)
		if err := row.Scan(&vRepoInfo.RepoID, &vRepoInfo.OriginRepoID, &vRepoInfo.Path, &vRepoInfo.BaseCommitID); err != nil {
			if err != sql.ErrNoRows {
				return nil, err
			}
		}
		vRepos = append(vRepos, vRepoInfo)
	}

	return vRepos, nil
}

// GetEmailByToken return user's email by token.
func GetEmailByToken(repoID string, token string) (string, error) {
	var email string
	sqlStr := "SELECT email FROM RepoUserToken WHERE repo_id = ? AND token = ?"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID, token)
	if err := row.Scan(&email); err != nil {
		if err != sql.ErrNoRows {
			return email, err
		}
	}
	return email, nil
}

// GetRepoStatus return repo status by repo id.
func GetRepoStatus(repoID string) (int, error) {
	var status int
	sqlStr := "SELECT status FROM RepoInfo WHERE repo_id=?"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&status); err != nil {
		if err != sql.ErrNoRows {
			return status, err
		}
	}
	return status, nil
}

// TokenPeerInfoExists check if the token exists.
func TokenPeerInfoExists(token string) (bool, error) {
	var exists string
	sqlStr := "SELECT token FROM RepoTokenPeerInfo WHERE token=?"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, token)
	if err := row.Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

// AddTokenPeerInfo add token peer info to RepoTokenPeerInfo table.
func AddTokenPeerInfo(token, peerID, peerIP, peerName, clientVer string, syncTime int64) error {
	sqlStr := "INSERT INTO RepoTokenPeerInfo (token, peer_id, peer_ip, peer_name, sync_time, client_ver)" +
		"VALUES (?, ?, ?, ?, ?, ?)"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	if _, err := seafileDB.ExecContext(ctx, sqlStr, token, peerID, peerIP, peerName, syncTime, clientVer); err != nil {
		return err
	}
	return nil
}

// UpdateTokenPeerInfo update token peer info to RepoTokenPeerInfo table.
func UpdateTokenPeerInfo(token, peerID, clientVer string, syncTime int64) error {
	sqlStr := "UPDATE RepoTokenPeerInfo SET " +
		"peer_ip=?, sync_time=?, client_ver=? WHERE token=?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	if _, err := seafileDB.ExecContext(ctx, sqlStr, peerID, syncTime, clientVer, token); err != nil {
		return err
	}
	return nil
}

// GetUploadTmpFile gets the timp file path of upload file.
func GetUploadTmpFile(repoID, filePath string) (string, error) {
	var filePathNoSlash string
	if filePath[0] == '/' {
		filePathNoSlash = filePath[1:]
	} else {
		filePathNoSlash = filePath
		filePath = "/" + filePath
	}

	var tmpFile string
	sqlStr := "SELECT tmp_file_path FROM WebUploadTempFiles WHERE repo_id = ? AND file_path = ?"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID, filePath)
	if err := row.Scan(&tmpFile); err != nil {
		if err != sql.ErrNoRows {
			return "", err
		}
	}
	if tmpFile == "" {
		row := seafileDB.QueryRowContext(ctx, sqlStr, repoID, filePathNoSlash)
		if err := row.Scan(&tmpFile); err != nil {
			if err != sql.ErrNoRows {
				return "", err
			}
		}
	}

	return tmpFile, nil
}

// AddUploadTmpFile adds the tmp file path of upload file.
func AddUploadTmpFile(repoID, filePath, tmpFile string) error {
	if filePath[0] != '/' {
		filePath = "/" + filePath
	}

	sqlStr := "INSERT INTO WebUploadTempFiles (repo_id, file_path, tmp_file_path) VALUES (?, ?, ?)"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	_, err := seafileDB.ExecContext(ctx, sqlStr, repoID, filePath, tmpFile)
	if err != nil {
		return err
	}

	return nil
}

// DelUploadTmpFile deletes the tmp file path of upload file.
func DelUploadTmpFile(repoID, filePath string) error {
	var filePathNoSlash string
	if filePath[0] == '/' {
		filePathNoSlash = filePath[1:]
	} else {
		filePathNoSlash = filePath
		filePath = "/" + filePath
	}

	sqlStr := "DELETE FROM WebUploadTempFiles WHERE repo_id = ? AND file_path IN (?, ?)"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	_, err := seafileDB.ExecContext(ctx, sqlStr, repoID, filePath, filePathNoSlash)
	if err != nil {
		return err
	}

	return nil
}

func setRepoCommitToDb(repoID, repoName string, updateTime int64, version int, isEncrypted string, lastModifier string) error {
	var exists int
	var encrypted int

	sqlStr := "SELECT 1 FROM RepoInfo WHERE repo_id=?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			return err
		}
	}
	if updateTime == 0 {
		updateTime = time.Now().Unix()
	}

	if isEncrypted == "true" {
		encrypted = 1
	}

	if exists == 1 {
		sqlStr := "UPDATE RepoInfo SET name=?, update_time=?, version=?, is_encrypted=?, " +
			"last_modifier=? WHERE repo_id=?"
		if _, err := seafileDB.ExecContext(ctx, sqlStr, repoName, updateTime, version, encrypted, lastModifier, repoID); err != nil {
			return err
		}
	} else {
		sqlStr := "INSERT INTO RepoInfo (repo_id, name, update_time, version, is_encrypted, last_modifier) " +
			"VALUES (?, ?, ?, ?, ?, ?)"
		if _, err := seafileDB.ExecContext(ctx, sqlStr, repoID, repoName, updateTime, version, encrypted, lastModifier); err != nil {
			return err
		}
	}

	return nil
}

// SetVirtualRepoBaseCommitPath updates the table of VirtualRepo.
func SetVirtualRepoBaseCommitPath(repoID, baseCommitID, newPath string) error {
	sqlStr := "UPDATE VirtualRepo SET base_commit=?, path=? WHERE repo_id=?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	if _, err := seafileDB.ExecContext(ctx, sqlStr, baseCommitID, newPath, repoID); err != nil {
		return err
	}
	return nil
}

// GetVirtualRepoIDsByOrigin return the virtual repo ids by origin repo id.
func GetVirtualRepoIDsByOrigin(repoID string) ([]string, error) {
	sqlStr := "SELECT repo_id FROM VirtualRepo WHERE origin_repo=?"

	var id string
	var ids []string
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row, err := seafileDB.QueryContext(ctx, sqlStr, repoID)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	for row.Next() {
		if err := row.Scan(&id); err != nil {
			if err != sql.ErrNoRows {
				return nil, err
			}
		}
		ids = append(ids, id)
	}

	return ids, nil
}

// DelVirtualRepo deletes virtual repo from database.
func DelVirtualRepo(repoID string, cloudMode bool) error {
	err := removeVirtualRepoOndisk(repoID, cloudMode)
	if err != nil {
		err := fmt.Errorf("failed to remove virtual repo on disk: %v", err)
		return err
	}
	sqlStr := "DELETE FROM VirtualRepo WHERE repo_id = ?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	_, err = seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}

	return nil
}

func removeVirtualRepoOndisk(repoID string, cloudMode bool) error {
	sqlStr := "DELETE FROM Repo WHERE repo_id = ?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	_, err := seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}
	sqlStr = "SELECT name, repo_id, commit_id FROM Branch WHERE repo_id=?"
	rows, err := seafileDB.QueryContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, id, commitID string
		if err := rows.Scan(&name, &id, &commitID); err != nil {
			if err != sql.ErrNoRows {
				return err
			}
		}
		sqlStr := "DELETE FROM RepoHead WHERE branch_name = ? AND repo_id = ?"
		_, err := seafileDB.ExecContext(ctx, sqlStr, name, id)
		if err != nil {
			return err
		}
		sqlStr = "DELETE FROM Branch WHERE name=? AND repo_id=?"
		_, err = seafileDB.ExecContext(ctx, sqlStr, name, id)
		if err != nil {
			return err
		}
	}

	sqlStr = "DELETE FROM RepoOwner WHERE repo_id = ?"
	_, err = seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}

	sqlStr = "DELETE FROM SharedRepo WHERE repo_id = ?"
	_, err = seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}

	sqlStr = "DELETE FROM RepoGroup WHERE repo_id = ?"
	_, err = seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}
	if !cloudMode {
		sqlStr = "DELETE FROM InnerPubRepo WHERE repo_id = ?"
		_, err := seafileDB.ExecContext(ctx, sqlStr, repoID)
		if err != nil {
			return err
		}
	}

	sqlStr = "DELETE FROM RepoUserToken WHERE repo_id = ?"
	_, err = seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}

	sqlStr = "DELETE FROM RepoValidSince WHERE repo_id = ?"
	_, err = seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}

	sqlStr = "DELETE FROM RepoSize WHERE repo_id = ?"
	_, err = seafileDB.ExecContext(ctx, sqlStr, repoID)
	if err != nil {
		return err
	}

	var exists int
	sqlStr = "SELECT 1 FROM GarbageRepos WHERE repo_id=?"
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			return err
		}
	}
	if exists == 0 {
		sqlStr = "INSERT INTO GarbageRepos (repo_id) VALUES (?)"
		_, err := seafileDB.ExecContext(ctx, sqlStr, repoID)
		if err != nil {
			return err
		}
	} else {
		sqlStr = "REPLACE INTO GarbageRepos (repo_id) VALUES (?)"
		_, err := seafileDB.ExecContext(ctx, sqlStr, repoID)
		if err != nil {
			return err
		}
	}

	return nil
}

// IsVirtualRepo check if the repo is a virtual reop.
func IsVirtualRepo(repoID string) (bool, error) {
	var exists int
	sqlStr := "SELECT 1 FROM VirtualRepo WHERE repo_id = ?"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
		return false, nil
	}
	return true, nil

}

// GetRepoOwner get the owner of repo.
func GetRepoOwner(repoID string) (string, error) {
	var owner string
	sqlStr := "SELECT owner_id FROM RepoOwner WHERE repo_id=?"

	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&owner); err != nil {
		if err != sql.ErrNoRows {
			return "", err
		}
	}

	return owner, nil
}

func UpdateRepoInfo(repoID, commitID string) error {
	head, err := commitmgr.Load(repoID, commitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%s", repoID, commitID)
		return err
	}

	setRepoCommitToDb(repoID, head.RepoName, head.Ctime, head.Version, head.Encrypted, head.CreatorName)

	return nil
}

func HasLastGCID(repoID, clientID string) (bool, error) {
	sqlStr := "SELECT 1 FROM LastGCID WHERE repo_id = ? AND client_id = ?"

	var exist int
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID, clientID)
	if err := row.Scan(&exist); err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
	}
	if exist == 0 {
		return false, nil
	}
	return true, nil
}

func GetLastGCID(repoID, clientID string) (string, error) {
	sqlStr := "SELECT gc_id FROM LastGCID WHERE repo_id = ? AND client_id = ?"

	var gcID sql.NullString
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID, clientID)
	if err := row.Scan(&gcID); err != nil {
		if err != sql.ErrNoRows {
			return "", err
		}
	}

	return gcID.String, nil
}

func GetCurrentGCID(repoID string) (string, error) {
	sqlStr := "SELECT gc_id FROM GCID WHERE repo_id = ?"

	var gcID sql.NullString
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	row := seafileDB.QueryRowContext(ctx, sqlStr, repoID)
	if err := row.Scan(&gcID); err != nil {
		if err != sql.ErrNoRows {
			return "", err
		}
	}

	return gcID.String, nil
}

func RemoveLastGCID(repoID, clientID string) error {
	sqlStr := "DELETE FROM LastGCID WHERE repo_id = ? AND client_id = ?"
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	if _, err := seafileDB.ExecContext(ctx, sqlStr, repoID, clientID); err != nil {
		return err
	}
	return nil
}

func SetLastGCID(repoID, clientID, gcID string) error {
	exist, err := HasLastGCID(repoID, clientID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	if exist {
		sqlStr := "UPDATE LastGCID SET gc_id = ? WHERE repo_id = ? AND client_id = ?"
		if _, err = seafileDB.ExecContext(ctx, sqlStr, gcID, repoID, clientID); err != nil {
			return err
		}
	} else {
		sqlStr := "INSERT INTO LastGCID (repo_id, client_id, gc_id) VALUES (?, ?, ?)"
		if _, err = seafileDB.ExecContext(ctx, sqlStr, repoID, clientID, gcID); err != nil {
			return err
		}
	}
	return nil
}
