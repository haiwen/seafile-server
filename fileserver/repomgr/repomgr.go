// Package repomgr manages repo objects and file operations in repos.
package repomgr

import (
	"database/sql"
	"log"
	// Change to non-blank imports when use
	_ "github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	_ "github.com/haiwen/seafile-server/fileserver/fsmgr"
)

// Repo contains information about a repo.
type Repo struct {
	ID                   string
	Name                 string
	LastModifier         string
	LastModificationTime int64
	HeadCommitID         string
	RootID               string

	// Set when repo is virtual
	VirtualInfo *VRepoInfo

	// ID for fs and block store
	StoreID string

	// Encrypted repo info
	IsEncrypted bool
	EncVersion  int
	Magic       string
	RandomKey   string
	Salt        string
	Version     int
}

// VRepoInfo contains virtual repo information.
type VRepoInfo struct {
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

	stmt, err := seafileDB.Prepare(query)
	if err != nil {
		log.Printf("failed to prepare sql : %s ：%v.\n", query, err)
		return nil
	}
	defer stmt.Close()

	rows, err := stmt.Query(id)
	if err != nil {
		log.Printf("failed to query sql : %v.\n", err)
		return nil
	}
	defer rows.Close()

	repo := new(Repo)
	repo.VirtualInfo = new(VRepoInfo)

	var originRepoID sql.NullString
	var path sql.NullString
	var baseCommitID sql.NullString
	if rows.Next() {
		err := rows.Scan(&repo.ID, &repo.HeadCommitID, &originRepoID, &path, &baseCommitID)
		if err != nil {
			log.Printf("failed to scan sql rows : %v.\n", err)
			return nil
		}
	}
	if originRepoID.Valid {
		repo.VirtualInfo.OriginRepoID = originRepoID.String
		repo.StoreID = originRepoID.String
	} else {
		repo.StoreID = repo.ID
	}
	if path.Valid {
		repo.VirtualInfo.Path = path.String
	}
	if baseCommitID.Valid {
		repo.VirtualInfo.BaseCommitID = baseCommitID.String
	}

	commit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		log.Printf("failed to load commit %s/%s : %v.\n", repo.ID, repo.HeadCommitID, err)
		return nil
	}

	repo.Name = commit.RepoName
	repo.LastModifier = commit.CreaterName
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
		}
	}

	return repo
}
