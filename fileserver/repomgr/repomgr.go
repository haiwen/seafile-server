// Package repomgr manages repo objects and file operations in repos.
package repomgr

import (
	"database/sql"
	// Change to non-blank imports when use
	_ "github.com/haiwen/seafile-server/fileserver/blockmgr"
	_ "github.com/haiwen/seafile-server/fileserver/commitmgr"
	_ "github.com/haiwen/seafile-server/fileserver/fsmgr"
)

// Repo contains information about a repo.
type Repo struct {
	ID                   string
	Name                 string
	LastModifier         string
	LastModificationTime uint64
	HeadCommitID         string
	RootID               string

	// Set when repo is virtual
	VirtualInfo *VRepoInfo

	// ID for fs and block store
	StoreID string

	// Encrypted repo info
	IsEncrypted bool
	EncVersion  uint32
	Magic       string
	RandomKey   string
	Salt        string
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
	return nil
}
