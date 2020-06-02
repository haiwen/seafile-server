// Package commitmgr manages commit objects.
package commitmgr

import (
	"encoding/json"
	"github.com/haiwen/seafile-server/fileserver/objstore"
	"io"
)

type Commit struct {
	CommitID       string  `json:"commit_id"`
	RepoID         string  `json:"repo_id"`
	RootID         string  `json:"root_id"`
	CreaterName    string  `json:"creater_name,omitempty"`
	CreaterID      string  `json:"creater"`
	Desc           string  `json:"description"`
	Ctime          int64   `json:"ctime"`
	ParentID       *string `json:"parent_id"`
	SecondParentID *string `json:"second_parent_id"`
	RepoName       string  `json:"repo_name"`
	RepoDesc       string  `json:"repo_desc"`
	RepoCategory   *string `json:"repo_category"`
	DeviceName     string  `json:"device_name,omitempty"`
	ClientVersion  string  `json:"client_version,omitempty"`
	Encrypted      string  `json:"encrypted,omitempty"`
	EncVersion     int     `json:"enc_version,omitempty"`
	Magic          string  `json:"magic,omitempty"`
	RandomKey      string  `json:"key,omitempty"`
	Salt           string  `json:"salt,omitempty"`
	Version        int     `json:"version,omitempty"`
	Conflict       int     `json:"conflict,omitempty"`
	NewMerge       int     `json:"new_merge,omitempty"`
	Repaired       int     `json:"repaired,omitempty"`
}

var store *objstore.ObjectStore

//Init objstore.
func Init(seafileConfPath string, seafileDataDir string) {
	store = objstore.New(seafileConfPath, seafileDataDir, "commit")
}

//Write parse the JSON-encoded data and stores the result int the commit.
func (commit *Commit) Write(p []byte) (int, error) {
	err := json.Unmarshal(p, commit)
	if err != nil {
		return -1, err
	}

	return len(p), nil
}

//Read traverses the commit to JSON-encoded data.
func (c *Commit) Read(p []byte) (int, error) {
	jsonstr, err := json.Marshal(c)
	if err != nil {
		return -1, err
	}
	copy(p, jsonstr)

	return len(jsonstr), io.EOF
}

func readRaw(repoID string, commitID string, w io.Writer) error {
	err := store.Read(repoID, commitID, w)
	if err != nil {
		return err
	}
	return nil
}

func writeRaw(repoID string, commitID string, r io.Reader) error {
	err := store.Write(repoID, commitID, r, false)
	if err != nil {
		return err
	}
	return nil
}

//Load commit from storage backend.
func Load(repoID string, commitID string) (*Commit, error) {
	commit := new(Commit)
	err := readRaw(repoID, commitID, commit)
	if err != nil {
		return nil, err
	}

	return commit, nil
}

//Save commit to storage backend.
func Save(commit *Commit) error {
	err := writeRaw(commit.RepoID, commit.CommitID, commit)

	return err
}
