// Package commitmgr manages commit objects.
package commitmgr

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/haiwen/seafile-server/fileserver/objstore"
)

type Commit struct {
	CommitID       string `json:"commit_id"`
	RepoID         string `json:"repo_id"`
	RootID         string `json:"root_id"`
	CreaterName    string `json:"creater_name,omitempty"`
	CreaterID      string `json:"creater"`
	Desc           string `json:"description"`
	Ctime          int64  `json:"ctime"`
	ParentID       string `json:"parent_id"`
	SecondParentID string `json:"second_parent_id"`
	RepoName       string `json:"repo_name"`
	RepoDesc       string `json:"repo_desc"`
	RepoCategory   string `json:"repo_category"`
	DeviceName     string `json:"device_name,omitempty"`
	ClientVersion  string `json:"client_version,omitempty"`
	Encrypted      string `json:"encrypted,omitempty"`
	EncVersion     int    `json:"enc_version,omitempty"`
	Magic          string `json:"magic,omitempty"`
	RandomKey      string `json:"key,omitempty"`
	Salt           string `json:"salt,omitempty"`
	Version        int    `json:"version,omitempty"`
	Conflict       int    `json:"conflict,omitempty"`
	NewMerge       int    `json:"new_merge,omitempty"`
	Repaired       int    `json:"repaired,omitempty"`
}

var store *objstore.ObjectStore

// Init initializes commit manager and creates underlying object store.
func Init(seafileConfPath string, seafileDataDir string) {
	store = objstore.New(seafileConfPath, seafileDataDir, "commits")
}

// FromData reads from p and converts JSON-encoded data to commit.
func (commit *Commit) FromData(p []byte) error {
	err := json.Unmarshal(p, commit)
	if err != nil {
		return err
	}

	return nil
}

// ToData converts commit to JSON-encoded data and writes to w.
func (c *Commit) ToData(w io.Writer) error {
	jsonstr, err := json.Marshal(c)
	if err != nil {
		return err
	}

	_, err = w.Write(jsonstr)
	if err != nil {
		return err
	}

	return nil
}

// ReadRaw reads data in binary format from storage backend.
func ReadRaw(repoID string, commitID string, w io.Writer) error {
	err := store.Read(repoID, commitID, w)
	if err != nil {
		return err
	}
	return nil
}

// WrtieRaw writes data in binary format to storage backend.
func WriteRaw(repoID string, commitID string, r io.Reader) error {
	err := store.Write(repoID, commitID, r, false)
	if err != nil {
		return err
	}
	return nil
}

// Load commit from storage backend.
func Load(repoID string, commitID string) (*Commit, error) {
	var buf bytes.Buffer
	commit := new(Commit)
	err := ReadRaw(repoID, commitID, &buf)
	if err != nil {
		return nil, err
	}
	err = commit.FromData(buf.Bytes())
	if err != nil {
		return nil, err
	}

	return commit, nil
}

// Save commit to storage backend.
func Save(commit *Commit) error {
	var buf bytes.Buffer
	err := commit.ToData(&buf)
	if err != nil {
		return err
	}

	err = WriteRaw(commit.RepoID, commit.CommitID, &buf)
	if err != nil {
		return err
	}

	return err
}

// Exists checks commit if exists.
func Exists(repoID string, commitID string) (bool, error) {
	return store.Exists(repoID, commitID)
}
