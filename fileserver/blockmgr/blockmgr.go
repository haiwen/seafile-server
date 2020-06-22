// Package blockmgr provides operations on blocks
package blockmgr

import (
	"github.com/haiwen/seafile-server/fileserver/objstore"
	"io"
)

var store *objstore.ObjectStore

// Init initializes block manager and creates underlying object store.
func Init(seafileConfPath string, seafileDataDir string) {
	store = objstore.New(seafileConfPath, seafileDataDir, "blocks")
}

// Read reads block from storage backend.
func Read(repoID string, blockID string, w io.Writer) error {
	err := store.Read(repoID, blockID, w)
	if err != nil {
		return err
	}

	return nil
}

// Write writes block to storage backend.
func Write(repoID string, blockID string, r io.Reader) error {
	err := store.Write(repoID, blockID, r, false)
	if err != nil {
		return err
	}

	return nil
}

// Exists checks block if exists.
func Exists(repoID string, blockID string) bool {
	ret, _ := store.Exists(repoID, blockID)
	return ret
}
