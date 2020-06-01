// Package blockmgr provides operations on blocks
package blockmgr

import (
	// Change to non-blank import when use
	"github.com/haiwen/seafile-server/fileserver/objstore"
	"io"
)

//Read block from storage backend.
func BlockRead(store *objstore.ObjectStore, repoID string, blockID string, w io.Writer) error {
	err := store.Read(repoID, blockID, w)
	if err != nil {
		return err
	}

	return nil
}

//Write block to storage backend.
func BlockWrite(store *objstore.ObjectStore, repoID string, blockID string, r io.Reader) error {
	err := store.Write(repoID, blockID, r, false)
	if err != nil {
		return err
	}

	return nil
}

//Check block if exists.
func BlockExists(store *objstore.ObjectStore, repoID string, blockID string) (bool, error) {
	ret, err := store.Exists(repoID, blockID)
	return ret, err
}
