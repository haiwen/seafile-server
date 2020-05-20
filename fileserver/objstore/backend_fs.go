// Implementation of file system storage backend.
package objstore

import (
	"io"
)

type fsBackend struct {
	// Path of the object directory
	objDir  string
	objType string
}

func newFSBackend(seafileDataDir string, objType string) (b *fsBackend, err error) {
	return nil, nil
}

func (b *fsBackend) read(repoID string, objID string, w io.Writer) (err error) {
	return nil
}

func (b *fsBackend) write(repoID string, objID string, r io.Reader, sync bool) (err error) {
	return nil
}

func (b *fsBackend) exists(repoID string, objID string) (res bool, err error) {
	return false, nil
}
