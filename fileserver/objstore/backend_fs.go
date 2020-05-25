// Implementation of file system storage backend.
package objstore

import (
	"io"
	"io/ioutil"
	"os"
	"path"
)

type fsBackend struct {
	// Path of the object directory
	objDir  string
	objType string
}

func newFSBackend(seafileDataDir string, objType string) (b *fsBackend, err error) {
	backend := new(fsBackend)
	backend.objDir = path.Join(seafileDataDir, "storage", objType)
	backend.objType = objType
	return backend, nil
}

func (b *fsBackend) read(repoID string, objID string, w io.Writer) (err error) {
	path := path.Join(b.objDir, repoID, objID[:2], objID[2:])
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	w.Write(buf)

	return nil
}

func (b *fsBackend) write(repoID string, objID string, r io.Reader, sync bool) (err error) {
	parent_dir := path.Join(b.objDir, repoID, objID[:2])
	path := path.Join(parent_dir, objID[2:])
	err = os.MkdirAll(parent_dir, os.ModePerm)
	if err != nil {
		return
	}

	outputFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer outputFile.Close()

	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return
	}
	outputFile.Write(buf)

	return nil
}

func (b *fsBackend) exists(repoID string, objID string) (res bool, err error) {
	path := path.Join(b.objDir, repoID, objID[:2], objID[2:])
	_, err = os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true, err
		}
		return false, err
	}
	return true, nil
}
