// Implementation of file system storage backend.
package objstore

import (
	"io"
	"os"
	"path"
)

type fsBackend struct {
	// Path of the object directory
	objDir  string
	objType string
	tmpDir  string
}

func newFSBackend(seafileDataDir string, objType string) (*fsBackend, error) {
	objDir := path.Join(seafileDataDir, "storage", objType)
	err := os.MkdirAll(objDir, os.ModePerm)
	if err != nil {
		return nil, err
	}
	tmpDir := path.Join(seafileDataDir, "tmpfiles")
	err = os.MkdirAll(tmpDir, os.ModePerm)
	if err != nil {
		return nil, err
	}
	backend := new(fsBackend)
	backend.objDir = objDir
	backend.objType = objType
	backend.tmpDir = tmpDir
	return backend, nil
}

func (b *fsBackend) read(repoID string, objID string, w io.Writer) error {
	p := path.Join(b.objDir, repoID, objID[:2], objID[2:])
	fd, err := os.Open(p)
	if err != nil {
		return err
	}
	defer fd.Close()

	_, err = io.Copy(w, fd)
	if err != nil {
		return err
	}

	return nil
}

func (b *fsBackend) write(repoID string, objID string, r io.Reader, sync bool) error {
	parentDir := path.Join(b.objDir, repoID, objID[:2])
	p := path.Join(parentDir, objID[2:])
	err := os.MkdirAll(parentDir, os.ModePerm)
	if err != nil {
		return err
	}

	tmpDir := b.tmpDir
	if b.objType != "blocks" {
		tmpDir = parentDir
	}
	tFile, err := os.CreateTemp(tmpDir, objID+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tFile.Name())
	defer tFile.Close()

	_, err = io.Copy(tFile, r)
	if err != nil {
		return err
	}

	err = os.Rename(tFile.Name(), p)
	if err != nil {
		return err
	}

	return nil
}

func (b *fsBackend) exists(repoID string, objID string) (bool, error) {
	path := path.Join(b.objDir, repoID, objID[:2], objID[2:])
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, err
		}
		return true, err
	}
	return true, nil
}

func (b *fsBackend) stat(repoID string, objID string) (int64, error) {
	path := path.Join(b.objDir, repoID, objID[:2], objID[2:])
	fileInfo, err := os.Stat(path)
	if err != nil {
		return -1, err
	}
	return fileInfo.Size(), nil
}
