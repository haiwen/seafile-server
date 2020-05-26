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

func newFSBackend(seafileDataDir string, objType string) (*fsBackend, error) {
	objDir := path.Join(seafileDataDir, "storage", objType)
	err := os.MkdirAll(objDir, os.ModePerm)
	if err != nil {
		return nil, err
	}
	backend := new(fsBackend)
	backend.objDir = objDir
	backend.objType = objType
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

	outputFile, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	outputFile.Write(buf)

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
