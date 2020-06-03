// Package fsmgr manages fs objects
package fsmgr

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"github.com/haiwen/seafile-server/fileserver/objstore"
	"io"
)

const (
	SeafMetaDataTypeInvalid = iota
	SeafMetaDataTypeFile
	SeafMetaDataTypeLink
	SeafMetaDataTypeDir
)

type Seafile struct {
	FileType int    `json:"type"`
	Version  int    `json:"version"`
	FileSize uint64 `json:"size"`
	Aa       string
	BlkShals []interface{} `json:"block_ids"`
}

type SeafDirent struct {
	Mode    uint32 `json:"mode"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Mtime   int64  `json:"mtime"`
	Modifer string `json:"modifire"`
	Size    int64  `json:"size"`
}

type SeafDir struct {
	FileType int          `json:"type"`
	Version  int          `json:"version"`
	Entries  []SeafDirent `json:"dirents"`
}

var store *objstore.ObjectStore

// Init initializes fs manager and creates underlying object store.
func Init(seafileConfPath string, seafileDataDir string) {
	store = objstore.New(seafileConfPath, seafileDataDir, "fs")
}

func uncompress(p []byte) ([]byte, error) {
	b := bytes.NewReader(p)
	var out bytes.Buffer
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	io.Copy(&out, r)
	return out.Bytes(), nil
}

// FromData reads from p and converts JSON-encoded data to Seafile.
func (seafile *Seafile) FromData(p []byte) error {
	b, err := uncompress(p)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, seafile)
	if err != nil {
		return err
	}

	return nil
}

// FromData reads from p and converts JSON-encoded data to SeafDir.
func (seafdir *SeafDir) FromData(p []byte) error {
	b, err := uncompress(p)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, seafdir)
	if err != nil {
		return err
	}

	return nil
}

// ReadRaw reads data in binary format from storage backend.
func ReadRaw(repoID string, objID string, w io.Writer) error {
	err := store.Read(repoID, objID, w)
	if err != nil {
		return err
	}

	return nil
}

// WrtieRaw writes data in binary format to storage backend.
func WriteRaw(repoID string, objID string, r io.Reader) error {
	err := store.Write(repoID, objID, r, false)
	if err != nil {
		return err
	}
	return nil
}

// GetSeafile gets seafile from storage backend
func GetSeafile(repoID string, fileID string) (*Seafile, error) {
	var buf bytes.Buffer
	seafile := new(Seafile)
	err := ReadRaw(repoID, fileID, &buf)
	if err != nil {
		return nil, err
	}

	err = seafile.FromData(buf.Bytes())
	if err != nil {
		return nil, err
	}

	if seafile.FileType != SeafMetaDataTypeFile {
		return nil, errors.New("Object is not a file.\n")
	}

	if seafile.Version < 1 {
		return nil, errors.New("Seafile object version should be > 0.\n")
	}

	if seafile.BlkShals == nil {
		return nil, errors.New("No blkoc id array in seafile object.\n")
	}

	return seafile, nil
}

// GetSeafdir gets seafdir from storage backend
func GetSeafdir(repoID string, dirID string) (*SeafDir, error) {
	var buf bytes.Buffer
	seafdir := new(SeafDir)
	err := ReadRaw(repoID, dirID, &buf)
	if err != nil {
		return nil, err
	}

	err = seafdir.FromData(buf.Bytes())
	if err != nil {
		return nil, err
	}

	if seafdir.FileType != SeafMetaDataTypeDir {
		return nil, errors.New("Object is not a dir.\n")
	}

	if seafdir.Version < 1 {
		return nil, errors.New("Dir object version should be > 0.\n")
	}

	if seafdir.Entries == nil {
		return nil, errors.New("No dirents in dir object.\n")
	}

	return seafdir, nil
}
