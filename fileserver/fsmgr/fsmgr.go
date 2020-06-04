// Package fsmgr manages fs objects
package fsmgr

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
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
	Version  int      `json:"version"`
	FileSize uint64   `json:"size"`
	BlkIDs   []string `json:"block_ids"`
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
	Version int          `json:"version"`
	Entries []SeafDirent `json:"dirents"`
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
	r.Close()
	return out.Bytes(), nil
}

func compress(p []byte) []byte {
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	w.Write(p)
	w.Close()

	return out.Bytes()
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

// ToData converts seafile to JSON-encoded data and writes to w.
func (seafile *Seafile) ToData(w io.Writer) error {
	jsonstr, err := json.Marshal(seafile)
	if err != nil {
		return err
	}

	buf := compress(jsonstr)

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	return nil
}

// ToData converts seafdir to JSON-encoded data and writes to w.
func (seafdir *SeafDir) ToData(w io.Writer) error {
	jsonstr, err := json.Marshal(seafdir)
	if err != nil {
		return err
	}

	buf := compress(jsonstr)

	_, err = w.Write(buf)
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

// GetSeafile gets seafile from storage backend.
func GetSeafile(repoID string, fileID string) (*Seafile, error) {
	var buf bytes.Buffer
	seafile := new(Seafile)
	err := ReadRaw(repoID, fileID, &buf)
	if err != nil {
		str := fmt.Sprintf("Failed to read seafile object %s/%s from storage : %v.\n", repoID, fileID, err)
		return nil, errors.New(str)
	}

	err = seafile.FromData(buf.Bytes())
	if err != nil {
		str := fmt.Sprintf("Failed to parse seafile object %s/%s : %v.\n", repoID, fileID, err)
		return nil, errors.New(str)
	}

	if seafile.Version < 1 {
		str := fmt.Sprintf("Seafile object %s/%s version should be > 0.\n", repoID, fileID)
		return nil, errors.New(str)
	}

	return seafile, nil
}

// SaveSeafile saves seafile to storage backend.
func SaveSeafile(repoID string, fileID string, seafile *Seafile) error {
	exist, _ := store.Exists(repoID, fileID)
	if exist {
		return nil
	}

	var buf bytes.Buffer
	err := seafile.ToData(&buf)
	if err != nil {
		str := fmt.Sprintf("Failed to parse seafile object %s/%s : %v.\n", repoID, fileID, err)
		return errors.New(str)
	}

	err = WriteRaw(repoID, fileID, &buf)
	if err != nil {
		str := fmt.Sprintf("Failed to write seafile object %s/%s to storage : %v.\n", repoID, fileID, err)
		return errors.New(str)
	}

	return nil
}

// GetSeafdir gets seafdir from storage backend.
func GetSeafdir(repoID string, dirID string) (*SeafDir, error) {
	var buf bytes.Buffer
	seafdir := new(SeafDir)
	err := ReadRaw(repoID, dirID, &buf)
	if err != nil {
		str := fmt.Sprintf("Failed to read seafdir object %s/%s from storage : %v.\n", repoID, dirID, err)
		return nil, errors.New(str)
	}

	err = seafdir.FromData(buf.Bytes())
	if err != nil {
		str := fmt.Sprintf("Failed to parse seafdir object %s/%s : %v.\n", repoID, dirID, err)
		return nil, errors.New(str)
	}

	if seafdir.Version < 1 {
		str := fmt.Sprintf("Seadir object %s/%s version should be > 0.\n", repoID, dirID)
		return nil, errors.New(str)
	}

	return seafdir, nil
}

// SaveSeafdir saves seafdir to storage backend.
func SaveSeafdir(repoID string, dirID string, seafdir *SeafDir) error {
	exist, _ := store.Exists(repoID, dirID)
	if exist {
		return nil
	}

	var buf bytes.Buffer
	err := seafdir.ToData(&buf)
	if err != nil {
		str := fmt.Sprintf("Failed to parse seafdir object %s/%s : %v.\n", repoID, dirID, err)
		return errors.New(str)
	}

	err = WriteRaw(repoID, dirID, &buf)
	if err != nil {
		str := fmt.Sprintf("Failed to write seafdir object %s/%s to storage : %v.\n", repoID, dirID, err)
		return errors.New(str)
	}

	return nil
}
