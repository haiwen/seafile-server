// Package fsmgr manages fs objects
package fsmgr

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"github.com/haiwen/seafile-server/fileserver/objstore"
	"io"
	"path/filepath"
	"strings"
	"syscall"
)

type Seafile struct {
	Version  int      `json:"version"`
	FileID   string   `json:"file_id,omitempty"`
	FileSize uint64   `json:"size"`
	BlkIDs   []string `json:"block_ids"`
}

type SeafDirent struct {
	Mode     uint32 `json:"mode"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Mtime    int64  `json:"mtime"`
	Modifier string `json:"modifier"`
	Size     int64  `json:"size"`
}

type SeafDir struct {
	Version int          `json:"version"`
	DirID   string       `json:"dir_id,omitempty"`
	Entries []SeafDirent `json:"dirents"`
}

var store *objstore.ObjectStore

const (
	EMPTY_SHA1 = "0000000000000000000000000000000000000000"
)

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

	_, err = io.Copy(&out, r)
	if err != nil {
		r.Close()
		return nil, err
	}

	r.Close()

	return out.Bytes(), nil
}

func compress(p []byte) ([]byte, error) {
	var out bytes.Buffer
	w := zlib.NewWriter(&out)

	_, err := w.Write(p)
	if err != nil {
		w.Close()
		return nil, err
	}

	w.Close()

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

// ToData converts seafile to JSON-encoded data and writes to w.
func (seafile *Seafile) ToData(w io.Writer) error {
	jsonstr, err := json.Marshal(seafile)
	if err != nil {
		return err
	}

	buf, err := compress(jsonstr)
	if err != nil {
		return err
	}

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

	buf, err := compress(jsonstr)
	if err != nil {
		return err
	}

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
	if fileID == EMPTY_SHA1 {
		seafile.FileID = EMPTY_SHA1
		return seafile, nil
	}

	err := ReadRaw(repoID, fileID, &buf)
	if err != nil {
		errors := fmt.Errorf("failed to read seafile object from storage : %v.\n", err)
		return nil, errors
	}

	err = seafile.FromData(buf.Bytes())
	if err != nil {
		errors := fmt.Errorf("failed to parse seafile object %s/%s : %v.\n", repoID, fileID, err)
		return nil, errors
	}

	if seafile.Version < 1 {
		errors := fmt.Errorf("seafile object %s/%s version should be > 0.\n", repoID, fileID)
		return nil, errors
	}

	seafile.FileID = fileID

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
		errors := fmt.Errorf("failed to convert seafile object %s/%s to json.\n", repoID, fileID)
		return errors
	}

	err = WriteRaw(repoID, fileID, &buf)
	if err != nil {
		errors := fmt.Errorf("failed to write seafile object to storage : %v.\n", err)
		return errors
	}

	return nil
}

// GetSeafdir gets seafdir from storage backend.
func GetSeafdir(repoID string, dirID string) (*SeafDir, error) {
	var buf bytes.Buffer
	seafdir := new(SeafDir)
	if dirID == EMPTY_SHA1 {
		seafdir.DirID = EMPTY_SHA1
		return seafdir, nil
	}

	err := ReadRaw(repoID, dirID, &buf)
	if err != nil {
		errors := fmt.Errorf("failed to read seafdir object from storage : %v.\n", err)
		return nil, errors
	}

	err = seafdir.FromData(buf.Bytes())
	if err != nil {
		errors := fmt.Errorf("failed to parse seafdir object %s/%s : %v.\n", repoID, dirID, err)
		return nil, errors
	}

	if seafdir.Version < 1 {
		errors := fmt.Errorf("seadir object %s/%s version should be > 0.\n", repoID, dirID)
		return nil, errors
	}

	seafdir.DirID = dirID

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
		errors := fmt.Errorf("failed to convert seafdir object %s/%s to json.\n", repoID, dirID)
		return errors
	}

	err = WriteRaw(repoID, dirID, &buf)
	if err != nil {
		errors := fmt.Errorf("failed to write seafdir object to storage : %v.\n", err)
		return errors
	}

	return nil
}

// Check if fs object is exists.
func Exists(repoID string, objID string) (bool, error) {
	return store.Exists(repoID, objID)
}

func comp(c rune) bool {
	if c == '/' {
		return true
	} else {
		return false
	}
}

// Check if the mode is dir.
func IsDir(m uint32) bool {
	return (m & syscall.S_IFMT) == syscall.S_IFDIR
}

// Get seafdir object by path.
func GetSeafdirByPath(repoID string, rootID string, path string) (*SeafDir, error) {
	dir, err := GetSeafdir(repoID, rootID)
	if err != nil {
		errors := fmt.Errorf("directory is missing.\n")
		return nil, errors
	}

	path = filepath.Join("/", path)
	parts := strings.FieldsFunc(path, comp)
	var dirID string
	for _, name := range parts {
		entries := dir.Entries
		for _, v := range entries {
			if v.Name == name && IsDir(v.Mode) {
				dirID = v.ID
				break
			}
		}

		if dirID == `` {
			errors := fmt.Errorf("path %s does not exists.\n", path)
			return nil, errors
		}

		dir, err = GetSeafdir(repoID, dirID)
		if err != nil {
			errors := fmt.Errorf("directory is missing.\n")
			return nil, errors
		}
	}

	return dir, nil
}
