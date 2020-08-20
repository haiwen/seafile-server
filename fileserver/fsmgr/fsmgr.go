// Package fsmgr manages fs objects
package fsmgr

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/haiwen/seafile-server/fileserver/objstore"
)

type Seafile struct {
	Version  int      `json:"version"`
	FileType int      `json:"type,omitempty"`
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
	Version int           `json:"version"`
	DirType int           `json:"type,omitempty"`
	DirID   string        `json:"dir_id,omitempty"`
	Entries []*SeafDirent `json:"dirents"`
}

type FileCountInfo struct {
	FileCount int64
	Size      int64
	DirCount  int64
}

const (
	SEAF_METADATA_TYPE_INVALID = iota
	SEAF_METADATA_TYPE_FILE
	SEAF_METADATA_TYPE_LINK
	SEAF_METADATA_TYPE_DIR
)

var store *objstore.ObjectStore

const (
	EMPTY_SHA1 = "0000000000000000000000000000000000000000"
)

// Init initializes fs manager and creates underlying object store.
func Init(seafileConfPath string, seafileDataDir string) {
	store = objstore.New(seafileConfPath, seafileDataDir, "fs")
}

func NewDirent(id string, name string, mode uint32, mtime int64, modifier string, size int64) *SeafDirent {
	dent := new(SeafDirent)
	dent.ID = id
	if id == "" {
		dent.ID = EMPTY_SHA1
	}
	dent.Name = name
	dent.Mode = mode
	dent.Mtime = mtime
	if IsRegular(mode) {
		dent.Modifier = modifier
		dent.Size = size
	}

	return dent
}

func NewSeafdir(version int, entries []*SeafDirent) (*SeafDir, error) {
	dir := new(SeafDir)
	dir.Version = version
	dir.Entries = entries
	jsonstr, err := json.Marshal(dir)
	if err != nil {
		err := fmt.Errorf("failed to convert seafdir to json.\n")
		return nil, err
	}
	checksum := sha1.Sum(jsonstr)
	dir.DirID = hex.EncodeToString(checksum[:])

	return dir, nil
}

func NewSeafile(version int, fileSize int64, blkIDs []string) (*Seafile, error) {
	seafile := new(Seafile)
	seafile.Version = version
	seafile.FileSize = uint64(fileSize)
	seafile.BlkIDs = blkIDs

	jsonstr, err := json.Marshal(seafile)
	if err != nil {
		err := fmt.Errorf("failed to convert seafile to json.\n")
		return nil, err
	}
	checkSum := sha1.Sum(jsonstr)
	seafile.FileID = hex.EncodeToString(checkSum[:])

	return seafile, nil
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
func SaveSeafile(repoID string, seafile *Seafile) error {
	fileID := seafile.FileID

	exist, _ := store.Exists(repoID, fileID)
	if exist {
		return nil
	}

	seafile.FileType = SEAF_METADATA_TYPE_FILE
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
func SaveSeafdir(repoID string, seafdir *SeafDir) error {
	dirID := seafdir.DirID
	exist, _ := store.Exists(repoID, dirID)
	if exist {
		return nil
	}

	seafdir.DirType = SEAF_METADATA_TYPE_DIR
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

// IsRegular Check if the mode is regular.
func IsRegular(m uint32) bool {
	return (m & syscall.S_IFMT) == syscall.S_IFREG
}

var PathNoExist = fmt.Errorf("path does not exist")

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
			return nil, PathNoExist
		}

		dir, err = GetSeafdir(repoID, dirID)
		if err != nil {
			errors := fmt.Errorf("directory is missing.\n")
			return nil, errors
		}
	}

	return dir, nil
}

func GetSeafdirIDByPath(repoID, rootID, path string) (string, error) {
	var name string
	var baseDir *SeafDir
	formatPath := filepath.Join(path)
	if len(formatPath) == 0 {
		return rootID, nil
	}
	lastIndex := strings.Index(formatPath, "/")
	if lastIndex == 0 {
		return rootID, nil
	} else if lastIndex < 0 {
		dir, err := GetSeafdir(repoID, rootID)
		if err != nil {
			err := fmt.Errorf("failed to find root dir %s: %v.\n", rootID, err)
			return "", err
		}
		name = formatPath
		baseDir = dir
	} else {
		name = filepath.Base(formatPath)
		dirName := filepath.Dir(formatPath)
		dir, err := GetSeafdirByPath(repoID, rootID, dirName)
		if err != nil {
			if err == PathNoExist {
				return "", PathNoExist
			}
			err := fmt.Errorf("failed to find dir %s in repo %s: %v.\n", dirName, repoID, err)
			return "", err
		}
		baseDir = dir
	}

	entries := baseDir.Entries
	for _, de := range entries {
		if de.Name == name {
			if IsDir(de.Mode) {
				return de.ID, nil
			}
			return "", nil
		}
	}

	return "", nil
}

func GetFileCountInfoByPath(repoID, rootID, path string) (*FileCountInfo, error) {
	dirID, err := GetSeafdirIDByPath(repoID, rootID, path)
	if err != nil {
		err := fmt.Errorf("failed to get file count info for repo %s path %s: %v.\n", repoID, path, err)
		return nil, err
	}

	info, err := getFileCountInfo(repoID, dirID)
	if err != nil {
		err := fmt.Errorf("failed to get file count in repo %s: %v.\n", repoID, err)
		return nil, err
	}

	return info, nil
}

func getFileCountInfo(repoID, dirID string) (*FileCountInfo, error) {
	dir, err := GetSeafdir(repoID, dirID)
	if err != nil {
		err := fmt.Errorf("failed to get dir: %v.\n", err)
		return nil, err
	}

	info := new(FileCountInfo)

	entries := dir.Entries
	for _, de := range entries {
		if IsDir(de.Mode) {
			tmpInfo, err := getFileCountInfo(repoID, de.ID)
			if err != nil {
				err := fmt.Errorf("failed to get file count: %v.\n", err)
				return nil, err
			}
			info.DirCount = tmpInfo.DirCount + 1
			info.FileCount += tmpInfo.FileCount
			info.Size += tmpInfo.Size
		} else {
			info.FileCount++
			info.Size += de.Size
		}
	}

	return info, nil
}
