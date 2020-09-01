package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"database/sql"
	"math/rand"
	"sort"
	"syscall"

	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

// Dirents is an alias for slice of SeafDirent.
type Dirents []*fsmgr.SeafDirent

func (d Dirents) Less(i, j int) bool {
	return d[i].Name > d[j].Name
}

func (d Dirents) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
func (d Dirents) Len() int {
	return len(d)
}

//contentType = "application/octet-stream"
func parseContentType(fileName string) string {
	var contentType string

	parts := strings.Split(fileName, ".")
	if len(parts) >= 2 {
		suffix := parts[len(parts)-1]
		switch suffix {
		case "txt":
			contentType = "text/plain"
		case "doc":
			contentType = "application/vnd.ms-word"
		case "docx":
			contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		case "ppt":
			contentType = "application/vnd.ms-powerpoint"
		case "xls":
			contentType = "application/vnd.ms-excel"
		case "xlsx":
			contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		case "pdf":
			contentType = "application/pdf"
		case "zip":
			contentType = "application/zip"
		case "mp3":
			contentType = "audio/mp3"
		case "mpeg":
			contentType = "video/mpeg"
		case "mp4":
			contentType = "video/mp4"
		case "jpeg", "JPEG", "jpg", "JPG":
			contentType = "image/jpeg"
		case "png", "PNG":
			contentType = "image/png"
		case "gif", "GIF":
			contentType = "image/gif"
		case "svg", "SVG":
			contentType = "image/svg+xml"
		}
	}

	return contentType
}

func testFireFox(r *http.Request) bool {
	userAgent, ok := r.Header["User-Agent"]
	if !ok {
		return false
	}

	userAgentStr := strings.Join(userAgent, "")
	if strings.Index(userAgentStr, "firefox") != -1 {
		return true
	}

	return false
}

func accessCB(rsp http.ResponseWriter, r *http.Request) *appError {
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 3 {
		msg := "Invalid URL"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	token := parts[1]
	fileName := parts[2]
	accessInfo, err := parseWebaccessInfo(token)
	if err != nil {
		return err
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	objID := accessInfo.objID

	if op != "view" && op != "download" && op != "download-link" {
		msg := "Bad access token"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if _, ok := r.Header["If-Modified-Since"]; ok {
		return &appError{nil, "", http.StatusNotModified}
	}

	now := time.Now()
	rsp.Header().Set("Last-Modified", now.Format("Mon, 2 Jan 2006 15:04:05 GMT"))
	rsp.Header().Set("Cache-Control", "max-age=3600")

	ranges := r.Header["Range"]
	byteRanges := strings.Join(ranges, "")

	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Bad repo id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user)
		if err != nil {
			return err
		}
		cryptKey = key
	}

	exists, _ := fsmgr.Exists(repo.StoreID, objID)
	if !exists {
		msg := "Invalid file id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if !repo.IsEncrypted && len(byteRanges) != 0 {
		if err := doFileRange(rsp, r, repo, objID, fileName, op, byteRanges, user); err != nil {
			return err
		}
	} else if err := doFile(rsp, r, repo, objID, fileName, op, cryptKey, user); err != nil {
		return err
	}

	return nil
}

type seafileCrypt struct {
	key []byte
	iv  []byte
}

func parseCryptKey(rsp http.ResponseWriter, repoID string, user string) (*seafileCrypt, *appError) {
	key, err := rpcclient.Call("seafile_get_decrypt_key", repoID, user)
	if err != nil {
		errMessage := "Repo is encrypted. Please provide password to view it."
		return nil, &appError{nil, errMessage, http.StatusBadRequest}
	}

	cryptKey, ok := key.(map[string]interface{})
	if !ok {
		err := fmt.Errorf("failed to assert crypt key")
		return nil, &appError{err, "", http.StatusInternalServerError}
	}

	seafileKey := new(seafileCrypt)

	if cryptKey != nil {
		key, ok := cryptKey["key"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt key")
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
		iv, ok := cryptKey["iv"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt iv")
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
		seafileKey.key, err = hex.DecodeString(key)
		if err != nil {
			err := fmt.Errorf("failed to decode key: %v", err)
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
		seafileKey.iv, err = hex.DecodeString(iv)
		if err != nil {
			err := fmt.Errorf("failed to decode iv: %v", err)
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
	}

	return seafileKey, nil
}

func doFile(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, cryptKey *seafileCrypt, user string) *appError {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		msg := "Failed to get seafile"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	var encKey, encIv []byte
	if cryptKey != nil {
		encKey = cryptKey.key
		encIv = cryptKey.iv
	}

	rsp.Header().Set("Access-Control-Allow-Origin", "*")

	setCommonHeaders(rsp, r, operation, fileName)

	//filesize string
	fileSize := fmt.Sprintf("%d", file.FileSize)
	rsp.Header().Set("Content-Length", fileSize)

	if r.Method == "HEAD" {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}
	if file.FileSize == 0 {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	if cryptKey != nil {
		for _, blkID := range file.BlkIDs {
			var buf bytes.Buffer
			blockmgr.Read(repo.StoreID, blkID, &buf)
			decoded, err := decrypt(buf.Bytes(), encKey, encIv)
			if err != nil {
				err := fmt.Errorf("failed to decrypt block %s: %v", blkID, err)
				return &appError{err, "", http.StatusInternalServerError}
			}
			_, err = rsp.Write(decoded)
			if err != nil {
				log.Printf("failed to write block %s to response: %v.\n", blkID, err)
				return nil
			}
		}
		return nil
	}

	for _, blkID := range file.BlkIDs {
		err := blockmgr.Read(repo.StoreID, blkID, rsp)
		if err != nil {
			log.Printf("fatild to write block %s to response: %v.\n", blkID, err)
			return nil
		}
	}

	return nil
}

func doFileRange(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, byteRanges string, user string) *appError {

	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		msg := "Failed to get seafile"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if file.FileSize == 0 {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	start, end, ok := parseRange(byteRanges, file.FileSize)
	if !ok {
		conRange := fmt.Sprintf("bytes */%d", file.FileSize)
		rsp.Header().Set("Content-Range", conRange)
		return &appError{nil, "", http.StatusRequestedRangeNotSatisfiable}
	}

	rsp.Header().Set("Accept-Ranges", "bytes")

	setCommonHeaders(rsp, r, operation, fileName)

	//filesize string
	conLen := fmt.Sprintf("%d", end-start+1)
	rsp.Header().Set("Content-Length", conLen)

	conRange := fmt.Sprintf("bytes %d-%d/%d", start, end, file.FileSize)
	rsp.Header().Set("Content-Range", conRange)

	var blkSize []uint64
	for _, v := range file.BlkIDs {
		size, err := blockmgr.Stat(repo.StoreID, v)
		if err != nil {
			err := fmt.Errorf("failed to stat block %s : %v", v, err)
			return &appError{err, "", http.StatusInternalServerError}
		}
		blkSize = append(blkSize, uint64(size))
	}

	var off uint64
	var pos uint64
	var startBlock int
	for i, v := range blkSize {
		pos = start - off
		off += v
		if off > start {
			startBlock = i
			break
		}
	}

	// Read block from the start block and specified position
	var i int
	for ; i < len(file.BlkIDs); i++ {
		if i < startBlock {
			continue
		}

		blkID := file.BlkIDs[i]
		var buf bytes.Buffer
		if end-start+1 <= blkSize[i]-pos {
			err := blockmgr.Read(repo.StoreID, blkID, &buf)
			if err != nil {
				log.Printf("failed to read block %s: %v.\n", blkID, err)
				return nil
			}
			recvBuf := buf.Bytes()
			_, err = rsp.Write(recvBuf[pos : pos+end-start+1])
			if err != nil {
				log.Printf("failed to write block %s to response: %v.\n", blkID, err)
			}
			return nil
		}

		err := blockmgr.Read(repo.StoreID, blkID, &buf)
		if err != nil {
			log.Printf("failed to read block %s: %v.\n", blkID, err)
			return nil
		}
		recvBuf := buf.Bytes()
		_, err = rsp.Write(recvBuf[pos:])
		if err != nil {
			log.Printf("failed to write block %s to response: %v.\n", blkID, err)
			return nil
		}
		start += blkSize[i] - pos
		i++
		break
	}

	// Always read block from the remaining block and pos=0
	for ; i < len(file.BlkIDs); i++ {
		blkID := file.BlkIDs[i]
		var buf bytes.Buffer
		if end-start+1 <= blkSize[i] {
			err := blockmgr.Read(repo.StoreID, blkID, &buf)
			if err != nil {
				log.Printf("failed to read block %s: %v.\n", blkID, err)
				return nil
			}
			recvBuf := buf.Bytes()
			_, err = rsp.Write(recvBuf[:end-start+1])
			if err != nil {
				log.Printf("failed to write block %s to response: %v.\n", blkID, err)
				return nil
			}
			break
		} else {
			err := blockmgr.Read(repo.StoreID, blkID, rsp)
			if err != nil {
				log.Printf("failed to write block %s to response: %v.\n", blkID, err)
				return nil
			}
			start += blkSize[i]
		}
	}

	return nil
}

func parseRange(byteRanges string, fileSize uint64) (uint64, uint64, bool) {
	start := strings.Index(byteRanges, "=")
	end := strings.Index(byteRanges, "-")

	if end < 0 {
		return 0, 0, false
	}

	var startByte, endByte uint64

	if start+1 == end {
		retByte, err := strconv.ParseUint(byteRanges[end+1:], 10, 64)
		if err != nil || retByte == 0 {
			return 0, 0, false
		}
		startByte = fileSize - retByte
		endByte = fileSize - 1
	} else if end+1 == len(byteRanges) {
		firstByte, err := strconv.ParseUint(byteRanges[start+1:end], 10, 64)
		if err != nil {
			return 0, 0, false
		}

		startByte = firstByte
		endByte = fileSize - 1
	} else {
		firstByte, err := strconv.ParseUint(byteRanges[start+1:end], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		lastByte, err := strconv.ParseUint(byteRanges[end+1:], 10, 64)
		if err != nil {
			return 0, 0, false
		}

		if lastByte > fileSize-1 {
			lastByte = fileSize - 1
		}

		startByte = firstByte
		endByte = lastByte
	}

	if startByte > endByte {
		return 0, 0, false
	}

	return startByte, endByte, true
}

func setCommonHeaders(rsp http.ResponseWriter, r *http.Request, operation, fileName string) {
	fileType := parseContentType(fileName)
	if fileType != "" {
		var contentType string
		if strings.Index(fileType, "text") != -1 {
			contentType = fileType + "; " + "charset=gbk"
		} else {
			contentType = fileType
		}
		rsp.Header().Set("Content-Type", contentType)
	} else {
		rsp.Header().Set("Content-Type", "application/octet-stream")
	}

	var contFileName string
	if operation == "download" || operation == "download-link" ||
		operation == "downloadblks" {
		if testFireFox(r) {
			contFileName = fmt.Sprintf("attachment;filename*=\"utf-8' '%s\"", fileName)
		} else {
			contFileName = fmt.Sprintf("attachment;filename*=\"%s\"", fileName)
		}
	} else {
		if testFireFox(r) {
			contFileName = fmt.Sprintf("inline;filename*=\"utf-8' '%s\"", fileName)
		} else {
			contFileName = fmt.Sprintf("inline;filename=\"%s\"", fileName)
		}
	}
	rsp.Header().Set("Content-Disposition", contFileName)

	if fileType != "image/jpg" {
		rsp.Header().Set("X-Content-Type-Options", "nosniff")
	}
}

func accessBlksCB(rsp http.ResponseWriter, r *http.Request) *appError {
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 3 {
		msg := "Invalid URL"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	token := parts[1]
	blkID := parts[2]
	accessInfo, err := parseWebaccessInfo(token)
	if err != nil {
		return err
	}
	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	id := accessInfo.objID

	if _, ok := r.Header["If-Modified-Since"]; ok {
		return &appError{nil, "", http.StatusNotModified}
	}

	now := time.Now()
	rsp.Header().Set("Last-Modified", now.Format("Mon, 2 Jan 2006 15:04:05 GMT"))
	rsp.Header().Set("Cache-Control", "max-age=3600")

	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Bad repo id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	exists, _ := fsmgr.Exists(repo.StoreID, id)
	if !exists {
		msg := "Invalid file id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if op != "downloadblks" {
		msg := "Bad access token"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if err := doBlock(rsp, r, repo, id, user, blkID); err != nil {
		return err
	}

	return nil
}

func doBlock(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	user string, blkID string) *appError {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		msg := "Failed to get seafile"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	var found bool
	for _, id := range file.BlkIDs {
		if id == blkID {
			found = true
			break
		}
	}

	if !found {
		rsp.WriteHeader(http.StatusBadRequest)
		return nil
	}

	exists := blockmgr.Exists(repo.StoreID, blkID)
	if !exists {
		rsp.WriteHeader(http.StatusBadRequest)
		return nil
	}

	rsp.Header().Set("Access-Control-Allow-Origin", "*")
	setCommonHeaders(rsp, r, "downloadblks", blkID)

	size, err := blockmgr.Stat(repo.StoreID, blkID)
	if err != nil {
		msg := "Failed to stat block"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	if size == 0 {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	fileSize := fmt.Sprintf("%d", size)
	rsp.Header().Set("Content-Length", fileSize)

	err = blockmgr.Read(repo.StoreID, blkID, rsp)
	if err != nil {
		log.Printf("fatild to write block %s to response: %v.\n", blkID, err)
	}

	return nil
}

func accessZipCB(rsp http.ResponseWriter, r *http.Request) *appError {
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) != 2 {
		msg := "Invalid URL"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	token := parts[1]

	accessInfo, err := parseWebaccessInfo(token)
	if err != nil {
		return err
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	data := accessInfo.objID

	if op != "download-dir" && op != "download-dir-link" &&
		op != "download-multi" && op != "download-multi-link" {
		err := fmt.Errorf("wrong operation of token: %s", op)
		return &appError{err, "", http.StatusInternalServerError}
	}

	if _, ok := r.Header["If-Modified-Since"]; ok {
		return &appError{nil, "", http.StatusNotModified}
	}

	now := time.Now()
	rsp.Header().Set("Last-Modified", now.Format("Mon, 2 Jan 2006 15:04:05 GMT"))
	rsp.Header().Set("Cache-Control", "max-age=3600")

	if err := downloadZipFile(rsp, r, data, repoID, user, op); err != nil {
		return err
	}

	return nil
}

func downloadZipFile(rsp http.ResponseWriter, r *http.Request, data, repoID, user, op string) *appError {
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	obj := make(map[string]interface{})
	err := json.Unmarshal([]byte(data), &obj)
	if err != nil {
		err := fmt.Errorf("failed to parse obj data for zip: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	ar := zip.NewWriter(rsp)
	defer ar.Close()

	if op == "download-dir" || op == "download-dir-link" {
		dirName, ok := obj["dir_name"].(string)
		if !ok || dirName == "" {
			err := fmt.Errorf("invalid download dir data: miss dir_name field")
			return &appError{err, "", http.StatusInternalServerError}
		}

		objID, ok := obj["obj_id"].(string)
		if !ok || objID == "" {
			err := fmt.Errorf("invalid download dir data: miss obj_id field")
			return &appError{err, "", http.StatusInternalServerError}
		}

		setCommonHeaders(rsp, r, "download", dirName)

		err := packDir(ar, repo, objID, dirName)
		if err != nil {
			log.Printf("failed to pack dir %s: %v.\n", dirName, err)
			return nil
		}
	} else {
		dirList, err := parseDirFilelist(repo, obj)
		if err != nil {
			return &appError{err, "", http.StatusInternalServerError}
		}

		now := time.Now()
		zipName := fmt.Sprintf("documents-export-%d-%d-%d.zip", now.Year(), now.Month(), now.Day())

		setCommonHeaders(rsp, r, "download", zipName)

		for _, v := range dirList {
			if fsmgr.IsDir(v.Mode) {
				if err := packDir(ar, repo, v.ID, v.Name); err != nil {
					log.Printf("failed to pack dir %s: %v.\n", v.Name, err)
					return nil
				}
			} else {
				if err := packFiles(ar, &v, repo, ""); err != nil {
					log.Printf("failed to pack file %s: %v.\n", v.Name, err)
					return nil
				}
			}
		}
	}

	return nil
}

func parseDirFilelist(repo *repomgr.Repo, obj map[string]interface{}) ([]fsmgr.SeafDirent, error) {
	parentDir, ok := obj["parent_dir"].(string)
	if !ok || parentDir == "" {
		err := fmt.Errorf("invalid download multi data, miss parent_dir field")
		return nil, err
	}

	dir, err := fsmgr.GetSeafdirByPath(repo.StoreID, repo.RootID, parentDir)
	if err != nil {
		err := fmt.Errorf("failed to get dir %s repo %s", parentDir, repo.StoreID)
		return nil, err
	}

	fileList, ok := obj["file_list"].([]interface{})
	if !ok || fileList == nil {
		err := fmt.Errorf("invalid download multi data, miss file_list field")
		return nil, err
	}

	direntHash := make(map[string]fsmgr.SeafDirent)
	for _, v := range dir.Entries {
		direntHash[v.Name] = *v
	}

	direntList := make([]fsmgr.SeafDirent, 0)

	for _, fileName := range fileList {
		name, ok := fileName.(string)
		if !ok {
			err := fmt.Errorf("invalid download multi data")
			return nil, err
		}

		v, ok := direntHash[name]
		if !ok {
			err := fmt.Errorf("invalid download multi data")
			return nil, err
		}

		direntList = append(direntList, v)
	}

	return direntList, nil
}

func packDir(ar *zip.Writer, repo *repomgr.Repo, dirID, dirPath string) error {
	dirent, err := fsmgr.GetSeafdir(repo.StoreID, dirID)
	if err != nil {
		err := fmt.Errorf("failed to get dir for zip: %v", err)
		return err
	}

	if dirent.Entries == nil {
		fileDir := filepath.Join(dirPath)
		fileDir = strings.TrimLeft(fileDir, "/")
		_, err := ar.Create(fileDir + "/")
		if err != nil {
			err := fmt.Errorf("failed to create zip dir: %v", err)
			return err
		}

		return nil
	}

	entries := dirent.Entries

	for _, v := range entries {
		fileDir := filepath.Join(dirPath, v.Name)
		fileDir = strings.TrimLeft(fileDir, "/")
		if fsmgr.IsDir(v.Mode) {
			if err := packDir(ar, repo, v.ID, fileDir); err != nil {
				return err
			}
		} else {
			if err := packFiles(ar, v, repo, dirPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func packFiles(ar *zip.Writer, dirent *fsmgr.SeafDirent, repo *repomgr.Repo, parentPath string) error {
	file, err := fsmgr.GetSeafile(repo.StoreID, dirent.ID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v", err)
		return err
	}

	filePath := filepath.Join(parentPath, dirent.Name)
	filePath = strings.TrimLeft(filePath, "/")

	fileHeader := new(zip.FileHeader)
	fileHeader.Name = filePath
	fileHeader.Modified = time.Unix(dirent.Mtime, 0)
	fileHeader.Method = zip.Deflate
	zipFile, err := ar.CreateHeader(fileHeader)
	if err != nil {
		err := fmt.Errorf("failed to create zip file : %v", err)
		return err
	}

	for _, blkID := range file.BlkIDs {
		err := blockmgr.Read(repo.StoreID, blkID, zipFile)
		if err != nil {
			return err
		}
	}

	return nil
}

type recvData struct {
	parentDir   string
	tokenType   string
	repoID      string
	user        string
	rstart      int64
	rend        int64
	fsize       int64
	fileNames   []string
	files       []string
	fileHeaders []*multipart.FileHeader
}

func uploadAPICB(rsp http.ResponseWriter, r *http.Request) *appError {
	fsm, err := parseUploadHeaders(r)
	if err != nil {
		return err
	}

	if err := doUpload(rsp, r, fsm, false); err != nil {
		formatJSONError(rsp, err)
		return err
	}

	return nil
}

func uploadAjaxCB(rsp http.ResponseWriter, r *http.Request) *appError {
	fsm, err := parseUploadHeaders(r)
	if err != nil {
		return err
	}

	if err := doUpload(rsp, r, fsm, true); err != nil {
		formatJSONError(rsp, err)
		return err
	}

	return nil
}

func formatJSONError(rsp http.ResponseWriter, err *appError) {
	if err.Message != "" {
		rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
		err.Message = fmt.Sprintf("\"error\": \"%s\"", err.Message)
	}
}

func doUpload(rsp http.ResponseWriter, r *http.Request, fsm *recvData, isAjax bool) *appError {
	rsp.Header().Set("Access-Control-Allow-Origin", "*")
	rsp.Header().Set("Access-Control-Allow-Headers", "x-requested-with, content-type, content-range, content-disposition, accept, origin, authorization")
	rsp.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	rsp.Header().Set("Access-Control-Max-Age", "86400")

	if r.Method == "OPTIONS" {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return &appError{nil, "", http.StatusBadRequest}
	}
	defer r.MultipartForm.RemoveAll()

	repoID := fsm.repoID
	user := fsm.user

	replaceStr := r.FormValue("replace")
	var replaceExisted bool
	if replaceStr != "" {
		replace, err := strconv.ParseInt(replaceStr, 10, 64)
		if err != nil || (replace != 0 && replace != 1) {
			msg := "Invalid argument.\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		if replace == 1 {
			replaceExisted = true
		}
	}

	parentDir := r.FormValue("parent_dir")
	if parentDir == "" {
		msg := "Invalid URL.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	relativePath := r.FormValue("relative_path")
	if relativePath != "" {
		if relativePath[0] == '/' || relativePath[0] == '\\' {
			msg := "Invalid relative path"
			return &appError{nil, msg, http.StatusBadRequest}
		}
	}

	newParentDir := filepath.Join("/", parentDir, relativePath)
	defer clearTmpFile(fsm, newParentDir)

	if fsm.rstart >= 0 {
		if parentDir[0] != '/' {
			msg := "Invalid parent dir"
			return &appError{nil, msg, http.StatusBadRequest}
		}

		formFiles := r.MultipartForm.File
		files, ok := formFiles["file"]
		if !ok {
			msg := "No file in multipart form.\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}

		if len(files) > 1 {
			msg := "More files in one request"
			return &appError{nil, msg, http.StatusBadRequest}
		}

		err := writeBlockDataToTmpFile(r, fsm, formFiles, repoID, newParentDir)
		if err != nil {
			msg := "Internal error.\n"
			err := fmt.Errorf("failed to write block data to tmp file: %v", err)
			return &appError{err, msg, http.StatusInternalServerError}
		}

		if fsm.rend != fsm.fsize-1 {
			success := "{\"success\": true}"
			_, err := rsp.Write([]byte(success))
			if err != nil {
				log.Printf("failed to write data to response.\n")
			}
			rsp.Header().Set("Content-Type", "application/json; charset=utf-8")

			return nil
		}
	} else {
		formFiles := r.MultipartForm.File
		fileHeaders, ok := formFiles["file"]
		if !ok {
			msg := "No file in multipart form.\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		for _, handler := range fileHeaders {
			fileName := filepath.Base(handler.Filename)
			fsm.fileNames = append(fsm.fileNames, fileName)
			fsm.fileHeaders = append(fsm.fileHeaders, handler)
		}
	}

	if fsm.fileNames == nil {
		msg := "No file.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if err := checkParentDir(repoID, parentDir); err != nil {
		return err
	}

	if !isParentMatched(fsm.parentDir, parentDir) {
		msg := "Permission denied."
		return &appError{nil, msg, http.StatusForbidden}
	}

	if err := checkTmpFileList(fsm); err != nil {
		return err
	}

	var contentLen int64
	if fsm.fsize > 0 {
		contentLen = fsm.fsize
	} else {
		lenstr := rsp.Header().Get("Content-Length")
		if lenstr == "" {
			contentLen = -1
		} else {
			tmpLen, err := strconv.ParseInt(lenstr, 10, 64)
			if err != nil {
				msg := "Internal error.\n"
				err := fmt.Errorf("failed to parse content len: %v", err)
				return &appError{err, msg, http.StatusInternalServerError}
			}
			contentLen = tmpLen
		}
	}

	ret, err := checkQuota(repoID, contentLen)
	if err != nil {
		msg := "Internal error.\n"
		err := fmt.Errorf("failed to check quota: %v", err)
		return &appError{err, msg, http.StatusInternalServerError}
	}
	if ret == 1 {
		msg := "Out of quota.\n"
		return &appError{nil, msg, 443}
	}

	if err := createRelativePath(repoID, parentDir, relativePath, user); err != nil {
		return err
	}

	if err := postMultiFiles(rsp, r, repoID, newParentDir, user, fsm,
		replaceExisted, isAjax); err != nil {
		return err
	}

	rsp.Header().Set("Content-Type", "application/json; charset=utf-8")

	oper := "web-file-upload"
	if fsm.tokenType == "upload-link" {
		oper = "link-file-upload"
	}

	sendStatisticMsg(repoID, user, oper, uint64(contentLen))

	return nil
}

func writeBlockDataToTmpFile(r *http.Request, fsm *recvData, formFiles map[string][]*multipart.FileHeader,
	repoID, parentDir string) error {
	httpTempDir := filepath.Join(absDataDir, "httptemp")

	fileHeaders, ok := formFiles["file"]
	if !ok {
		err := fmt.Errorf("failed to get file from multipart form")
		return err
	}

	disposition := r.Header.Get("Content-Disposition")
	if disposition == "" {
		err := fmt.Errorf("missing content disposition")
		return err
	}

	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		err := fmt.Errorf("failed to parse Content-Disposition: %v", err)
		return err
	}
	filename, err := url.QueryUnescape(params["filename"])
	if err != nil {
		err := fmt.Errorf("failed to get filename: %v", err)
		return err
	}

	handler := fileHeaders[0]
	file, err := handler.Open()
	if err != nil {
		err := fmt.Errorf("failed to open file for read: %v", err)
		return err
	}
	defer file.Close()

	var f *os.File
	//filename := handler.Filename
	filePath := filepath.Join("/", parentDir, filename)
	tmpFile, err := repomgr.GetUploadTmpFile(repoID, filePath)
	if err != nil || tmpFile == "" {
		tmpDir := filepath.Join(httpTempDir, "cluster-shared")
		f, err = ioutil.TempFile(tmpDir, filename)
		if err != nil {
			return err
		}
		repomgr.AddUploadTmpFile(repoID, filePath, f.Name())
		tmpFile = f.Name()
	} else {
		f, err = os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			return err
		}
	}

	if fsm.rend == fsm.fsize-1 {
		fileName := filepath.Base(filename)
		fsm.fileNames = append(fsm.fileNames, fileName)
		fsm.files = append(fsm.files, tmpFile)
	}

	f.Seek(fsm.rstart, 0)
	io.Copy(f, file)
	f.Close()

	return nil
}

func createRelativePath(repoID, parentDir, relativePath, user string) *appError {
	if relativePath == "" {
		return nil
	}

	err := mkdirWithParents(repoID, parentDir, relativePath, user)
	if err != nil {
		msg := "Internal error.\n"
		err := fmt.Errorf("Failed to create parent directory: %v", err)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	return nil
}

func mkdirWithParents(repoID, parentDir, newDirPath, user string) error {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %s", repoID)
		return err
	}

	headCommit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
		return err
	}

	relativeDirCan := getCanonPath(newDirPath)

	subFolders := strings.Split(relativeDirCan, "/")

	for _, name := range subFolders {
		if name == "" {
			continue
		}
		if shouldIgnoreFile(name) {
			err := fmt.Errorf("invalid dir name %s", name)
			return err
		}
	}

	var rootID string
	var parentDirCan string
	if parentDir == "/" || parentDir == "\\" {
		parentDirCan = "/"
	} else {
		parentDirCan = getCanonPath(parentDir)
	}

	absPath, dirID, err := checkAndCreateDir(repo, headCommit.RootID, parentDirCan, subFolders)
	if err != nil {
		err := fmt.Errorf("failed to check and create dir: %v", err)
		return err
	}
	if absPath == "" {
		return nil
	}
	newRootID := headCommit.RootID
	mtime := time.Now().Unix()
	mode := (syscall.S_IFDIR | 0644)
	dent := fsmgr.NewDirent(dirID, filepath.Base(absPath), uint32(mode), mtime, "", 0)

	var names []string
	rootID, _ = doPostMultiFiles(repo, newRootID, filepath.Dir(absPath), []*fsmgr.SeafDirent{dent}, user, false, &names)
	if rootID == "" {
		err := fmt.Errorf("failed to put dir")
		return err
	}

	buf := fmt.Sprintf("Added directory \"%s\"", relativeDirCan)
	_, err = genNewCommit(repo, headCommit, rootID, user, buf)
	if err != nil {
		err := fmt.Errorf("failed to generate new commit: %v", err)
		return err
	}

	go mergeVirtualRepo(repo.ID, "")

	return nil
}

func checkAndCreateDir(repo *repomgr.Repo, rootID, parentDir string, subFolders []string) (string, string, error) {
	storeID := repo.StoreID
	dir, err := fsmgr.GetSeafdirByPath(storeID, rootID, parentDir)
	if err != nil {
		err := fmt.Errorf("parent_dir %s doesn't exist in repo %s", parentDir, storeID)
		return "", "", err
	}

	entries := dir.Entries
	var exists bool
	var absPath string
	var dirList []string
	for i, dirName := range subFolders {
		for _, de := range entries {
			if de.Name == dirName {
				exists = true
				subDir, err := fsmgr.GetSeafdir(storeID, de.ID)
				if err != nil {
					err := fmt.Errorf("failed to get seaf dir: %v", err)
					return "", "", err
				}
				entries = subDir.Entries
				break
			}
		}

		if !exists {
			relativePath := filepath.Join(subFolders[:i+1]...)
			absPath = filepath.Join(parentDir, relativePath)
			dirList = subFolders[i:]
			break
		}
		exists = false
	}
	if dirList != nil {
		dirList = dirList[1:]
	}
	if len(dirList) == 0 {
		return absPath, "", nil
	}

	dirID, err := genDirRecursive(repo, dirList)
	if err != nil {
		err := fmt.Errorf("failed to generate dir recursive: %v", err)
		return "", "", err
	}

	return absPath, dirID, nil
}

func genDirRecursive(repo *repomgr.Repo, toPath []string) (string, error) {
	if len(toPath) == 1 {
		uniqueName := toPath[0]
		mode := (syscall.S_IFDIR | 0644)
		mtime := time.Now().Unix()
		dent := fsmgr.NewDirent("", uniqueName, uint32(mode), mtime, "", 0)
		newdir, err := fsmgr.NewSeafdir(1, []*fsmgr.SeafDirent{dent})
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v", err)
			return "", err
		}
		err = fsmgr.SaveSeafdir(repo.StoreID, newdir)
		if err != nil {
			err := fmt.Errorf("failed to save seafdir %s/%s", repo.ID, newdir.DirID)
			return "", err
		}

		return newdir.DirID, nil
	}

	ret, err := genDirRecursive(repo, toPath[1:])
	if err != nil {
		err := fmt.Errorf("failed to generate dir recursive: %v", err)
		return "", err
	}
	if ret != "" {
		uniqueName := toPath[0]
		mode := (syscall.S_IFDIR | 0644)
		mtime := time.Now().Unix()
		dent := fsmgr.NewDirent(ret, uniqueName, uint32(mode), mtime, "", 0)
		newdir, err := fsmgr.NewSeafdir(1, []*fsmgr.SeafDirent{dent})
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v", err)
			return "", err
		}
		err = fsmgr.SaveSeafdir(repo.StoreID, newdir)
		if err != nil {
			err := fmt.Errorf("failed to save seafdir %s/%s", repo.ID, newdir.DirID)
			return "", err
		}
		ret = newdir.DirID
	}

	return ret, nil
}

func clearTmpFile(fsm *recvData, parentDir string) {
	if fsm.rstart >= 0 && fsm.rend == fsm.fsize-1 {
		filePath := filepath.Join("/", parentDir, fsm.fileNames[0])
		tmpFile, err := repomgr.GetUploadTmpFile(fsm.repoID, filePath)
		if err == nil && tmpFile != "" {
			os.Remove(tmpFile)
		}
		repomgr.DelUploadTmpFile(fsm.repoID, filePath)
	}

	return
}

func parseUploadHeaders(r *http.Request) (*recvData, *appError) {
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 2 {
		msg := "Invalid URL"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}
	urlOp := parts[0]
	token := parts[1]

	accessInfo, appErr := parseWebaccessInfo(token)
	if appErr != nil {
		msg := "Access denied"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	id := accessInfo.objID

	status, err := repomgr.GetRepoStatus(repoID)
	if err != nil {
		msg := "Internal error.\n"
		return nil, &appError{nil, msg, http.StatusInternalServerError}
	}
	if status != repomgr.RepoStatusNormal && status != -1 {
		msg := "Access denied"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}

	if op == "upload-link" {
		op = "upload"
	}
	if strings.Index(urlOp, op) != 0 {
		msg := "Access denied"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}

	obj := make(map[string]interface{})
	if err := json.Unmarshal([]byte(id), &obj); err != nil {
		err := fmt.Errorf("failed to decode obj data : %v", err)
		return nil, &appError{err, "", http.StatusBadRequest}
	}

	parentDir, ok := obj["parent_dir"].(string)
	if !ok || parentDir == "" {
		msg := "Invalid URL"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}

	fsm := new(recvData)

	fsm.parentDir = parentDir
	fsm.tokenType = accessInfo.op
	fsm.repoID = repoID
	fsm.user = user
	fsm.rstart = -1
	fsm.rend = -1
	fsm.fsize = -1

	ranges := r.Header.Get("Content-Range")
	if ranges != "" {
		parseContentRange(ranges, fsm)
	}

	return fsm, nil
}

func postMultiFiles(rsp http.ResponseWriter, r *http.Request, repoID, parentDir, user string, fsm *recvData, replace bool, isAjax bool) *appError {

	fileNames := fsm.fileNames
	files := fsm.files
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo.\n"
		err := fmt.Errorf("Failed to get repo %s", repoID)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	canonPath := getCanonPath(parentDir)

	for _, fileName := range fileNames {
		if shouldIgnoreFile(fileName) {
			msg := fmt.Sprintf("invalid fileName: %s.\n", fileName)
			return &appError{nil, msg, http.StatusBadRequest}
		}
	}
	if strings.Index(parentDir, "//") != -1 {
		msg := "parent_dir contains // sequence.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user)
		if err != nil {
			return err
		}
		cryptKey = key
	}

	var ids []string
	var sizes []int64
	if fsm.rstart >= 0 {
		for _, filePath := range files {
			id, size, err := indexBlocks(repo.StoreID, repo.Version, filePath, nil, cryptKey)
			if err != nil {
				err := fmt.Errorf("failed to index blocks: %v", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
			ids = append(ids, id)
			sizes = append(sizes, size)
		}
	} else {
		for _, handler := range fsm.fileHeaders {
			id, size, err := indexBlocks(repo.StoreID, repo.Version, "", handler, cryptKey)
			if err != nil {
				err := fmt.Errorf("failed to index blocks: %v", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
			ids = append(ids, id)
			sizes = append(sizes, size)

		}
	}

	retStr, err := postFilesAndGenCommit(fileNames, repo, user, canonPath, replace, ids, sizes)
	if err != nil {
		err := fmt.Errorf("failed to post files and gen commit: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	_, ok := r.Form["ret-json"]
	if ok || isAjax {
		rsp.Write([]byte(retStr))
	} else {
		var array []map[string]interface{}
		err := json.Unmarshal([]byte(retStr), &array)
		if err != nil {
			msg := "Internal error.\n"
			err := fmt.Errorf("failed to decode data to json: %v", err)
			return &appError{err, msg, http.StatusInternalServerError}
		}

		var ids []string
		for _, v := range array {
			id, ok := v["id"].(string)
			if !ok {
				msg := "Internal error.\n"
				err := fmt.Errorf("failed to assert")
				return &appError{err, msg, http.StatusInternalServerError}
			}
			ids = append(ids, id)
		}
		newIDs := strings.Join(ids, "\t")
		rsp.Write([]byte(newIDs))
	}

	return nil
}

func postFilesAndGenCommit(fileNames []string, repo *repomgr.Repo, user, canonPath string, replace bool, ids []string, sizes []int64) (string, error) {
	headCommit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
		return "", err
	}
	var names []string

	var dents []*fsmgr.SeafDirent
	for i, name := range fileNames {
		if i > len(ids)-1 || i > len(sizes)-1 {
			break
		}
		mode := (syscall.S_IFREG | 0644)
		mtime := time.Now().Unix()
		dent := fsmgr.NewDirent(ids[i], name, uint32(mode), mtime, "", sizes[i])
		dents = append(dents, dent)
	}

	rootID, err := doPostMultiFiles(repo, headCommit.RootID, canonPath, dents, user, replace, &names)
	if err != nil {
		err := fmt.Errorf("failed to post files to %s in repo %s", canonPath, repo.ID)
		return "", err
	}

	var buf string
	if len(fileNames) > 1 {
		buf = fmt.Sprintf("Added \"%s\" and %d more files.", fileNames[0], len(fileNames)-1)
	} else {
		buf = fmt.Sprintf("Added \"%s\".", fileNames[0])
	}

	_, err = genNewCommit(repo, headCommit, rootID, user, buf)
	if err != nil {
		err := fmt.Errorf("failed to generate new commit: %v", err)
		return "", err
	}

	go mergeVirtualRepo(repo.ID, "")

	go updateRepoSize(repo.ID)

	retJSON, err := formatJSONRet(names, ids, sizes)
	if err != nil {
		err := fmt.Errorf("failed to format json data")
		return "", err
	}

	return string(retJSON), nil
}

func formatJSONRet(nameList, idList []string, sizeList []int64) ([]byte, error) {
	var array []map[string]interface{}
	for i := range nameList {
		if i >= len(idList) || i >= len(sizeList) {
			break
		}
		obj := make(map[string]interface{})
		obj["name"] = nameList[i]
		obj["id"] = idList[i]
		obj["size"] = sizeList[i]
		array = append(array, obj)
	}

	jsonstr, err := json.Marshal(array)
	if err != nil {
		err := fmt.Errorf("failed to convert array to json")
		return nil, err
	}

	return jsonstr, nil
}

func getCanonPath(p string) string {
	formatPath := strings.Replace(p, "\\", "/", -1)
	return filepath.Join(formatPath)
}

func genNewCommit(repo *repomgr.Repo, base *commitmgr.Commit, newRoot, user, desc string) (string, error) {
	var retryCnt int
	repoID := repo.ID
	commit := commitmgr.NewCommit(repoID, base.CommitID, newRoot, user, desc)
	repomgr.RepoToCommit(repo, commit)
	err := commitmgr.Save(commit)
	if err != nil {
		err := fmt.Errorf("failed to add commit: %v", err)
		return "", err
	}
	var commitID string

	for retry, err := genCommitNeedRetry(repo, base, commit, newRoot, user, &commitID); retry || err != nil; {
		if err != nil {
			return "", err
		}

		if retryCnt < 3 {
			random := rand.Intn(10) + 1
			time.Sleep(time.Duration(random*100) * time.Millisecond)
			repo = repomgr.Get(repoID)
			if repo == nil {
				err := fmt.Errorf("repo %s doesn't exist", repoID)
				return "", err
			}
			retryCnt++
		} else {
			err := fmt.Errorf("stop updating repo %s after 3 retries", repoID)
			return "", err
		}
	}

	return commitID, nil
}

func genCommitNeedRetry(repo *repomgr.Repo, base *commitmgr.Commit, commit *commitmgr.Commit, newRoot, user string, commitID *string) (bool, error) {
	repoID := repo.ID
	var mergeDesc string
	var mergedCommit *commitmgr.Commit
	currentHead, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get head commit for repo %s", repoID)
		return false, err
	}
	if base.CommitID != currentHead.CommitID {
		roots := []string{base.RootID, currentHead.RootID, newRoot}
		opt := new(mergeOptions)
		opt.remoteRepoID = repoID
		opt.remoteHead = commit.CommitID

		err := mergeTrees(repo.StoreID, roots, opt)
		if err != nil {
			err := fmt.Errorf("failed to merge")
			return false, err
		}

		if !opt.conflict {
			mergeDesc = fmt.Sprintf("Auto merge by system")
		} else {
			mergeDesc = genMergeDesc(repo, opt.mergedRoot, currentHead.RootID, newRoot)
			if mergeDesc == "" {
				mergeDesc = fmt.Sprintf("Auto merge by system")
			}
		}

		mergedCommit = commitmgr.NewCommit(repoID, currentHead.CommitID, opt.mergedRoot, user, mergeDesc)
		repomgr.RepoToCommit(repo, mergedCommit)
		mergedCommit.SecondParentID = commit.CommitID
		mergedCommit.NewMerge = 1
		if opt.conflict {
			mergedCommit.Conflict = 1
		}

		err = commitmgr.Save(commit)
		if err != nil {
			err := fmt.Errorf("failed to add commit: %v", err)
			return false, err
		}
	} else {
		mergedCommit = commit
	}

	err = updateBranch(repoID, mergedCommit.CommitID, currentHead.CommitID)
	if err != nil {
		return true, nil
	}

	*commitID = mergedCommit.CommitID
	return false, nil
}

func genMergeDesc(repo *repomgr.Repo, mergedRoot, p1Root, p2Root string) string {
	var results []interface{}
	err := diffMergeRoots(repo.StoreID, mergedRoot, p1Root, p2Root, &results, true)
	if err != nil {
		return ""
	}

	desc := diffResultsToDesc(results)

	return desc
}

func updateBranch(repoID, newCommitID, oldCommitID string) error {
	var commitID string
	name := "master"
	sqlStr := "SELECT commit_id FROM Branch WHERE name = ? AND repo_id = ? FOR UPDATE"

	trans, err := seafileDB.Begin()
	if err != nil {
		err := fmt.Errorf("failed to start transaction: %v", err)
		return err
	}
	row := trans.QueryRow(sqlStr, name, repoID)
	if err := row.Scan(&commitID); err != nil {
		if err != sql.ErrNoRows {
			trans.Rollback()
			return err
		}
	}
	if oldCommitID != commitID {
		trans.Rollback()
		err := fmt.Errorf("head commit id has changed")
		return err
	}

	sqlStr = "UPDATE Branch SET commit_id = ? WHERE name = ? AND repo_id = ?"
	_, err = trans.Exec(sqlStr, newCommitID, name, repoID)
	if err != nil {
		trans.Rollback()
		return err
	}

	trans.Commit()

	return nil
}

func doPostMultiFiles(repo *repomgr.Repo, rootID, parentDir string, dents []*fsmgr.SeafDirent, user string, replace bool, names *[]string) (string, error) {
	if parentDir[0] == '/' {
		parentDir = parentDir[1:]
	}

	id, err := postMultiFilesRecursive(repo, rootID, parentDir, user, dents, replace, names)
	if err != nil {
		err := fmt.Errorf("failed to post multi files: %v", err)
		return "", err
	}

	return id, nil
}

func postMultiFilesRecursive(repo *repomgr.Repo, dirID, toPath, user string, dents []*fsmgr.SeafDirent, replace bool, names *[]string) (string, error) {
	olddir, err := fsmgr.GetSeafdir(repo.StoreID, dirID)
	if err != nil {
		err := fmt.Errorf("failed to get dir")
		return "", err
	}

	var ret string

	if toPath == "" {
		err := addNewEntries(repo, user, &olddir.Entries, dents, replace, names)
		if err != nil {
			err := fmt.Errorf("failed to add new entries: %v", err)
			return "", err
		}
		newdir, err := fsmgr.NewSeafdir(1, olddir.Entries)
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v", err)
			return "", err
		}
		err = fsmgr.SaveSeafdir(repo.StoreID, newdir)
		if err != nil {
			err := fmt.Errorf("failed to save seafdir %s/%s", repo.ID, newdir.DirID)
			return "", err
		}

		return newdir.DirID, nil
	}

	var remain string
	firstName := toPath
	if slash := strings.Index(toPath, "/"); slash >= 0 {
		remain = toPath[slash+1:]
		firstName = toPath[:slash]
	}

	entries := olddir.Entries
	for i, dent := range entries {
		if dent.Name != firstName {
			continue
		}

		id, err := postMultiFilesRecursive(repo, dent.ID, remain, user, dents, replace, names)
		if err != nil {
			err := fmt.Errorf("failed to post dirent %s: %v", dent.Name, err)
			return "", err
		}
		ret = id
		if id != "" {
			entries[i].ID = id
			entries[i].Mtime = time.Now().Unix()
		}
		break
	}

	if ret != "" {
		newdir, err := fsmgr.NewSeafdir(1, entries)
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v", err)
			return "", err
		}
		err = fsmgr.SaveSeafdir(repo.StoreID, newdir)
		if err != nil {
			err := fmt.Errorf("failed to save seafdir %s/%s", repo.ID, newdir.DirID)
			return "", err
		}
		ret = newdir.DirID
	}

	return ret, nil
}

func addNewEntries(repo *repomgr.Repo, user string, oldDents *[]*fsmgr.SeafDirent, newDents []*fsmgr.SeafDirent, replaceExisted bool, names *[]string) error {
	for _, dent := range newDents {
		var replace bool
		var uniqueName string
		if replaceExisted {
			for i, entry := range *oldDents {
				if entry.Name == dent.Name {
					replace = true
					*oldDents = append((*oldDents)[:i], (*oldDents)[i+1:]...)
					break
				}
			}
		}

		if replace {
			uniqueName = dent.Name
		} else {
			uniqueName = genUniqueName(dent.Name, *oldDents)
		}
		if uniqueName != "" {
			newDent := fsmgr.NewDirent(dent.ID, uniqueName, dent.Mode, dent.Mtime, user, dent.Size)
			*oldDents = append(*oldDents, newDent)
			*names = append(*names, uniqueName)
		} else {
			err := fmt.Errorf("failed to generate unique name for %s", dent.Name)
			return err
		}
	}

	sort.Sort(Dirents(*oldDents))

	return nil
}

func genUniqueName(fileName string, entries []*fsmgr.SeafDirent) string {
	var uniqueName string
	var name string
	i := 1
	dot := strings.Index(fileName, ".")
	if dot < 0 {
		name = fileName
	} else {
		name = fileName[:dot]
	}
	uniqueName = fileName
	for nameExists(entries, uniqueName) && i <= 100 {
		if dot < 0 {
			uniqueName = fmt.Sprintf("%s (%d)", name, i)
		} else {
			uniqueName = fmt.Sprintf("%s (%d).%s", name, i, fileName[dot+1:])
		}
		i++
	}

	if i <= 100 {
		return uniqueName
	}

	return ""
}

func nameExists(entries []*fsmgr.SeafDirent, fileName string) bool {
	for _, entry := range entries {
		if entry.Name == fileName {
			return true
		}
	}

	return false
}

func shouldIgnoreFile(fileName string) bool {
	if !utf8.ValidString(fileName) {
		log.Printf("file name %s contains non-UTF8 characters, skip.\n", fileName)
		return true
	}

	if len(fileName) >= 256 {
		return true
	}

	if strings.Index(fileName, "/") != -1 {
		return true
	}

	return false
}

func indexBlocks(repoID string, version int, filePath string, handler *multipart.FileHeader, cryptKey *seafileCrypt) (string, int64, error) {
	var size int64
	if handler != nil {
		size = handler.Size
	} else {
		f, err := os.Open(filePath)
		if err != nil {
			err := fmt.Errorf("failed to open file: %s: %v", filePath, err)
			return "", -1, err
		}
		defer f.Close()
		fileInfo, err := f.Stat()
		if err != nil {
			err := fmt.Errorf("failed to stat file %s: %v", filePath, err)
			return "", -1, err
		}
		size = fileInfo.Size()
	}

	chunkJobs := make(chan chunkingData, 10)
	results := make(chan chunkingResult, 10)
	go createChunkPool(int(options.maxIndexingThreads), chunkJobs, results)

	var blkSize int64
	var offset int64

	jobNum := uint64(size)/options.fixedBlockSize + 1
	blkIDs := make([]string, jobNum)

	left := size
	for {
		if uint64(left) >= options.fixedBlockSize {
			blkSize = int64(options.fixedBlockSize)
		} else {
			blkSize = left
		}
		if left > 0 {
			job := chunkingData{repoID, filePath, handler, offset, cryptKey}
			select {
			case chunkJobs <- job:
				left -= blkSize
				offset += blkSize
			case result := <-results:
				if result.err != nil {
					close(chunkJobs)
					go func() {
						for result := range results {
							_ = result
						}
					}()
					return "", -1, result.err
				}
				blkIDs[result.idx] = result.blkID
			}
		} else {
			close(chunkJobs)
			for result := range results {
				if result.err != nil {
					go func() {
						for result := range results {
							_ = result
						}
					}()
					return "", -1, result.err
				}
				blkIDs[result.idx] = result.blkID
			}
			break
		}
	}

	fileID, err := writeSeafile(repoID, version, size, blkIDs)
	if err != nil {
		err := fmt.Errorf("failed to write seafile: %v", err)
		return "", -1, err
	}

	return fileID, size, nil
}

func writeSeafile(repoID string, version int, fileSize int64, blkIDs []string) (string, error) {
	seafile, err := fsmgr.NewSeafile(version, fileSize, blkIDs)
	if err != nil {
		err := fmt.Errorf("failed to new seafile: %v", err)
		return "", err
	}

	err = fsmgr.SaveSeafile(repoID, seafile)
	if err != nil {
		err := fmt.Errorf("failed to save seafile %s/%s", repoID, seafile.FileID)
		return "", err
	}

	return seafile.FileID, nil
}

type chunkingData struct {
	repoID   string
	filePath string
	handler  *multipart.FileHeader
	offset   int64
	cryptKey *seafileCrypt
}

type chunkingResult struct {
	idx   int64
	blkID string
	err   error
}

func createChunkPool(n int, chunkJobs chan chunkingData, res chan chunkingResult) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go chunkingWorker(&wg, chunkJobs, res)
	}
	wg.Wait()
	close(res)
}

func chunkingWorker(wg *sync.WaitGroup, chunkJobs chan chunkingData, res chan chunkingResult) {
	for job := range chunkJobs {
		job := job
		blkID, err := chunkFile(job)
		idx := job.offset / int64(options.fixedBlockSize)
		result := chunkingResult{idx, blkID, err}
		res <- result
	}
	wg.Done()
}

func chunkFile(job chunkingData) (string, error) {
	repoID := job.repoID
	offset := job.offset
	filePath := job.filePath
	handler := job.handler
	blkSize := options.fixedBlockSize
	cryptKey := job.cryptKey
	var file multipart.File
	if handler != nil {
		f, err := handler.Open()
		if err != nil {
			err := fmt.Errorf("failed to open file for read: %v", err)
			return "", err
		}
		defer f.Close()
		file = f
	} else {
		f, err := os.Open(filePath)
		if err != nil {
			err := fmt.Errorf("failed to open file for read: %v", err)
			return "", err
		}
		defer f.Close()
		file = f
	}
	_, err := file.Seek(offset, os.SEEK_SET)
	if err != nil {
		err := fmt.Errorf("failed to seek file: %v", err)
		return "", err
	}
	buf := make([]byte, blkSize)
	n, err := file.Read(buf)
	if err != nil {
		err := fmt.Errorf("failed to seek file: %v", err)
		return "", err
	}
	buf = buf[:n]

	blkID, err := writeChunk(repoID, buf, int64(n), cryptKey)
	if err != nil {
		err := fmt.Errorf("failed to write chunk: %v", err)
		return "", err
	}

	return blkID, nil
}

func writeChunk(repoID string, input []byte, blkSize int64, cryptKey *seafileCrypt) (string, error) {
	var blkID string
	if cryptKey != nil && blkSize > 0 {
		encKey := cryptKey.key
		encIv := cryptKey.iv
		encoded, err := encrypt(input, encKey, encIv)
		if err != nil {
			err := fmt.Errorf("failed to encrypt block: %v", err)
			return "", err
		}
		checkSum := sha1.Sum(encoded)
		blkID = hex.EncodeToString(checkSum[:])
		reader := bytes.NewReader(encoded)
		err = blockmgr.Write(repoID, blkID, reader)
		if err != nil {
			err := fmt.Errorf("failed to write block: %v", err)
			return "", err
		}
	} else {
		checkSum := sha1.Sum(input)
		blkID = hex.EncodeToString(checkSum[:])
		reader := bytes.NewReader(input)
		err := blockmgr.Write(repoID, blkID, reader)
		if err != nil {
			err := fmt.Errorf("failed to write block: %v", err)
			return "", err
		}
	}

	return blkID, nil
}

func checkTmpFileList(fsm *recvData) *appError {
	var totalSize int64
	if fsm.rstart >= 0 {
		for _, tmpFile := range fsm.files {
			fileInfo, err := os.Stat(tmpFile)
			if err != nil {
				msg := "Internal error.\n"
				err := fmt.Errorf("[upload] Failed to stat temp file %s", tmpFile)
				return &appError{err, msg, http.StatusInternalServerError}
			}
			totalSize += fileInfo.Size()
		}
	} else {
		for _, handler := range fsm.fileHeaders {
			totalSize += handler.Size
		}
	}

	if options.maxUploadSize > 0 && uint64(totalSize) > options.maxUploadSize {
		msg := "File size is too large.\n"
		return &appError{nil, msg, 442}
	}

	return nil
}

func checkParentDir(repoID string, parentDir string) *appError {
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo.\n"
		err := fmt.Errorf("Failed to get repo %s", repoID)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	commit, err := commitmgr.Load(repoID, repo.HeadCommitID)
	if err != nil {
		msg := "Failed to get head commit.\n"
		err := fmt.Errorf("Failed to get head commit for repo %s", repoID)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	canonPath := getCanonPath(parentDir)

	_, err = fsmgr.GetSeafdirByPath(repo.StoreID, commit.RootID, canonPath)
	if err != nil {
		msg := "Parent dir doesn't exist.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	return nil
}

func isParentMatched(uploadDir, parentDir string) bool {
	uploadCanon := filepath.Join("/", uploadDir)
	parentCanon := filepath.Join("/", parentDir)
	if uploadCanon != parentCanon {
		return false
	}

	return true
}

func parseContentRange(ranges string, fsm *recvData) bool {
	start := strings.Index(ranges, "bytes")
	end := strings.Index(ranges, "-")
	slash := strings.Index(ranges, "/")

	if start < 0 || end < 0 || slash < 0 {
		return false
	}

	startStr := strings.TrimLeft(ranges[start+len("bytes"):end], " ")
	firstByte, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil {
		return false
	}

	lastByte, err := strconv.ParseInt(ranges[end+1:slash], 10, 64)
	if err != nil {
		return false
	}

	fileSize, err := strconv.ParseInt(ranges[slash+1:], 10, 64)
	if err != nil {
		return false
	}

	if firstByte > lastByte || lastByte >= fileSize {
		return false
	}

	fsm.rstart = firstByte
	fsm.rend = lastByte
	fsm.fsize = fileSize

	return true
}

type webaccessInfo struct {
	repoID string
	objID  string
	op     string
	user   string
}

func parseWebaccessInfo(token string) (*webaccessInfo, *appError) {
	webaccess, err := rpcclient.Call("seafile_web_query_access_token", token)
	if err != nil {
		err := fmt.Errorf("failed to get web access token: %v", err)
		return nil, &appError{err, "", http.StatusInternalServerError}
	}
	if webaccess == nil {
		msg := "Bad access token"
		return nil, &appError{err, msg, http.StatusBadRequest}
	}

	webaccessMap, ok := webaccess.(map[string]interface{})
	if !ok {
		return nil, &appError{nil, "", http.StatusInternalServerError}
	}

	accessInfo := new(webaccessInfo)
	repoID, ok := webaccessMap["repo-id"].(string)
	if !ok {
		return nil, &appError{nil, "", http.StatusInternalServerError}
	}
	accessInfo.repoID = repoID

	id, ok := webaccessMap["obj-id"].(string)
	if !ok {
		return nil, &appError{nil, "", http.StatusInternalServerError}
	}
	accessInfo.objID = id

	op, ok := webaccessMap["op"].(string)
	if !ok {
		return nil, &appError{nil, "", http.StatusInternalServerError}
	}
	accessInfo.op = op

	user, ok := webaccessMap["username"].(string)
	if !ok {
		return nil, &appError{nil, "", http.StatusInternalServerError}
	}
	accessInfo.user = user

	return accessInfo, nil
}
