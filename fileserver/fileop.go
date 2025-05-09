package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"database/sql"
	"math/rand"
	"sort"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/diff"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/option"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/unicode/norm"
)

const (
	cacheBlockMapThreshold          = 1 << 23
	blockMapCacheExpiretime   int64 = 3600 * 24
	fileopCleaningIntervalSec       = 3600
	duplicateNamesCount             = 1000
)

var blockMapCacheTable sync.Map

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

func fileopInit() {
	ticker := time.NewTicker(time.Second * fileopCleaningIntervalSec)
	go RecoverWrapper(func() {
		for range ticker.C {
			removeFileopExpireCache()
		}
	})
}

func initUpload() {
	objDir := filepath.Join(dataDir, "httptemp", "cluster-shared")
	os.MkdirAll(objDir, os.ModePerm)
}

// contentType = "application/octet-stream"
func parseContentType(fileName string) string {
	var contentType string

	parts := strings.Split(fileName, ".")
	if len(parts) >= 2 {
		suffix := parts[len(parts)-1]
		suffix = strings.ToLower(suffix)
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
		case "ogv":
			contentType = "video/ogg"
		case "mov":
			contentType = "video/mp4"
		case "webm":
			contentType = "video/webm"
		case "jpeg", "JPEG", "jpg", "JPG":
			contentType = "image/jpeg"
		case "png", "PNG":
			contentType = "image/png"
		case "gif", "GIF":
			contentType = "image/gif"
		case "svg", "SVG":
			contentType = "image/svg+xml"
		case "heic":
			contentType = "image/heic"
		case "ico":
			contentType = "image/x-icon"
		case "bmp":
			contentType = "image/bmp"
		case "tif", "tiff":
			contentType = "image/tiff"
		case "psd":
			contentType = "image/vnd.adobe.photoshop"
		case "webp":
			contentType = "image/webp"
		case "jfif":
			contentType = "image/jpeg"
		}
	}

	return contentType
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
		msg := "Operation does not match access token."
		return &appError{nil, msg, http.StatusForbidden}
	}

	if _, ok := r.Header["If-Modified-Since"]; ok {
		return &appError{nil, "", http.StatusNotModified}
	}

	now := time.Now()
	rsp.Header().Set("ETag", objID)
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
		key, err := parseCryptKey(rsp, repoID, user, repo.EncVersion)
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

func parseCryptKey(rsp http.ResponseWriter, repoID string, user string, version int) (*seafileCrypt, *appError) {
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
	seafileKey.version = version

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

func accessV2CB(rsp http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	repoID := vars["repoid"]
	filePath := vars["filepath"]

	if filePath == "" {
		msg := "No file path\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	rpath := getCanonPath(filePath)
	fileName := filepath.Base(rpath)

	op := r.URL.Query().Get("op")
	if op != "view" && op != "download" {
		msg := "Operation is neither view or download\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	token := utils.GetAuthorizationToken(r.Header)
	cookie := r.Header.Get("Cookie")

	if token == "" && cookie == "" {
		msg := "Both token and cookie are not set\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	ipAddr := getClientIPAddr(r)
	userAgent := r.Header.Get("User-Agent")
	user, appErr := checkFileAccess(repoID, token, cookie, filePath, "download", ipAddr, userAgent)
	if appErr != nil {
		return appErr
	}

	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Bad repo id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	fileID, _, err := fsmgr.GetObjIDByPath(repo.StoreID, repo.RootID, rpath)
	if err != nil {
		msg := "Invalid file_path\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	etag := r.Header.Get("If-None-Match")
	if etag == fileID {
		return &appError{nil, "", http.StatusNotModified}
	}

	rsp.Header().Set("ETag", fileID)
	rsp.Header().Set("Cache-Control", "private, no-cache")

	ranges := r.Header["Range"]
	byteRanges := strings.Join(ranges, "")

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user, repo.EncVersion)
		if err != nil {
			return err
		}
		cryptKey = key
	}

	exists, _ := fsmgr.Exists(repo.StoreID, fileID)
	if !exists {
		msg := "Invalid file id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if !repo.IsEncrypted && len(byteRanges) != 0 {
		if err := doFileRange(rsp, r, repo, fileID, fileName, op, byteRanges, user); err != nil {
			return err
		}
	} else if err := doFile(rsp, r, repo, fileID, fileName, op, cryptKey, user); err != nil {
		return err
	}

	return nil
}

type UserInfo struct {
	User string `json:"user"`
}

func checkFileAccess(repoID, token, cookie, filePath, op, ipAddr, userAgent string) (string, *appError) {
	tokenString, err := utils.GenSeahubJWTToken()
	if err != nil {
		err := fmt.Errorf("failed to sign jwt token: %v", err)
		return "", &appError{err, "", http.StatusInternalServerError}
	}
	url := fmt.Sprintf("%s/repos/%s/check-access/", option.SeahubURL, repoID)
	header := map[string][]string{
		"Authorization": {"Token " + tokenString},
	}
	if cookie != "" {
		header["Cookie"] = []string{cookie}
	}
	req := make(map[string]string)
	req["op"] = op
	req["path"] = filePath
	if token != "" {
		req["token"] = token
	}
	if ipAddr != "" {
		req["ip_addr"] = ipAddr
	}
	if userAgent != "" {
		req["user_agent"] = userAgent
	}
	msg, err := json.Marshal(req)
	if err != nil {
		err := fmt.Errorf("failed to encode access token: %v", err)
		return "", &appError{err, "", http.StatusInternalServerError}
	}
	status, body, err := utils.HttpCommon("POST", url, header, bytes.NewReader(msg))
	if err != nil {
		if status != http.StatusInternalServerError {
			return "", &appError{nil, string(body), status}
		} else {
			err := fmt.Errorf("failed to get access token info: %v", err)
			return "", &appError{err, "", http.StatusInternalServerError}
		}
	}

	info := new(UserInfo)
	err = json.Unmarshal(body, &info)
	if err != nil {
		err := fmt.Errorf("failed to decode access token info: %v", err)
		return "", &appError{err, "", http.StatusInternalServerError}
	}

	return info.User, nil
}

func doFile(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, cryptKey *seafileCrypt, user string) *appError {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		msg := "Failed to get seafile"
		return &appError{nil, msg, http.StatusBadRequest}
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
			decoded, err := cryptKey.decrypt(buf.Bytes())
			if err != nil {
				err := fmt.Errorf("failed to decrypt block %s: %v", blkID, err)
				return &appError{err, "", http.StatusInternalServerError}
			}
			_, err = rsp.Write(decoded)
			if err != nil {
				return nil
			}
		}
		return nil
	}

	for _, blkID := range file.BlkIDs {
		err := blockmgr.Read(repo.StoreID, blkID, rsp)
		if err != nil {
			if !isNetworkErr(err) {
				log.Errorf("failed to read block %s: %v", blkID, err)
			}
			return nil
		}
	}

	oper := "web-file-download"
	if operation == "download-link" {
		oper = "link-file-download"
	}
	sendStatisticMsg(repo.StoreID, user, oper, file.FileSize)

	return nil
}

func isNetworkErr(err error) bool {
	_, ok := err.(net.Error)
	return ok
}

type blockMap struct {
	blkSize    []uint64
	expireTime int64
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

	rsp.WriteHeader(http.StatusPartialContent)

	var blkSize []uint64
	if file.FileSize > cacheBlockMapThreshold {
		if v, ok := blockMapCacheTable.Load(file.FileID); ok {
			if blkMap, ok := v.(*blockMap); ok {
				blkSize = blkMap.blkSize
			}
		}
		if len(blkSize) == 0 {
			for _, v := range file.BlkIDs {
				size, err := blockmgr.Stat(repo.StoreID, v)
				if err != nil {
					err := fmt.Errorf("failed to stat block %s : %v", v, err)
					return &appError{err, "", http.StatusInternalServerError}
				}
				blkSize = append(blkSize, uint64(size))
			}
			blockMapCacheTable.Store(file.FileID, &blockMap{blkSize, time.Now().Unix() + blockMapCacheExpiretime})
		}
	} else {
		for _, v := range file.BlkIDs {
			size, err := blockmgr.Stat(repo.StoreID, v)
			if err != nil {
				err := fmt.Errorf("failed to stat block %s : %v", v, err)
				return &appError{err, "", http.StatusInternalServerError}
			}
			blkSize = append(blkSize, uint64(size))
		}
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
				if !isNetworkErr(err) {
					log.Errorf("failed to read block %s: %v", blkID, err)
				}
				return nil
			}
			recvBuf := buf.Bytes()
			rsp.Write(recvBuf[pos : pos+end-start+1])
			return nil
		}

		err := blockmgr.Read(repo.StoreID, blkID, &buf)
		if err != nil {
			if !isNetworkErr(err) {
				log.Errorf("failed to read block %s: %v", blkID, err)
			}
			return nil
		}
		recvBuf := buf.Bytes()
		_, err = rsp.Write(recvBuf[pos:])
		if err != nil {
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
				if !isNetworkErr(err) {
					log.Errorf("failed to read block %s: %v", blkID, err)
				}
				return nil
			}
			recvBuf := buf.Bytes()
			_, err = rsp.Write(recvBuf[:end-start+1])
			if err != nil {
				return nil
			}
			break
		} else {
			err := blockmgr.Read(repo.StoreID, blkID, rsp)
			if err != nil {
				if !isNetworkErr(err) {
					log.Errorf("failed to read block %s: %v", blkID, err)
				}
				return nil
			}
			start += blkSize[i]
		}
	}

	oper := "web-file-download"
	if operation == "download-link" {
		oper = "link-file-download"
	}
	sendStatisticMsg(repo.StoreID, user, oper, end-start+1)

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
		if strings.Contains(fileType, "text") {
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
		// Since the file name downloaded by safari will be garbled, we need to encode the filename.
		// Safari cannot parse unencoded utf8 characters.
		contFileName = fmt.Sprintf("attachment;filename*=utf-8''%s;filename=\"%s\"", url.PathEscape(fileName), fileName)
	} else {
		contFileName = fmt.Sprintf("inline;filename*=utf-8''%s;filename=\"%s\"", url.PathEscape(fileName), fileName)
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
		msg := "Operation does not match access token"
		return &appError{nil, msg, http.StatusForbidden}
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
		if !isNetworkErr(err) {
			log.Errorf("failed to read block %s: %v", blkID, err)
		}
	}

	sendStatisticMsg(repo.StoreID, user, "web-file-download", uint64(size))

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
		msg := "Operation does not match access token"
		return &appError{nil, msg, http.StatusForbidden}
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

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user, repo.EncVersion)
		if err != nil {
			return err
		}
		cryptKey = key
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

		zipName := dirName + ".zip"
		setCommonHeaders(rsp, r, "download", zipName)

		// The zip name downloaded by safari will be garbled if we encode the zip name,
		// because we download zip file using chunk encoding.
		contFileName := fmt.Sprintf("attachment;filename=\"%s\";filename*=utf-8''%s", zipName, url.PathEscape(zipName))
		rsp.Header().Set("Content-Disposition", contFileName)
		rsp.Header().Set("Content-Type", "application/octet-stream")

		err := packDir(ar, repo, objID, dirName, cryptKey)
		if err != nil {
			log.Errorf("failed to pack dir %s: %v", dirName, err)
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
		contFileName := fmt.Sprintf("attachment;filename=\"%s\";filename*=utf8''%s", zipName, url.PathEscape(zipName))
		rsp.Header().Set("Content-Disposition", contFileName)
		rsp.Header().Set("Content-Type", "application/octet-stream")

		fileList := []string{}
		for _, v := range dirList {
			uniqueName := genUniqueFileName(v.Name, fileList)
			fileList = append(fileList, uniqueName)
			if fsmgr.IsDir(v.Mode) {
				if err := packDir(ar, repo, v.ID, uniqueName, cryptKey); err != nil {
					if !isNetworkErr(err) {
						log.Errorf("failed to pack dir %s: %v", v.Name, err)
					}
					return nil
				}
			} else {
				if err := packFiles(ar, &v, repo, "", uniqueName, cryptKey); err != nil {
					if !isNetworkErr(err) {
						log.Errorf("failed to pack file %s: %v", v.Name, err)
					}
					return nil
				}
			}
		}
	}

	return nil
}

func genUniqueFileName(fileName string, fileList []string) string {
	var uniqueName string
	var name string
	i := 1
	dot := strings.LastIndex(fileName, ".")
	if dot < 0 {
		name = fileName
	} else {
		name = fileName[:dot]
	}
	uniqueName = fileName

	for nameInFileList(uniqueName, fileList) {
		if dot < 0 {
			uniqueName = fmt.Sprintf("%s (%d)", name, i)
		} else {
			uniqueName = fmt.Sprintf("%s (%d).%s", name, i, fileName[dot+1:])
		}
		i++
	}

	return uniqueName
}

func nameInFileList(fileName string, fileList []string) bool {
	for _, name := range fileList {
		if name == fileName {
			return true
		}
	}
	return false
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
		if name == "" {
			err := fmt.Errorf("invalid download file name")
			return nil, err
		}

		if strings.Contains(name, "/") {
			rpath := filepath.Join(parentDir, name)
			dent, err := fsmgr.GetDirentByPath(repo.StoreID, repo.RootID, rpath)
			if err != nil {
				err := fmt.Errorf("failed to get path %s for repo %s: %v", rpath, repo.StoreID, err)
				return nil, err
			}
			direntList = append(direntList, *dent)
		} else {
			v, ok := direntHash[name]
			if !ok {
				err := fmt.Errorf("invalid download multi data")
				return nil, err
			}

			direntList = append(direntList, v)
		}
	}

	return direntList, nil
}

func packDir(ar *zip.Writer, repo *repomgr.Repo, dirID, dirPath string, cryptKey *seafileCrypt) error {
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
			if err := packDir(ar, repo, v.ID, fileDir, cryptKey); err != nil {
				return err
			}
		} else {
			if err := packFiles(ar, v, repo, dirPath, v.Name, cryptKey); err != nil {
				return err
			}
		}
	}

	return nil
}

func packFiles(ar *zip.Writer, dirent *fsmgr.SeafDirent, repo *repomgr.Repo, parentPath, baseName string, cryptKey *seafileCrypt) error {
	file, err := fsmgr.GetSeafile(repo.StoreID, dirent.ID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v", err)
		return err
	}

	filePath := filepath.Join(parentPath, baseName)
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

	if cryptKey != nil {
		for _, blkID := range file.BlkIDs {
			var buf bytes.Buffer
			blockmgr.Read(repo.StoreID, blkID, &buf)
			decoded, err := cryptKey.decrypt(buf.Bytes())
			if err != nil {
				err := fmt.Errorf("failed to decrypt block %s: %v", blkID, err)
				return err
			}
			_, err = zipFile.Write(decoded)
			if err != nil {
				return err
			}
		}
		return nil
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
	if r.Method == "OPTIONS" {
		setAccessControl(rsp)
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

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

func setAccessControl(rsp http.ResponseWriter) {
	rsp.Header().Set("Access-Control-Allow-Origin", "*")
	rsp.Header().Set("Access-Control-Allow-Headers", "x-requested-with, content-type, content-range, content-disposition, accept, origin, authorization")
	rsp.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	rsp.Header().Set("Access-Control-Max-Age", "86400")
}

func uploadAjaxCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == "OPTIONS" {
		setAccessControl(rsp)
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

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
		err.Message = fmt.Sprintf("{\"error\": \"%s\"}", err.Message)
	}
}

func normalizeUTF8Path(p string) string {
	newPath := norm.NFC.Bytes([]byte(p))
	return string(newPath)
}

func doUpload(rsp http.ResponseWriter, r *http.Request, fsm *recvData, isAjax bool) *appError {
	setAccessControl(rsp)

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
			msg := "Invalid argument replace.\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		if replace == 1 {
			replaceExisted = true
		}
	}

	parentDir := normalizeUTF8Path(r.FormValue("parent_dir"))
	if parentDir == "" {
		msg := "No parent_dir given.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	lastModifyStr := normalizeUTF8Path(r.FormValue("last_modify"))
	var lastModify int64
	if lastModifyStr != "" {
		t, err := time.Parse(time.RFC3339, lastModifyStr)
		if err == nil {
			lastModify = t.Unix()
		}
	}

	relativePath := normalizeUTF8Path(r.FormValue("relative_path"))
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
			rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
			success := "{\"success\": true}"
			rsp.Write([]byte(success))

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
			fsm.fileNames = append(fsm.fileNames, normalizeUTF8Path(fileName))
			fsm.fileHeaders = append(fsm.fileHeaders, handler)
		}
	}

	if fsm.fileNames == nil {
		msg := "No file uploaded.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if err := checkParentDir(repoID, parentDir); err != nil {
		return err
	}

	if !isParentMatched(fsm.parentDir, parentDir) {
		msg := "Parent dir doesn't match."
		return &appError{nil, msg, http.StatusForbidden}
	}

	if err := checkTmpFileList(fsm); err != nil {
		return err
	}

	var contentLen int64
	if fsm.fsize > 0 {
		contentLen = fsm.fsize
	} else {
		lenstr := r.Header.Get("Content-Length")
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
		return &appError{nil, msg, seafHTTPResNoQuota}
	}

	if err := createRelativePath(repoID, parentDir, relativePath, user); err != nil {
		return err
	}

	if err := postMultiFiles(rsp, r, repoID, newParentDir, user, fsm,
		replaceExisted, lastModify, isAjax); err != nil {
		return err
	}

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
		f, err = os.CreateTemp(tmpDir, filename)
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
		fsm.fileNames = append(fsm.fileNames, normalizeUTF8Path(fileName))
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
	_, err = genNewCommit(repo, headCommit, rootID, user, buf, true, "", false)
	if err != nil {
		err := fmt.Errorf("failed to generate new commit: %v", err)
		return err
	}

	go mergeVirtualRepoPool.AddTask(repo.ID, "")

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
}

func parseUploadHeaders(r *http.Request) (*recvData, *appError) {
	tokenLen := 36
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 2 {
		msg := "Invalid URL"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}
	urlOp := parts[0]
	if len(parts[1]) < tokenLen {
		msg := "Invalid URL"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}
	token := parts[1][:tokenLen]

	accessInfo, appErr := parseWebaccessInfo(token)
	if appErr != nil {
		return nil, appErr
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	id := accessInfo.objID

	status, err := repomgr.GetRepoStatus(repoID)
	if err != nil {
		return nil, &appError{err, "", http.StatusInternalServerError}
	}
	if status != repomgr.RepoStatusNormal && status != -1 {
		msg := "Repo status not writable."
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}

	if op == "upload-link" {
		op = "upload"
	}
	if strings.Index(urlOp, op) != 0 {
		msg := "Operation does not match access token."
		return nil, &appError{nil, msg, http.StatusForbidden}
	}

	fsm := new(recvData)

	if op != "update" {
		obj := make(map[string]interface{})
		if err := json.Unmarshal([]byte(id), &obj); err != nil {
			err := fmt.Errorf("failed to decode obj data : %v", err)
			return nil, &appError{err, "", http.StatusInternalServerError}
		}

		parentDir, ok := obj["parent_dir"].(string)
		if !ok || parentDir == "" {
			err := fmt.Errorf("no parent_dir in access token")
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
		fsm.parentDir = parentDir
	}

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

func postMultiFiles(rsp http.ResponseWriter, r *http.Request, repoID, parentDir, user string, fsm *recvData, replace bool, lastModify int64, isAjax bool) *appError {

	fileNames := fsm.fileNames
	files := fsm.files
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo.\n"
		err := fmt.Errorf("Failed to get repo %s", repoID)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	canonPath := getCanonPath(parentDir)

	if !replace && checkFilesWithSameName(repo, canonPath, fileNames) {
		msg := "Too many files with same name.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	for _, fileName := range fileNames {
		if shouldIgnoreFile(fileName) {
			msg := fmt.Sprintf("invalid fileName: %s.\n", fileName)
			return &appError{nil, msg, http.StatusBadRequest}
		}
	}
	if strings.Contains(parentDir, "//") {
		msg := "parent_dir contains // sequence.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user, repo.EncVersion)
		if err != nil {
			return err
		}
		cryptKey = key
	}

	gcID, err := repomgr.GetCurrentGCID(repo.StoreID)
	if err != nil {
		err := fmt.Errorf("failed to get current gc id for repo %s: %v", repoID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	var ids []string
	var sizes []int64
	if fsm.rstart >= 0 {
		for _, filePath := range files {
			id, size, err := indexBlocks(r.Context(), repo.StoreID, repo.Version, filePath, nil, cryptKey)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					err := fmt.Errorf("failed to index blocks: %v", err)
					return &appError{err, "", http.StatusInternalServerError}
				}
				return &appError{nil, "", http.StatusInternalServerError}
			}
			ids = append(ids, id)
			sizes = append(sizes, size)
		}
	} else {
		for _, handler := range fsm.fileHeaders {
			id, size, err := indexBlocks(r.Context(), repo.StoreID, repo.Version, "", handler, cryptKey)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					err := fmt.Errorf("failed to index blocks: %v", err)
					return &appError{err, "", http.StatusInternalServerError}
				}
				return &appError{nil, "", http.StatusInternalServerError}
			}
			ids = append(ids, id)
			sizes = append(sizes, size)
		}
	}

	retStr, err := postFilesAndGenCommit(fileNames, repo.ID, user, canonPath, replace, ids, sizes, lastModify, gcID)
	if err != nil {
		if errors.Is(err, ErrGCConflict) {
			return &appError{nil, "GC Conflict.\n", http.StatusConflict}
		} else {
			err := fmt.Errorf("failed to post files and gen commit: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
	}

	_, ok := r.Form["ret-json"]
	if ok || isAjax {
		rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
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

func checkFilesWithSameName(repo *repomgr.Repo, canonPath string, fileNames []string) bool {
	commit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		return false
	}
	dir, err := fsmgr.GetSeafdirByPath(repo.StoreID, commit.RootID, canonPath)
	if err != nil {
		return false
	}

	for _, name := range fileNames {
		uniqueName := genUniqueName(name, dir.Entries)
		if uniqueName == "" {
			return true
		}
	}

	return false
}

func postFilesAndGenCommit(fileNames []string, repoID string, user, canonPath string, replace bool, ids []string, sizes []int64, lastModify int64, lastGCID string) (string, error) {
	handleConncurrentUpdate := true
	if !replace {
		handleConncurrentUpdate = false
	}
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %s", repoID)
		return "", err
	}
	headCommit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
		return "", err
	}
	var names []string
	var retryCnt int

	var dents []*fsmgr.SeafDirent
	for i, name := range fileNames {
		if i > len(ids)-1 || i > len(sizes)-1 {
			break
		}
		mode := (syscall.S_IFREG | 0644)
		mtime := lastModify
		if mtime <= 0 {
			mtime = time.Now().Unix()
		}
		dent := fsmgr.NewDirent(ids[i], name, uint32(mode), mtime, "", sizes[i])
		dents = append(dents, dent)
	}

retry:
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

	_, err = genNewCommit(repo, headCommit, rootID, user, buf, handleConncurrentUpdate, lastGCID, true)
	if err != nil {
		if err != ErrConflict {
			err := fmt.Errorf("failed to generate new commit: %w", err)
			return "", err
		}
		retryCnt++
		/* Sleep random time between 0 and 3 seconds. */
		random := rand.Intn(30) + 1
		log.Debugf("concurrent upload retry :%d", retryCnt)
		time.Sleep(time.Duration(random*100) * time.Millisecond)
		repo = repomgr.Get(repoID)
		if repo == nil {
			err := fmt.Errorf("failed to get repo %s", repoID)
			return "", err
		}
		headCommit, err = commitmgr.Load(repo.ID, repo.HeadCommitID)
		if err != nil {
			err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
			return "", err
		}
		goto retry
	}

	go mergeVirtualRepoPool.AddTask(repo.ID, "")

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

var (
	ErrConflict   = errors.New("Concurent upload conflict")
	ErrGCConflict = errors.New("GC Conflict")
)

func genNewCommit(repo *repomgr.Repo, base *commitmgr.Commit, newRoot, user, desc string, handleConncurrentUpdate bool, lastGCID string, checkGC bool) (string, error) {
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

	maxRetryCnt := 10

	for {
		retry, err := genCommitNeedRetry(repo, base, commit, newRoot, user, handleConncurrentUpdate, &commitID, lastGCID, checkGC)
		if err != nil {
			return "", err
		}
		if !retry {
			break
		}
		if !handleConncurrentUpdate {
			return "", ErrConflict
		}

		if retryCnt < maxRetryCnt {
			/* Sleep random time between 0 and 3 seconds. */
			random := rand.Intn(30) + 1
			time.Sleep(time.Duration(random*100) * time.Millisecond)
			repo = repomgr.Get(repoID)
			if repo == nil {
				err := fmt.Errorf("repo %s doesn't exist", repoID)
				return "", err
			}
			retryCnt++
		} else {
			err := fmt.Errorf("stop updating repo %s after %d retries", repoID, maxRetryCnt)
			return "", err
		}
	}

	return commitID, nil
}

func fastForwardOrMerge(user, token string, repo *repomgr.Repo, base, newCommit *commitmgr.Commit) error {
	var retryCnt int
	checkGC, err := repomgr.HasLastGCID(repo.ID, token)
	if err != nil {
		return err
	}
	var lastGCID string
	if checkGC {
		lastGCID, _ = repomgr.GetLastGCID(repo.ID, token)
		repomgr.RemoveLastGCID(repo.ID, token)
	}
	for {
		retry, err := genCommitNeedRetry(repo, base, newCommit, newCommit.RootID, user, true, nil, lastGCID, checkGC)
		if err != nil {
			return err
		}
		if !retry {
			break
		}

		if retryCnt < 3 {
			random := rand.Intn(10) + 1
			time.Sleep(time.Duration(random*100) * time.Millisecond)
			retryCnt++
		} else {
			err = fmt.Errorf("stop updating repo %s after 3 retries", repo.ID)
			return err
		}
	}
	return nil
}

func genCommitNeedRetry(repo *repomgr.Repo, base *commitmgr.Commit, commit *commitmgr.Commit, newRoot, user string, handleConncurrentUpdate bool, commitID *string, lastGCID string, checkGC bool) (bool, error) {
	var secondParentID string
	repoID := repo.ID
	var mergeDesc string
	var mergedCommit *commitmgr.Commit
	currentHead, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get head commit for repo %s", repoID)
		return false, err
	}

	if base.CommitID != currentHead.CommitID {
		if !handleConncurrentUpdate {
			return false, ErrConflict
		}
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
			mergeDesc = "Auto merge by system"
		} else {
			mergeDesc = genMergeDesc(repo, opt.mergedRoot, currentHead.RootID, newRoot)
			if mergeDesc == "" {
				mergeDesc = "Auto merge by system"
			}
		}

		secondParentID = commit.CommitID
		mergedCommit = commitmgr.NewCommit(repoID, currentHead.CommitID, opt.mergedRoot, user, mergeDesc)
		repomgr.RepoToCommit(repo, mergedCommit)
		mergedCommit.SecondParentID.SetValid(commit.CommitID)
		mergedCommit.NewMerge = 1
		if opt.conflict {
			mergedCommit.Conflict = 1
		}

		err = commitmgr.Save(mergedCommit)
		if err != nil {
			err := fmt.Errorf("failed to add commit: %v", err)
			return false, err
		}
	} else {
		mergedCommit = commit
	}

	gcConflict, err := updateBranch(repoID, repo.StoreID, mergedCommit.CommitID, currentHead.CommitID, secondParentID, checkGC, lastGCID)
	if gcConflict {
		return false, err
	}
	if err != nil {
		return true, nil
	}

	if commitID != nil {
		*commitID = mergedCommit.CommitID
	}
	return false, nil
}

func genMergeDesc(repo *repomgr.Repo, mergedRoot, p1Root, p2Root string) string {
	var results []*diff.DiffEntry
	err := diff.DiffMergeRoots(repo.StoreID, mergedRoot, p1Root, p2Root, &results, true)
	if err != nil {
		return ""
	}

	desc := diff.DiffResultsToDesc(results)

	return desc
}

func updateBranch(repoID, originRepoID, newCommitID, oldCommitID, secondParentID string, checkGC bool, lastGCID string) (gcConflict bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), option.DBOpTimeout)
	defer cancel()
	trans, err := seafileDB.BeginTx(ctx, nil)
	if err != nil {
		err := fmt.Errorf("failed to start transaction: %v", err)
		return false, err
	}

	var row *sql.Row
	var sqlStr string
	if checkGC {
		sqlStr = "SELECT gc_id FROM GCID WHERE repo_id = ? FOR UPDATE"
		if originRepoID == "" {
			row = trans.QueryRowContext(ctx, sqlStr, repoID)
		} else {
			row = trans.QueryRowContext(ctx, sqlStr, originRepoID)
		}
		var gcID sql.NullString
		if err := row.Scan(&gcID); err != nil {
			if err != sql.ErrNoRows {
				trans.Rollback()
				return false, err
			}
		}

		if lastGCID != gcID.String {
			err = fmt.Errorf("Head branch update for repo %s conflicts with GC.", repoID)
			trans.Rollback()
			return true, ErrGCConflict
		}
	}

	var commitID string
	name := "master"
	sqlStr = "SELECT commit_id FROM Branch WHERE name = ? AND repo_id = ? FOR UPDATE"

	row = trans.QueryRowContext(ctx, sqlStr, name, repoID)
	if err := row.Scan(&commitID); err != nil {
		if err != sql.ErrNoRows {
			trans.Rollback()
			return false, err
		}
	}
	if oldCommitID != commitID {
		trans.Rollback()
		err := fmt.Errorf("head commit id has changed")
		return false, err
	}

	sqlStr = "UPDATE Branch SET commit_id = ? WHERE name = ? AND repo_id = ?"
	_, err = trans.ExecContext(ctx, sqlStr, newCommitID, name, repoID)
	if err != nil {
		trans.Rollback()
		return false, err
	}

	trans.Commit()

	if secondParentID != "" {
		if err := onBranchUpdated(repoID, secondParentID, false); err != nil {
			return false, err
		}
	}

	if err := onBranchUpdated(repoID, newCommitID, true); err != nil {
		return false, err
	}

	return false, nil
}

func onBranchUpdated(repoID string, commitID string, updateRepoInfo bool) error {
	if updateRepoInfo {
		if err := repomgr.UpdateRepoInfo(repoID, commitID); err != nil {
			return err
		}
	}

	if option.EnableNotification {
		notifRepoUpdate(repoID, commitID)
	}

	isVirtual, err := repomgr.IsVirtualRepo(repoID)
	if err != nil {
		return err
	}
	if isVirtual {
		return nil
	}
	publishUpdateEvent(repoID, commitID)
	return nil
}

type notifEvent struct {
	Type    string           `json:"type"`
	Content *repoUpdateEvent `json:"content"`
}
type repoUpdateEvent struct {
	RepoID   string `json:"repo_id"`
	CommitID string `json:"commit_id"`
}

func notifRepoUpdate(repoID string, commitID string) error {
	content := new(repoUpdateEvent)
	content.RepoID = repoID
	content.CommitID = commitID
	event := new(notifEvent)
	event.Type = "repo-update"
	event.Content = content
	msg, err := json.Marshal(event)
	if err != nil {
		log.Errorf("failed to encode repo update event: %v", err)
		return err
	}

	url := fmt.Sprintf("http://%s/events", option.NotificationURL)
	exp := time.Now().Add(time.Second * 300).Unix()
	token, err := utils.GenNotifJWTToken(repoID, "", exp)
	if err != nil {
		log.Errorf("failed to generate jwt token: %v", err)
		return err
	}
	header := map[string][]string{
		"Authorization": {"Token " + token},
	}
	_, _, err = utils.HttpCommon("POST", url, header, bytes.NewReader(msg))
	if err != nil {
		log.Warnf("failed to send repo update event: %v", err)
		return err
	}

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
	} else {
		// The ret will be an empty string when failed to find parent dir, an error should be returned in such case.
		err := fmt.Errorf("failed to find parent dir for %s", toPath)
		return "", err
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
	dot := strings.LastIndex(fileName, ".")
	if dot < 0 {
		name = fileName
	} else {
		name = fileName[:dot]
	}
	uniqueName = fileName
	for nameExists(entries, uniqueName) && i <= duplicateNamesCount {
		if dot < 0 {
			uniqueName = fmt.Sprintf("%s (%d)", name, i)
		} else {
			uniqueName = fmt.Sprintf("%s (%d).%s", name, i, fileName[dot+1:])
		}
		i++
	}

	if i <= duplicateNamesCount {
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

func shouldIgnore(fileName string) bool {
	parts := strings.Split(fileName, "/")
	for _, name := range parts {
		if name == ".." {
			return true
		}
	}
	return false
}

func shouldIgnoreFile(fileName string) bool {
	if shouldIgnore(fileName) {
		return true
	}

	if !utf8.ValidString(fileName) {
		log.Warnf("file name %s contains non-UTF8 characters, skip", fileName)
		return true
	}

	if len(fileName) >= 256 {
		return true
	}

	if strings.Contains(fileName, "/") {
		return true
	}

	return false
}

func indexBlocks(ctx context.Context, repoID string, version int, filePath string, handler *multipart.FileHeader, cryptKey *seafileCrypt) (string, int64, error) {
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

	if size == 0 {
		return fsmgr.EmptySha1, 0, nil
	}

	chunkJobs := make(chan chunkingData, 10)
	results := make(chan chunkingResult, 10)
	go createChunkPool(ctx, int(option.MaxIndexingThreads), chunkJobs, results)

	var blkSize int64
	var offset int64

	jobNum := (uint64(size) + option.FixedBlockSize - 1) / option.FixedBlockSize
	blkIDs := make([]string, jobNum)

	left := size
	for {
		if uint64(left) >= option.FixedBlockSize {
			blkSize = int64(option.FixedBlockSize)
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

					go RecoverWrapper(func() {
						for result := range results {
							_ = result
						}
					})
					return "", -1, result.err
				}
				blkIDs[result.idx] = result.blkID
			}
		} else {
			close(chunkJobs)
			for result := range results {
				if result.err != nil {
					go RecoverWrapper(func() {
						for result := range results {
							_ = result
						}
					})
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

func createChunkPool(ctx context.Context, n int, chunkJobs chan chunkingData, res chan chunkingResult) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panic: %v\n%s", err, debug.Stack())
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go chunkingWorker(ctx, &wg, chunkJobs, res)
	}
	wg.Wait()
	close(res)
}

func chunkingWorker(ctx context.Context, wg *sync.WaitGroup, chunkJobs chan chunkingData, res chan chunkingResult) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panic: %v\n%s", err, debug.Stack())
		}
	}()
	for job := range chunkJobs {
		select {
		case <-ctx.Done():
			err := context.Canceled
			result := chunkingResult{-1, "", err}
			res <- result
			wg.Done()
			return
		default:
		}

		job := job
		blkID, err := chunkFile(job)
		idx := job.offset / int64(option.FixedBlockSize)
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
	blkSize := option.FixedBlockSize
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
	_, err := file.Seek(offset, io.SeekStart)
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
		encoded, err := cryptKey.encrypt(input)
		if err != nil {
			err := fmt.Errorf("failed to encrypt block: %v", err)
			return "", err
		}
		checkSum := sha1.Sum(encoded)
		blkID = hex.EncodeToString(checkSum[:])
		if blockmgr.Exists(repoID, blkID) {
			return blkID, nil
		}
		reader := bytes.NewReader(encoded)
		err = blockmgr.Write(repoID, blkID, reader)
		if err != nil {
			err := fmt.Errorf("failed to write block: %v", err)
			return "", err
		}
	} else {
		checkSum := sha1.Sum(input)
		blkID = hex.EncodeToString(checkSum[:])
		if blockmgr.Exists(repoID, blkID) {
			return blkID, nil
		}
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

	if option.MaxUploadSize > 0 && uint64(totalSize) > option.MaxUploadSize {
		msg := "File size is too large.\n"
		return &appError{nil, msg, seafHTTPResTooLarge}
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
	return uploadCanon == parentCanon
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
		msg := "Access token not found"
		return nil, &appError{err, msg, http.StatusForbidden}
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

func updateDir(repoID, dirPath, newDirID, user, headID string) (string, error) {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %.10s", repoID)
		return "", err
	}

	var base string
	if headID == "" {
		base = repo.HeadCommitID
	} else {
		base = headID
	}

	headCommit, err := commitmgr.Load(repo.ID, base)
	if err != nil {
		err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
		return "", err
	}

	if dirPath == "/" {
		commitDesc := genCommitDesc(repo, newDirID, headCommit.RootID)
		if commitDesc == "" {
			commitDesc = "Auto merge by system"
		}
		newCommitID, err := genNewCommit(repo, headCommit, newDirID, user, commitDesc, true, "", false)
		if err != nil {
			err := fmt.Errorf("failed to generate new commit: %v", err)
			return "", err
		}
		return newCommitID, nil
	}

	parent := filepath.Dir(dirPath)
	canonPath := getCanonPath(parent)
	dirName := filepath.Base(dirPath)

	dir, err := fsmgr.GetSeafdirByPath(repo.StoreID, headCommit.RootID, canonPath)
	if err != nil {
		err := fmt.Errorf("dir %s doesn't exist in repo %s", canonPath, repo.StoreID)
		return "", err
	}
	var exists bool
	for _, de := range dir.Entries {
		if de.Name == dirName {
			exists = true
		}
	}
	if !exists {
		err := fmt.Errorf("directory %s doesn't exist in repo %s", dirName, repo.StoreID)
		return "", err
	}

	newDent := fsmgr.NewDirent(newDirID, dirName, (syscall.S_IFDIR | 0644), time.Now().Unix(), "", 0)

	rootID, err := doPutFile(repo, headCommit.RootID, canonPath, newDent)
	if err != nil || rootID == "" {
		err := fmt.Errorf("failed to put file")
		return "", err
	}

	commitDesc := genCommitDesc(repo, rootID, headCommit.RootID)
	if commitDesc == "" {
		commitDesc = "Auto merge by system"
	}

	newCommitID, err := genNewCommit(repo, headCommit, rootID, user, commitDesc, true, "", false)
	if err != nil {
		err := fmt.Errorf("failed to generate new commit: %v", err)
		return "", err
	}

	go updateSizePool.AddTask(repoID)

	return newCommitID, nil
}

func genCommitDesc(repo *repomgr.Repo, root, parentRoot string) string {
	var results []*diff.DiffEntry
	err := diff.DiffCommitRoots(repo.StoreID, parentRoot, root, &results, true)
	if err != nil {
		return ""
	}

	desc := diff.DiffResultsToDesc(results)

	return desc
}

func doPutFile(repo *repomgr.Repo, rootID, parentDir string, dent *fsmgr.SeafDirent) (string, error) {
	if strings.Index(parentDir, "/") == 0 {
		parentDir = parentDir[1:]
	}

	return putFileRecursive(repo, rootID, parentDir, dent)
}

func putFileRecursive(repo *repomgr.Repo, dirID, toPath string, newDent *fsmgr.SeafDirent) (string, error) {
	olddir, err := fsmgr.GetSeafdir(repo.StoreID, dirID)
	if err != nil {
		err := fmt.Errorf("failed to get dir")
		return "", err
	}
	entries := olddir.Entries

	var ret string

	if toPath == "" {
		var newEntries []*fsmgr.SeafDirent
		for _, dent := range entries {
			if dent.Name == newDent.Name {
				newEntries = append(newEntries, newDent)
			} else {
				newEntries = append(newEntries, dent)
			}
		}

		newdir, err := fsmgr.NewSeafdir(1, newEntries)
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

	for _, dent := range entries {
		if dent.Name != firstName {
			continue
		}
		id, err := putFileRecursive(repo, dent.ID, remain, newDent)
		if err != nil {
			err := fmt.Errorf("failed to put dirent %s: %v", dent.Name, err)
			return "", err
		}
		if id != "" {
			dent.ID = id
			dent.Mtime = time.Now().Unix()
		}
		ret = id
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
	} else {
		err := fmt.Errorf("failed to find parent dir for %s", toPath)
		return "", err
	}

	return ret, nil
}

func updateAPICB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == "OPTIONS" {
		setAccessControl(rsp)
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	fsm, err := parseUploadHeaders(r)
	if err != nil {
		return err
	}

	if err := doUpdate(rsp, r, fsm, false); err != nil {
		formatJSONError(rsp, err)
		return err
	}

	return nil
}

func updateAjaxCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if r.Method == "OPTIONS" {
		setAccessControl(rsp)
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	fsm, err := parseUploadHeaders(r)
	if err != nil {
		return err
	}

	if err := doUpdate(rsp, r, fsm, true); err != nil {
		formatJSONError(rsp, err)
		return err
	}

	return nil
}

func doUpdate(rsp http.ResponseWriter, r *http.Request, fsm *recvData, isAjax bool) *appError {
	setAccessControl(rsp)

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return &appError{nil, "", http.StatusBadRequest}
	}
	defer r.MultipartForm.RemoveAll()

	repoID := fsm.repoID
	user := fsm.user

	targetFile := normalizeUTF8Path(r.FormValue("target_file"))
	if targetFile == "" {
		msg := "No target_file given.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	lastModifyStr := normalizeUTF8Path(r.FormValue("last_modify"))
	var lastModify int64
	if lastModifyStr != "" {
		t, err := time.Parse(time.RFC3339, lastModifyStr)
		if err == nil {
			lastModify = t.Unix()
		}
	}

	parentDir := filepath.Dir(targetFile)
	fileName := filepath.Base(targetFile)

	defer clearTmpFile(fsm, parentDir)

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

		err := writeBlockDataToTmpFile(r, fsm, formFiles, repoID, parentDir)
		if err != nil {
			msg := "Internal error.\n"
			err := fmt.Errorf("failed to write block data to tmp file: %v", err)
			return &appError{err, msg, http.StatusInternalServerError}
		}

		if fsm.rend != fsm.fsize-1 {
			rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
			success := "{\"success\": true}"
			rsp.Write([]byte(success))

			return nil
		}
	} else {
		formFiles := r.MultipartForm.File
		fileHeaders, ok := formFiles["file"]
		if !ok {
			msg := "No file in multipart form.\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		if len(fileHeaders) > 1 {
			msg := "More files in one request"
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

	if err := checkTmpFileList(fsm); err != nil {
		return err
	}

	var contentLen int64
	if fsm.fsize > 0 {
		contentLen = fsm.fsize
	} else {
		lenstr := r.Header.Get("Content-Length")
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
		return &appError{nil, msg, seafHTTPResNoQuota}
	}

	headIDs, ok := r.Form["head"]
	var headID string
	if ok {
		headID = headIDs[0]
	}

	if err := putFile(rsp, r, repoID, parentDir, user, fileName, fsm, headID, lastModify, isAjax); err != nil {
		return err
	}

	oper := "web-file-upload"
	sendStatisticMsg(repoID, user, oper, uint64(contentLen))

	return nil
}

func putFile(rsp http.ResponseWriter, r *http.Request, repoID, parentDir, user, fileName string, fsm *recvData, headID string, lastModify int64, isAjax bool) *appError {
	files := fsm.files
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo.\n"
		err := fmt.Errorf("Failed to get repo %s", repoID)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	var base string
	if headID != "" {
		base = headID
	} else {
		base = repo.HeadCommitID
	}

	headCommit, err := commitmgr.Load(repo.ID, base)
	if err != nil {
		msg := "Failed to get head commit.\n"
		err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	canonPath := getCanonPath(parentDir)

	if shouldIgnoreFile(fileName) {
		msg := fmt.Sprintf("invalid fileName: %s.\n", fileName)
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if strings.Contains(parentDir, "//") {
		msg := "parent_dir contains // sequence.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	exist, _ := checkFileExists(repo.StoreID, headCommit.RootID, canonPath, fileName)
	if !exist {
		msg := "File does not exist.\n"
		return &appError{nil, msg, seafHTTPResNotExists}
	}

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user, repo.EncVersion)
		if err != nil {
			return err
		}
		cryptKey = key
	}

	gcID, err := repomgr.GetCurrentGCID(repo.StoreID)
	if err != nil {
		err := fmt.Errorf("failed to get current gc id: %v", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	var fileID string
	var size int64
	if fsm.rstart >= 0 {
		filePath := files[0]
		id, fileSize, err := indexBlocks(r.Context(), repo.StoreID, repo.Version, filePath, nil, cryptKey)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				err := fmt.Errorf("failed to index blocks: %w", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
			return &appError{nil, "", http.StatusInternalServerError}
		}
		fileID = id
		size = fileSize
	} else {
		handler := fsm.fileHeaders[0]
		id, fileSize, err := indexBlocks(r.Context(), repo.StoreID, repo.Version, "", handler, cryptKey)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				err := fmt.Errorf("failed to index blocks: %w", err)
				return &appError{err, "", http.StatusInternalServerError}
			}
			return &appError{nil, "", http.StatusInternalServerError}
		}
		fileID = id
		size = fileSize
	}

	fullPath := filepath.Join(parentDir, fileName)
	oldFileID, _, _ := fsmgr.GetObjIDByPath(repo.StoreID, headCommit.RootID, fullPath)
	if fileID == oldFileID {
		if isAjax {
			retJSON, err := formatUpdateJSONRet(fileName, fileID, size)
			if err != nil {
				err := fmt.Errorf("failed to format json data")
				return &appError{err, "", http.StatusInternalServerError}
			}
			rsp.Write(retJSON)
		} else {
			rsp.Write([]byte(fileID))
		}
		return nil
	}

	mtime := time.Now().Unix()
	if lastModify > 0 {
		mtime = lastModify
	}
	mode := (syscall.S_IFREG | 0644)
	newDent := fsmgr.NewDirent(fileID, fileName, uint32(mode), mtime, user, size)

	var names []string
	rootID, err := doPostMultiFiles(repo, headCommit.RootID, canonPath, []*fsmgr.SeafDirent{newDent}, user, true, &names)
	if err != nil {
		err := fmt.Errorf("failed to put file %s to %s in repo %s: %v", fileName, canonPath, repo.ID, err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	desc := fmt.Sprintf("Modified \"%s\"", fileName)
	_, err = genNewCommit(repo, headCommit, rootID, user, desc, true, gcID, true)
	if err != nil {
		if errors.Is(err, ErrGCConflict) {
			return &appError{nil, "GC Conflict.\n", http.StatusConflict}
		} else {
			err := fmt.Errorf("failed to generate new commit: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
	}

	if isAjax {
		retJSON, err := formatUpdateJSONRet(fileName, fileID, size)
		if err != nil {
			err := fmt.Errorf("failed to format json data")
			return &appError{err, "", http.StatusInternalServerError}
		}
		rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
		rsp.Write(retJSON)
	} else {
		rsp.Write([]byte(fileID))
	}

	go mergeVirtualRepoPool.AddTask(repo.ID)

	return nil
}

func formatUpdateJSONRet(fileName, fileID string, size int64) ([]byte, error) {
	var array []map[string]interface{}
	obj := make(map[string]interface{})
	obj["name"] = fileName
	obj["id"] = fileID
	obj["size"] = size
	array = append(array, obj)

	jsonstr, err := json.Marshal(array)
	if err != nil {
		err := fmt.Errorf("failed to convert array to json")
		return nil, err
	}

	return jsonstr, nil
}

func checkFileExists(storeID, rootID, parentDir, fileName string) (bool, error) {
	dir, err := fsmgr.GetSeafdirByPath(storeID, rootID, parentDir)
	if err != nil {
		err := fmt.Errorf("parent_dir %s doesn't exist in repo %s: %v", parentDir, storeID, err)
		return false, err
	}

	var ret bool
	entries := dir.Entries
	for _, de := range entries {
		if de.Name == fileName {
			ret = true
			break
		}
	}

	return ret, nil
}

func uploadBlksAPICB(rsp http.ResponseWriter, r *http.Request) *appError {
	fsm, err := parseUploadHeaders(r)
	if err != nil {
		return err
	}

	if err := doUploadBlks(rsp, r, fsm); err != nil {
		formatJSONError(rsp, err)
		return err
	}

	return nil
}

func doUploadBlks(rsp http.ResponseWriter, r *http.Request, fsm *recvData) *appError {
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
			msg := "Invalid argument replace.\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		if replace == 1 {
			replaceExisted = true
		}
	}

	parentDir := normalizeUTF8Path(r.FormValue("parent_dir"))
	if parentDir == "" {
		msg := "No parent_dir given.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	lastModifyStr := normalizeUTF8Path(r.FormValue("last_modify"))
	var lastModify int64
	if lastModifyStr != "" {
		t, err := time.Parse(time.RFC3339, lastModifyStr)
		if err == nil {
			lastModify = t.Unix()
		}
	}

	fileName := normalizeUTF8Path(r.FormValue("file_name"))
	if fileName == "" {
		msg := "No file_name given.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	fileSizeStr := r.FormValue("file_size")
	var fileSize int64 = -1
	if fileSizeStr != "" {
		size, err := strconv.ParseInt(fileSizeStr, 10, 64)
		if err != nil {
			msg := "Invalid argument file_size.\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		fileSize = size
	}

	if fileSize < 0 {
		msg := "Invalid file size.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	commitOnlyStr, ok := r.Form["commitonly"]
	if !ok || len(commitOnlyStr) == 0 {
		msg := "Only commit supported.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if err := checkParentDir(repoID, parentDir); err != nil {
		return err
	}

	blockIDsJSON := r.FormValue("blockids")
	if blockIDsJSON == "" {
		msg := "No blockids given.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	fileID, appErr := commitFileBlocks(repoID, parentDir, fileName, blockIDsJSON, user, fileSize, replaceExisted, lastModify)
	if appErr != nil {
		return appErr
	}
	_, ok = r.Form["ret-json"]
	if ok {
		obj := make(map[string]interface{})
		obj["id"] = fileID

		jsonstr, err := json.Marshal(obj)
		if err != nil {
			err := fmt.Errorf("failed to convert array to json: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
		rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
		rsp.Write([]byte(jsonstr))
	} else {
		rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
		rsp.Write([]byte("\""))
		rsp.Write([]byte(fileID))
		rsp.Write([]byte("\""))
	}

	return nil
}

func commitFileBlocks(repoID, parentDir, fileName, blockIDsJSON, user string, fileSize int64, replace bool, lastModify int64) (string, *appError) {
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo.\n"
		err := fmt.Errorf("Failed to get repo %s", repoID)
		return "", &appError{err, msg, http.StatusInternalServerError}
	}

	headCommit, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		msg := "Failed to get head commit.\n"
		err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
		return "", &appError{err, msg, http.StatusInternalServerError}
	}

	canonPath := getCanonPath(parentDir)

	if shouldIgnoreFile(fileName) {
		msg := fmt.Sprintf("invalid fileName: %s.\n", fileName)
		return "", &appError{nil, msg, http.StatusBadRequest}
	}

	if strings.Contains(parentDir, "//") {
		msg := "parent_dir contains // sequence.\n"
		return "", &appError{nil, msg, http.StatusBadRequest}
	}

	var blkIDs []string
	err = json.Unmarshal([]byte(blockIDsJSON), &blkIDs)
	if err != nil {
		err := fmt.Errorf("failed to decode data to json: %v", err)
		return "", &appError{err, "", http.StatusInternalServerError}
	}

	appErr := checkQuotaBeforeCommitBlocks(repo.StoreID, blkIDs)
	if appErr != nil {
		return "", appErr
	}

	gcID, err := repomgr.GetCurrentGCID(repo.StoreID)
	if err != nil {
		err := fmt.Errorf("failed to get current gc id: %v", err)
		return "", &appError{err, "", http.StatusInternalServerError}
	}

	fileID, appErr := indexExistedFileBlocks(repoID, repo.Version, blkIDs, fileSize)
	if appErr != nil {
		return "", appErr
	}

	mtime := time.Now().Unix()
	if lastModify > 0 {
		mtime = lastModify
	}
	mode := (syscall.S_IFREG | 0644)
	newDent := fsmgr.NewDirent(fileID, fileName, uint32(mode), mtime, user, fileSize)
	var names []string
	rootID, err := doPostMultiFiles(repo, headCommit.RootID, canonPath, []*fsmgr.SeafDirent{newDent}, user, replace, &names)
	if err != nil {
		err := fmt.Errorf("failed to post file %s to %s in repo %s: %v", fileName, canonPath, repo.ID, err)
		return "", &appError{err, "", http.StatusInternalServerError}
	}

	desc := fmt.Sprintf("Added \"%s\"", fileName)
	_, err = genNewCommit(repo, headCommit, rootID, user, desc, true, gcID, true)
	if err != nil {
		if errors.Is(err, ErrGCConflict) {
			return "", &appError{nil, "GC Conflict.\n", http.StatusConflict}
		} else {
			err := fmt.Errorf("failed to generate new commit: %v", err)
			return "", &appError{err, "", http.StatusInternalServerError}
		}
	}

	return fileID, nil
}

func checkQuotaBeforeCommitBlocks(storeID string, blockIDs []string) *appError {
	var totalSize int64
	for _, blkID := range blockIDs {
		size, err := blockmgr.Stat(storeID, blkID)
		if err != nil {
			err := fmt.Errorf("failed to stat block %s in store %s: %v", blkID, storeID, err)
			return &appError{err, "", http.StatusInternalServerError}
		}
		totalSize += size
	}
	ret, err := checkQuota(storeID, totalSize)
	if err != nil {
		msg := "Internal error.\n"
		err := fmt.Errorf("failed to check quota: %v", err)
		return &appError{err, msg, http.StatusInternalServerError}
	}
	if ret == 1 {
		msg := "Out of quota.\n"
		return &appError{nil, msg, seafHTTPResNoQuota}
	}

	return nil
}

func indexExistedFileBlocks(repoID string, version int, blkIDs []string, fileSize int64) (string, *appError) {
	if len(blkIDs) == 0 {
		return fsmgr.EmptySha1, nil
	}

	for _, blkID := range blkIDs {
		if !blockmgr.Exists(repoID, blkID) {
			err := fmt.Errorf("failed to check block: %s", blkID)
			return "", &appError{err, "", seafHTTPResBlockMissing}
		}
	}

	fileID, err := writeSeafile(repoID, version, fileSize, blkIDs)
	if err != nil {
		err := fmt.Errorf("failed to write seafile: %v", err)
		return "", &appError{err, "", http.StatusInternalServerError}
	}

	return fileID, nil
}

func uploadRawBlksAPICB(rsp http.ResponseWriter, r *http.Request) *appError {
	fsm, err := parseUploadHeaders(r)
	if err != nil {
		return err
	}

	if err := doUploadRawBlks(rsp, r, fsm); err != nil {
		formatJSONError(rsp, err)
		return err
	}

	return nil
}

func doUploadRawBlks(rsp http.ResponseWriter, r *http.Request, fsm *recvData) *appError {
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return &appError{nil, "", http.StatusBadRequest}
	}
	defer r.MultipartForm.RemoveAll()

	repoID := fsm.repoID
	user := fsm.user

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

	if fsm.fileNames == nil {
		msg := "No file.\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if err := checkTmpFileList(fsm); err != nil {
		return err
	}

	if err := postBlocks(repoID, user, fsm); err != nil {
		return err
	}

	var contentLen int64
	lenstr := r.Header.Get("Content-Length")
	if lenstr != "" {
		conLen, err := strconv.ParseInt(lenstr, 10, 64)
		if err != nil {
			msg := "Internal error.\n"
			err := fmt.Errorf("failed to parse content len: %v", err)
			return &appError{err, msg, http.StatusInternalServerError}
		}
		contentLen = conLen
	}

	oper := "web-file-upload"
	sendStatisticMsg(repoID, user, oper, uint64(contentLen))

	rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
	rsp.Write([]byte("\"OK\""))

	return nil
}

func postBlocks(repoID, user string, fsm *recvData) *appError {
	blockIDs := fsm.fileNames
	fileHeaders := fsm.fileHeaders
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo.\n"
		err := fmt.Errorf("Failed to get repo %s", repoID)
		return &appError{err, msg, http.StatusInternalServerError}
	}

	if err := indexRawBlocks(repo.StoreID, blockIDs, fileHeaders); err != nil {
		err := fmt.Errorf("failed to index file blocks")
		return &appError{err, "", http.StatusInternalServerError}
	}

	go updateSizePool.AddTask(repo.ID)

	return nil
}

func indexRawBlocks(repoID string, blockIDs []string, fileHeaders []*multipart.FileHeader) error {
	for i, handler := range fileHeaders {
		var buf bytes.Buffer
		f, err := handler.Open()
		if err != nil {
			err := fmt.Errorf("failed to open file for read: %v", err)
			return err
		}
		_, err = buf.ReadFrom(f)
		if err != nil {
			err := fmt.Errorf("failed to read block: %v", err)
			return err
		}
		checkSum := sha1.Sum(buf.Bytes())
		blkID := hex.EncodeToString(checkSum[:])
		if blkID != blockIDs[i] {
			err := fmt.Errorf("block id %s:%s doesn't match content", blkID, blockIDs[i])
			return err
		}

		err = blockmgr.Write(repoID, blkID, &buf)
		if err != nil {
			err := fmt.Errorf("failed to write block: %s/%s: %v", repoID, blkID, err)
			return err
		}
	}

	return nil
}

/*
func uploadLinkCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if seahubPK == "" {
		err := fmt.Errorf("no seahub private key is configured")
		return &appError{err, "", http.StatusNotFound}
	}
	if r.Method == "OPTIONS" {
		setAccessControl(rsp)
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	fsm, err := parseUploadLinkHeaders(r)
	if err != nil {
		return err
	}

	if err := doUpload(rsp, r, fsm, false); err != nil {
		formatJSONError(rsp, err)
		return err
	}

	return nil
}

func parseUploadLinkHeaders(r *http.Request) (*recvData, *appError) {
	tokenLen := 36
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 2 {
		msg := "Invalid URL"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}
	if len(parts[1]) < tokenLen {
		msg := "Invalid URL"
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}
	token := parts[1][:tokenLen]

	info, appErr := queryShareLinkInfo(token, "upload")
	if appErr != nil {
		return nil, appErr
	}

	repoID := info.RepoID
	parentDir := normalizeUTF8Path(info.ParentDir)

	status, err := repomgr.GetRepoStatus(repoID)
	if err != nil {
		return nil, &appError{err, "", http.StatusInternalServerError}
	}
	if status != repomgr.RepoStatusNormal && status != -1 {
		msg := "Repo status not writable."
		return nil, &appError{nil, msg, http.StatusBadRequest}
	}

	user, _ := repomgr.GetRepoOwner(repoID)

	fsm := new(recvData)

	fsm.parentDir = parentDir
	fsm.tokenType = "upload-link"
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
*/

type ShareLinkInfo struct {
	RepoID    string `json:"repo_id"`
	FilePath  string `json:"file_path"`
	ParentDir string `json:"parent_dir"`
	ShareType string `json:"share_type"`
}

func queryShareLinkInfo(token, cookie, opType, ipAddr, userAgent string) (*ShareLinkInfo, *appError) {
	tokenString, err := utils.GenSeahubJWTToken()
	if err != nil {
		err := fmt.Errorf("failed to sign jwt token: %v", err)
		return nil, &appError{err, "", http.StatusInternalServerError}
	}
	url := fmt.Sprintf("%s?type=%s", option.SeahubURL+"/check-share-link-access/", opType)
	header := map[string][]string{
		"Authorization": {"Token " + tokenString},
	}
	if cookie != "" {
		header["Cookie"] = []string{cookie}
	}
	req := make(map[string]string)
	req["token"] = token
	if ipAddr != "" {
		req["ip_addr"] = ipAddr
	}
	if userAgent != "" {
		req["user_agent"] = userAgent
	}
	msg, err := json.Marshal(req)
	if err != nil {
		err := fmt.Errorf("failed to encode access token: %v", err)
		return nil, &appError{err, "", http.StatusInternalServerError}
	}
	status, body, err := utils.HttpCommon("POST", url, header, bytes.NewReader(msg))
	if err != nil {
		if status != http.StatusInternalServerError {
			return nil, &appError{nil, string(body), status}
		} else {
			err := fmt.Errorf("failed to get share link info: %v", err)
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
	}

	info := new(ShareLinkInfo)
	err = json.Unmarshal(body, &info)
	if err != nil {
		err := fmt.Errorf("failed to decode share link info: %v", err)
		return nil, &appError{err, "", http.StatusInternalServerError}
	}

	return info, nil
}

func accessLinkCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if option.JWTPrivateKey == "" {
		err := fmt.Errorf("no seahub private key is configured")
		return &appError{err, "", http.StatusNotFound}
	}

	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 2 {
		msg := "Invalid URL"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	token := parts[1]
	cookie := r.Header.Get("Cookie")
	ipAddr := getClientIPAddr(r)
	userAgent := r.Header.Get("User-Agent")
	info, appErr := queryShareLinkInfo(token, cookie, "file", ipAddr, userAgent)
	if appErr != nil {
		return appErr
	}

	if info.FilePath == "" {
		msg := "Internal server error\n"
		err := fmt.Errorf("failed to get file_path by token %s", token)
		return &appError{err, msg, http.StatusInternalServerError}
	}
	if info.ShareType != "f" {
		msg := "Link type mismatch"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	repoID := info.RepoID
	filePath := normalizeUTF8Path(info.FilePath)
	fileName := filepath.Base(filePath)

	op := r.URL.Query().Get("op")
	if op != "view" {
		op = "download-link"
	}

	ranges := r.Header["Range"]
	byteRanges := strings.Join(ranges, "")

	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Bad repo id\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	user, _ := repomgr.GetRepoOwner(repoID)

	fileID, _, err := fsmgr.GetObjIDByPath(repo.StoreID, repo.RootID, filePath)
	if err != nil {
		msg := "Invalid file_path\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	// Check for file changes by comparing the ETag in the If-None-Match header with the file ID. Set no-cache to allow clients to validate file changes before using the cache.
	etag := r.Header.Get("If-None-Match")
	if etag == fileID {
		return &appError{nil, "", http.StatusNotModified}
	}

	rsp.Header().Set("ETag", fileID)
	rsp.Header().Set("Cache-Control", "public, no-cache")

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user, repo.EncVersion)
		if err != nil {
			return err
		}
		cryptKey = key
	}

	exists, _ := fsmgr.Exists(repo.StoreID, fileID)
	if !exists {
		msg := "Invalid file id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if !repo.IsEncrypted && len(byteRanges) != 0 {
		if err := doFileRange(rsp, r, repo, fileID, fileName, op, byteRanges, user); err != nil {
			return err
		}
	} else if err := doFile(rsp, r, repo, fileID, fileName, op, cryptKey, user); err != nil {
		return err
	}

	return nil
}

/*
func accessDirLinkCB(rsp http.ResponseWriter, r *http.Request) *appError {
	if seahubPK == "" {
		err := fmt.Errorf("no seahub private key is configured")
		return &appError{err, "", http.StatusNotFound}
	}

	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 2 {
		msg := "Invalid URL"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	token := parts[1]
	info, appErr := queryShareLinkInfo(token, "dir")
	if appErr != nil {
		return appErr
	}

	repoID := info.RepoID
	parentDir := normalizeUTF8Path(info.ParentDir)
	op := "download-link"

	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Bad repo id\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	user, _ := repomgr.GetRepoOwner(repoID)

	filePath := r.URL.Query().Get("p")
	if filePath == "" {
		err := r.ParseForm()
		if err != nil {
			msg := "Invalid form\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		parentDir := r.FormValue("parent_dir")
		if parentDir == "" {
			msg := "Invalid parent_dir\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		parentDir = normalizeUTF8Path(parentDir)
		parentDir = getCanonPath(parentDir)
		dirents := r.FormValue("dirents")
		if dirents == "" {
			msg := "Invalid dirents\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		// opStr:=r.FormVale("op")
		list, err := jsonToDirentList(repo, parentDir, dirents)
		if err != nil {
			log.Warnf("failed to parse dirent list: %v", err)
			msg := "Invalid dirents\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}
		if len(list) == 0 {
			msg := "Invalid dirents\n"
			return &appError{nil, msg, http.StatusBadRequest}
		}

		obj := make(map[string]interface{})
		if len(list) == 1 {
			dent := list[0]
			op = "download-dir-link"
			obj["dir_name"] = dent.Name
			obj["obj_id"] = dent.ID
		} else {
			op = "download-multi-link"
			obj["parent_dir"] = parentDir
			var fileList []string
			for _, dent := range list {
				fileList = append(fileList, dent.Name)
			}
			obj["file_list"] = fileList
		}
		data, err := json.Marshal(obj)
		if err != nil {
			err := fmt.Errorf("failed to encode zip obj: %v", err)
			return &appError{err, "", http.StatusInternalServerError}
		}
		if err := downloadZipFile(rsp, r, string(data), repoID, user, op); err != nil {
			return err
		}
		return nil
	}

	// file path is not empty string
	if _, ok := r.Header["If-Modified-Since"]; ok {
		return &appError{nil, "", http.StatusNotModified}
	}

	filePath = normalizeUTF8Path(filePath)
	fullPath := filepath.Join(parentDir, filePath)
	fileName := filepath.Base(filePath)

	fileID, _, err := fsmgr.GetObjIDByPath(repo.StoreID, repo.RootID, fullPath)
	if err != nil {
		msg := "Invalid file_path\n"
		return &appError{nil, msg, http.StatusBadRequest}
	}
	rsp.Header().Set("ETag", fileID)

	now := time.Now()
	rsp.Header().Set("Last-Modified", now.Format("Mon, 2 Jan 2006 15:04:05 GMT"))
	rsp.Header().Set("Cache-Control", "max-age=3600")

	ranges := r.Header["Range"]
	byteRanges := strings.Join(ranges, "")

	var cryptKey *seafileCrypt
	if repo.IsEncrypted {
		key, err := parseCryptKey(rsp, repoID, user, repo.EncVersion)
		if err != nil {
			return err
		}
		cryptKey = key
	}

	exists, _ := fsmgr.Exists(repo.StoreID, fileID)
	if !exists {
		msg := "Invalid file id"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	if !repo.IsEncrypted && len(byteRanges) != 0 {
		if err := doFileRange(rsp, r, repo, fileID, fileName, op, byteRanges, user); err != nil {
			return err
		}
	} else if err := doFile(rsp, r, repo, fileID, fileName, op, cryptKey, user); err != nil {
		return err
	}

	return nil
}

func jsonToDirentList(repo *repomgr.Repo, parentDir, dirents string) ([]*fsmgr.SeafDirent, error) {
	var list []string
	err := json.Unmarshal([]byte(dirents), &list)
	if err != nil {
		return nil, err
	}

	dir, err := fsmgr.GetSeafdirByPath(repo.StoreID, repo.RootID, parentDir)
	if err != nil {
		return nil, err
	}

	direntHash := make(map[string]*fsmgr.SeafDirent)
	for _, dent := range dir.Entries {
		direntHash[dent.Name] = dent
	}

	var direntList []*fsmgr.SeafDirent
	for _, path := range list {
		normPath := normalizeUTF8Path(path)
		if normPath == "" || normPath == "/" {
			return nil, fmt.Errorf("Invalid download file name: %s\n", normPath)
		}
		dent, ok := direntHash[normPath]
		if !ok {
			return nil, fmt.Errorf("failed to get dient for %s in dir %s in repo %s", normPath, parentDir, repo.StoreID)
		}
		direntList = append(direntList, dent)
	}

	return direntList, nil
}
*/

func removeFileopExpireCache() {
	deleteBlockMaps := func(key interface{}, value interface{}) bool {
		if blkMap, ok := value.(*blockMap); ok {
			if blkMap.expireTime <= time.Now().Unix() {
				blockMapCacheTable.Delete(key)
			}
		}
		return true
	}

	blockMapCacheTable.Range(deleteBlockMaps)
}
