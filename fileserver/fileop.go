package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encoding/hex"
	_ "github.com/go-sql-driver/mysql"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	_ "github.com/haiwen/seafile-server/fileserver/searpc"
)

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
		err := "Invalid URL"
		return &appError{nil, err, http.StatusBadRequest}
	}
	token := parts[1]
	fileName := parts[2]
	accessInfo, err := parseWebaccessInfo(rsp, token)
	if err != nil {
		return err
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	objID := accessInfo.objID

	if op != "view" && op != "download" && op != "download-link" {
		err := "Bad access token"
		return &appError{nil, err, http.StatusBadRequest}
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
		err := "Bad repo id"
		return &appError{nil, err, http.StatusBadRequest}
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
		err := "Invalid file id"
		return &appError{nil, err, http.StatusBadRequest}
	}

	if !repo.IsEncrypted && len(byteRanges) != 0 {
		if err := doFileRange(rsp, r, repo, objID, fileName, op, byteRanges, user); err != nil {
			errMessage := "Internal server error"
			return &appError{err, errMessage, http.StatusBadRequest}
		}
	} else if err := doFile(rsp, r, repo, objID, fileName, op, cryptKey, user); err != nil {
		errMessage := "Internal server error"
		return &appError{nil, errMessage, http.StatusBadRequest}
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
		err := fmt.Errorf("failed to get decrypt key : %v.\n", err)
		return nil, &appError{err, errMessage, http.StatusBadRequest}
	}

	cryptKey, ok := key.(map[string]interface{})
	if !ok {
		errMessage := "Internal server error."
		err := fmt.Errorf("failed to assert crypt key.\n")
		return nil, &appError{err, errMessage, http.StatusBadRequest}
	}

	seafileKey := new(seafileCrypt)

	if cryptKey != nil {
		key, ok := cryptKey["key"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt key.\n")
			return nil, &appError{err, "", http.StatusBadRequest}
		}
		iv, ok := cryptKey["iv"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt iv.\n")
			return nil, &appError{err, "", http.StatusBadRequest}
		}
		seafileKey.key, err = hex.DecodeString(key)
		if err != nil {
			err := fmt.Errorf("failed to decode key: %v.\n", err)
			return nil, &appError{err, "", http.StatusBadRequest}
		}
		seafileKey.iv, err = hex.DecodeString(iv)
		if err != nil {
			err := fmt.Errorf("failed to decode iv: %v.\n", err)
			return nil, &appError{err, "", http.StatusBadRequest}
		}
	}

	return seafileKey, nil
}

func doFile(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, cryptKey *seafileCrypt, user string) error {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v.\n", err)
		return err
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
				err := fmt.Errorf("failed to decrypt block %s: %v.\n", blkID, err)
				return err
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
	fileName string, operation string, byteRanges string, user string) error {

	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v\n", err)
		return err
	}

	if file.FileSize == 0 {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	start, end, ok := parseRange(byteRanges, file.FileSize)
	if !ok {
		conRange := fmt.Sprintf("bytes */%d", file.FileSize)
		rsp.Header().Set("Content-Range", conRange)
		rsp.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return nil
	}

	rsp.Header().Set("Accept-Ranges", "bytes")

	setCommonHeaders(rsp, r, operation, fileName)

	//filesize string
	conLen := fmt.Sprintf("%d", end-start+1)
	rsp.Header().Set("Content-Length", conLen)

	conRange := fmt.Sprintf("bytes %d-%d/%d", start, end, file.FileSize)
	rsp.Header().Set("Content-Range", conRange)

	var blkSize []int64
	for _, v := range file.BlkIDs {
		size, err := blockmgr.Stat(repo.StoreID, v)
		if err != nil {
			err := fmt.Errorf("failed to stat block %s : %v.\n", v, err)
			return err
		}
		blkSize = append(blkSize, size)
	}

	var off int64
	var pos int64
	var startBlock int
	for i, v := range blkSize {
		pos = start - off
		off += v
		if off > start {
			startBlock = i
			break
		}
	}

	for i, blkID := range file.BlkIDs {
		if i < startBlock {
			continue
		}

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
		} else {
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
			startBlock += 1
			break
		}
	}

	for i, blkID := range file.BlkIDs {
		if i < startBlock {
			continue
		}

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

func parseRange(byteRanges string, fileSize uint64) (int64, int64, bool) {
	start := strings.Index(byteRanges, "=")
	end := strings.Index(byteRanges, "-")

	if end < 0 {
		return 0, 0, false
	}

	var startByte, endByte int64

	if start+1 == end {
		retByte, err := strconv.ParseUint(byteRanges[end+1:], 10, 64)
		if err != nil || retByte == 0 {
			return 0, 0, false
		}
		startByte = int64(fileSize - retByte)
		endByte = int64(fileSize - 1)
	} else if end+1 == len(byteRanges) {
		firstByte, err := strconv.ParseUint(byteRanges[start+1:end], 10, 64)
		if err != nil {
			return 0, 0, false
		}

		startByte = int64(firstByte)
		endByte = int64(fileSize - 1)
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

		startByte = int64(firstByte)
		endByte = int64(lastByte)
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
			contentType = contentType
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
		err := "Invalid URL"
		return &appError{nil, err, http.StatusBadRequest}
	}
	token := parts[1]
	blkID := parts[2]
	accessInfo, err := parseWebaccessInfo(rsp, token)
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
		err := "Bad repo id"
		return &appError{nil, err, http.StatusBadRequest}
	}

	exists, _ := fsmgr.Exists(repo.StoreID, id)
	if !exists {
		err := "Invalid file id"
		return &appError{nil, err, http.StatusBadRequest}
	}

	if op != "downloadblks" {
		err := "Bad access token"
		return &appError{nil, err, http.StatusBadRequest}
	}

	if err := doBlock(rsp, r, repo, id, user, blkID); err != nil {
		errMessage := "Internal server error"
		return &appError{err, errMessage, http.StatusBadRequest}
	}

	return nil
}

func doBlock(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	user string, blkID string) error {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v.\n", err)
		return err
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
		err := fmt.Errorf("failed to stat block %s: %v.\n", blkID, err)
		return err
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

type webaccessInfo struct {
	repoID string
	objID  string
	op     string
	user   string
}

func parseWebaccessInfo(rsp http.ResponseWriter, token string) (*webaccessInfo, *appError) {
	webaccess, err := rpcclient.Call("seafile_web_query_access_token", token)
	if err != nil {
		err := "Bad access token"
		return nil, &appError{nil, err, http.StatusBadRequest}
	}
	webaccessMap, ok := webaccess.(map[string]interface{})
	if !ok {
		err := "internal server error"
		return nil, &appError{nil, err, http.StatusBadRequest}
	}

	accessInfo := new(webaccessInfo)
	repoID, ok := webaccessMap["repo-id"].(string)
	if !ok {
		err := "internal server error"
		return nil, &appError{nil, err, http.StatusBadRequest}
	}
	accessInfo.repoID = repoID

	id, ok := webaccessMap["obj-id"].(string)
	if !ok {
		err := "internal server error"
		return nil, &appError{nil, err, http.StatusBadRequest}
	}
	accessInfo.objID = id

	op, ok := webaccessMap["op"].(string)
	if !ok {
		err := "internal server error"
		return nil, &appError{nil, err, http.StatusBadRequest}
	}
	accessInfo.op = op

	user, ok := webaccessMap["username"].(string)
	if !ok {
		err := "internal server error"
		return nil, &appError{nil, err, http.StatusBadRequest}
	}
	accessInfo.user = user

	return accessInfo, nil
}
