package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	_ "github.com/go-sql-driver/mysql"
	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	_ "github.com/haiwen/seafile-server/fileserver/searpc"
)

var access = regexp.MustCompile(`^/files/.*`)
var accessBlks = regexp.MustCompile(`^/blks/.*`)

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

func pkcs7Padding(p []byte, blockSize int) []byte {
	padding := blockSize - len(p)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(p, padtext...)
}

func pkcs7UnPadding(p []byte) []byte {
	length := len(p)
	paddLen := int(p[length-1])
	return p[:(length - paddLen)]
}

func decrypt(input, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(input))
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(out, input)
	out = pkcs7UnPadding(out)

	return out, nil
}

func encrypt(input, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	input = pkcs7Padding(input, block.BlockSize())
	out := make([]byte, len(input))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(out, input)

	return out, nil
}

func parseRange(byteRanges string, fileSize uint64) (int64, int64, bool) {
	start := strings.Index(byteRanges, "=")
	end := strings.Index(byteRanges, "-")

	if end < 0 {
		return 0, 0, false
	}

	if start+1 == end {
		firstByte, err := strconv.ParseUint(byteRanges[end+1:], 10, 64)
		if err != nil || firstByte == 0 {
			return 0, 0, false
		}
		return int64(fileSize - firstByte), int64(fileSize - 1), true
	} else if end+1 == len(byteRanges) {
		firstByte, err := strconv.ParseUint(byteRanges[start+1:end], 10, 64)
		if err != nil {
			return 0, 0, false
		}

		return int64(firstByte), int64(fileSize - 1), true
	}

	firstByte, err := strconv.ParseUint(byteRanges[start+1:end], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	lastByte, err := strconv.ParseUint(byteRanges[end+1:], 10, 64)
	if err != nil {
		return 0, 0, false
	}

	return int64(firstByte), int64(lastByte), true
}

func accessCB(rsp http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 3 {
		err := "Invalid URL"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	token := parts[1]
	fileName := parts[2]
	accessInfo := parseWebaccessInfo(rsp, token)
	if accessInfo == nil {
		return
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	objID := accessInfo.objID

	if op != "view" && op != "download" && op != "download-link" {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}

	if _, ok := r.Header["If-Modified-Since"]; ok {
		rsp.WriteHeader(http.StatusNotModified)
		return
	}

	now := time.Now()
	rsp.Header().Set("Last-Modified", now.Format("Mon, 2 Jan 2006 15:04:05 GMT"))
	rsp.Header().Set("Cache-Control", "max-age=3600")

	Range := r.Header["Range"]
	byteRanges := strings.Join(Range, "")

	repo := repomgr.Get(repoID)
	if repo == nil {
		err := "Bad repo id"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}

	var cryptKey map[string]interface{}
	if repo.IsEncrypted {
		cryptKey = parseCryptKey(rsp, repoID, user)
		if cryptKey == nil {
			return
		}
	}

	exists, _ := fsmgr.Exists(repo.StoreID, objID)
	if !exists {
		err := "Invalid file id"
		fmt.Fprintf(rsp, "%s\n", err)
		rsp.WriteHeader(http.StatusBadRequest)
		return
	}

	if !repo.IsEncrypted && len(byteRanges) != 0 {
		if err := doFileRange(rsp, r, repo, objID, fileName, op, byteRanges, user); err != nil {
			log.Printf("internal server error: %v.\n", err)
			err := "Internal server error"
			rsp.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(rsp, "%s\n", err)
		}
	} else if err := doFile(rsp, r, repo, objID, fileName, op, cryptKey, user); err != nil {
		log.Printf("internal server error: %v.\n", err)
		err := "Internal server error"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
}

func parseCryptKey(rsp http.ResponseWriter, repoID string, user string) map[string]interface{} {
	key, err := rpcclient.Call("seafile_get_decrypt_key", repoID, user)
	if err != nil {
		err := "Repo is encrypted. Please provide password to view it."
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}

	cryptKey, ok := key.(map[string]interface{})
	if !ok {
		err := "Repo is encrypted. Please provide password to view it."
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}

	return cryptKey
}

func doFile(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, cryptKey map[string]interface{}, user string) error {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v.\n", err)
		return err
	}

	var encKey, encIv []byte
	if cryptKey != nil {
		key, ok := cryptKey["key"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt key.\n")
			return err
		}
		iv, ok := cryptKey["iv"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt iv.\n")
			return err
		}
		encKey, err = hex.DecodeString(key)
		if err != nil {
			err := fmt.Errorf("failed to decode key: %v.\n", err)
			return err
		}
		encIv, err = hex.DecodeString(iv)
		if err != nil {
			err := fmt.Errorf("failed to decode iv: %v.\n", err)
			return err
		}
	}

	rsp.Header().Set("Access-Control-Allow-Origin", "*")

	httpSetHeader(rsp, r, operation, fileName)

	//filesize string
	fileSize := fmt.Sprintf("%d", file.FileSize)
	rsp.Header().Set("Content-Length", fileSize)

	if r.Method == "HEAD" {
		rsp.WriteHeader(http.StatusBadRequest)
		return nil
	}
	if file.FileSize == 0 {
		rsp.WriteHeader(http.StatusBadRequest)
		return nil
	}

	if cryptKey != nil {
		for _, blkID := range file.BlkIDs {
			var buf bytes.Buffer
			blockmgr.Read(repo.StoreID, blkID, &buf)
			decoded, err := decrypt(buf.Bytes(), encKey, encIv)
			if err != nil {
				err := fmt.Errorf("failed to decrypt block: %v.\n", err)
				return err
			}
			rsp.Write(decoded)
		}
		return nil
	}

	for _, blkID := range file.BlkIDs {
		blockmgr.Read(repo.StoreID, blkID, rsp)
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
		rsp.WriteHeader(http.StatusBadRequest)
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

	httpSetHeader(rsp, r, operation, fileName)

	//filesize string
	conLen := fmt.Sprintf("%d", end-start+1)
	rsp.Header().Set("Content-Length", conLen)

	conRange := fmt.Sprintf("bytes %d-%d/%d", start, end, file.FileSize)
	rsp.Header().Set("Content-Range", conRange)

	var blkSize []int64
	for _, v := range file.BlkIDs {
		size, err := blockmgr.Stat(repo.StoreID, v)
		if err != nil {
			err := fmt.Errorf("failed to stat block : %v.\n", err)
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
		if pos == 0 {
			if end-start+1 <= blkSize[i] {
				blockmgr.Read(repo.StoreID, blkID, &buf)
				recvBuf := buf.Bytes()
				rsp.Write(recvBuf[:end-start+1])
				break
			} else {
				blockmgr.Read(repo.StoreID, blkID, rsp)
				pos = 0
				start += blkSize[i]
			}
		} else {
			if end-start+1 <= blkSize[i]-pos {
				blockmgr.Read(repo.StoreID, blkID, &buf)
				recvBuf := buf.Bytes()
				rsp.Write(recvBuf[pos : pos+end-start+1])
				break
			} else {
				blockmgr.Read(repo.StoreID, blkID, &buf)
				recvBuf := buf.Bytes()
				rsp.Write(recvBuf[pos:])
				start += blkSize[i] - pos
				pos = 0
			}
		}
	}

	return nil
}

func httpSetHeader(rsp http.ResponseWriter, r *http.Request, operation, fileName string) {
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
	if operation == "download" || operation == "download-link" {
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

func accessBlksCB(rsp http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 3 {
		err := "Invalid URL"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	token := parts[1]
	blkID := parts[2]
	accessInfo := parseWebaccessInfo(rsp, token)
	if accessInfo == nil {
		return
	}
	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	id := accessInfo.objID

	if _, ok := r.Header["If-Modified-Since"]; ok {
		rsp.WriteHeader(http.StatusNotModified)
		return
	}

	now := time.Now()
	rsp.Header().Set("Last-Modified", now.Format("Mon, 2 Jan 2006 15:04:05 GMT"))
	rsp.Header().Set("Cache-Control", "max-age=3600")

	repo := repomgr.Get(repoID)
	if repo == nil {
		err := "Bad repo id"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}

	exists, _ := fsmgr.Exists(repo.StoreID, id)
	if !exists {
		err := "Invalid file id"
		fmt.Fprintf(rsp, "%s\n", err)
		rsp.WriteHeader(http.StatusBadRequest)
		return
	}

	if op != "downloadblks" {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}

	if err := doBlock(rsp, r, repo, id, user, blkID); err != nil {
		log.Printf("internal server error : %v.\n", err)
		err := "Internal server error"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
	}
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
	var contFileName string
	if testFireFox(r) {
		contFileName = fmt.Sprintf("attachment;filename*=\"utf-8' '%s\"", blkID)
	} else {
		contFileName = fmt.Sprintf("attachment;filename*=\"%s\"", blkID)
	}
	rsp.Header().Set("Content-Disposition", contFileName)

	var buf bytes.Buffer
	err = blockmgr.Read(repo.StoreID, blkID, &buf)
	if err != nil {
		err := fmt.Errorf("failed to read block : %v.\n", err)
		return err
	}

	fileSize := fmt.Sprintf("%d", buf.Len())
	rsp.Header().Set("Content-Length", fileSize)

	rsp.Write(buf.Bytes())
	return nil
}

type webaccessInfo struct {
	repoID string
	objID  string
	op     string
	user   string
}

func parseWebaccessInfo(rsp http.ResponseWriter, token string) *webaccessInfo {
	webaccess, err := rpcclient.Call("seafile_web_query_access_token", token)
	if err != nil {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}
	webaccessMap, ok := webaccess.(map[string]interface{})
	if !ok {
		err := "internal server error"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}

	accessInfo := new(webaccessInfo)
	repoID, ok := webaccessMap["repo-id"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}
	accessInfo.repoID = repoID

	id, ok := webaccessMap["obj-id"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}
	accessInfo.objID = id

	op, ok := webaccessMap["op"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}
	accessInfo.op = op

	user, ok := webaccessMap["username"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return nil
	}
	accessInfo.user = user

	return accessInfo
}

func handleHttpRequest(rsp http.ResponseWriter, r *http.Request) {
	switch {
	case access.MatchString(r.URL.Path):
		accessCB(rsp, r)
	case accessBlks.MatchString(r.URL.Path):
		accessBlksCB(rsp, r)
	}
}
