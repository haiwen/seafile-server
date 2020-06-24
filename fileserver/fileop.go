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

func doFile(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, cryptKey map[string]interface{}, user string) int {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		log.Printf("failed to get seafile : %v\n", err)
		return -1
	}

	var encKey, encIv []byte
	if cryptKey != nil {
		key, ok := cryptKey["key"].(string)
		if !ok {
			return -1
		}
		iv, ok := cryptKey["iv"].(string)
		if !ok {
			return -1
		}
		encKey, err = hex.DecodeString(key)
		if err != nil {
			return -1
		}
		encIv, err = hex.DecodeString(iv)
		if err != nil {
			return -1
		}
	}

	rsp.Header().Set("Access-Control-Allow-Origin", "*")
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

	//filesize string
	fileSize := fmt.Sprintf("%d", file.FileSize)
	rsp.Header().Set("Content-Length", fileSize)

	var contFileName string
	if operation == "download" || operation == "download-link" {
		contFileName = fmt.Sprintf("attachment;filename*=\"utf-8' '%s\"", fileName)
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

	if r.Method == "HEAD" {
		return 0
	}
	if file.FileSize == 0 {
		return 0
	}

	if cryptKey != nil {
		for _, blkID := range file.BlkIDs {
			var buf bytes.Buffer
			blockmgr.Read(repo.StoreID, blkID, &buf)
			decoded, err := decrypt(buf.Bytes(), encKey, encIv)
			if err != nil {
				return -1
			}
			rsp.Write(decoded)
		}
		return 0
	}

	for _, blkID := range file.BlkIDs {
		blockmgr.Read(repo.StoreID, blkID, rsp)
	}
	return 0
}

func parseRange(byteRanges string, fileSize uint64) (uint64, uint64, bool) {
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
		return fileSize - firstByte, fileSize - 1, true
	} else if end+1 == len(byteRanges) {
		firstByte, err := strconv.ParseUint(byteRanges[start+1:end], 10, 64)
		if err != nil {
			return 0, 0, false
		}

		return firstByte, fileSize - 1, true
	}

	firstByte, err := strconv.ParseUint(byteRanges[start+1:end], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	lastByte, err := strconv.ParseUint(byteRanges[end+1:], 10, 64)
	if err != nil {
		return 0, 0, false
	}

	return firstByte, lastByte, true
}

func doFileRange(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, byteRanges string, user string) int {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		log.Printf("failed to get seafile : %v\n", err)
		return -1
	}

	if file.FileSize == 0 {
		return 0
	}

	start, end, ok := parseRange(byteRanges, file.FileSize)
	if !ok {
		conRange := fmt.Sprintf("bytes */%d", file.FileSize)
		rsp.Header().Set("Content-Range", conRange)
		rsp.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return 0
	}

	rsp.Header().Set("Accept-Ranges", "bytes")

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

	//filesize string
	conLen := fmt.Sprintf("%d", end-start+1)
	rsp.Header().Set("Content-Length", conLen)

	conRange := fmt.Sprintf("bytes %d-%d/%d", start, end, file.FileSize)
	rsp.Header().Set("Content-Range", conRange)

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

	var buf bytes.Buffer
	for _, blkID := range file.BlkIDs {
		blockmgr.Read(repo.StoreID, blkID, &buf)
	}

	recvBuf := buf.Bytes()
	rsp.Write(recvBuf[start : end+1])

	return 0
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
	webaccess, err := client.Call("seafile_web_query_access_token", token)
	if err != nil {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	webaccessMap, ok := webaccess.(map[string]interface{})
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}

	repoID, ok := webaccessMap["repo-id"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	objID, ok := webaccessMap["obj-id"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	op, ok := webaccessMap["op"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	user, ok := webaccessMap["username"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}

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
		key, err := client.Call("seafile_get_decrypt_key", repoID, user)
		if err != nil {
			err := "Repo is encrypted. Please provide password to view it."
			rsp.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(rsp, "%s\n", err)
			return
		}
		cryptKey, ok = key.(map[string]interface{})
		if !ok {
			err := "Repo is encrypted. Please provide password to view it."
			rsp.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(rsp, "%s\n", err)
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
		if doFileRange(rsp, r, repo, objID, fileName, op, byteRanges, user) < 0 {
			err := "Internal server error"
			rsp.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(rsp, "%s\n", err)
		}
	} else if doFile(rsp, r, repo, objID, fileName, op, cryptKey, user) < 0 {
		err := "Internal server error"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
}

func doBlock(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	user string, blkID string) int {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		log.Printf("failed to get seafile : %v\n", err)
		return -1
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
		return 0
	}

	exists := blockmgr.Exists(repo.StoreID, blkID)
	if !exists {
		rsp.WriteHeader(http.StatusBadRequest)
		return 0
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
		return -1
	}

	fileSize := fmt.Sprintf("%d", buf.Len())
	rsp.Header().Set("Content-Length", fileSize)

	rsp.Write(buf.Bytes())
	return 0
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
	webaccess, err := client.Call("seafile_web_query_access_token", token)
	if err != nil {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	webaccessMap, ok := webaccess.(map[string]interface{})
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}

	repoID, ok := webaccessMap["repo-id"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	id, ok := webaccessMap["obj-id"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	op, ok := webaccessMap["op"].(string)
	if !ok {
		err := "Bad access token"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
		return
	}
	user, ok := webaccessMap["username"].(string)
	if !ok {
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

	if doBlock(rsp, r, repo, id, user, blkID) < 0 {
		err := "Internal server error"
		rsp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(rsp, "%s\n", err)
	}
}

func handleHttpRequest(rsp http.ResponseWriter, r *http.Request) {
	switch {
	case access.MatchString(r.URL.Path):
		accessCB(rsp, r)
	case accessBlks.MatchString(r.URL.Path):
		accessBlksCB(rsp, r)
	}
}
