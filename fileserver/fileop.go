package main

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
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
		msg := "Invalid URL"
		return &appError{nil, msg, http.StatusBadRequest}
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
		err := fmt.Errorf("failed to get decrypt key : %v.\n", err)
		return nil, &appError{err, errMessage, http.StatusBadRequest}
	}

	cryptKey, ok := key.(map[string]interface{})
	if !ok {
		err := fmt.Errorf("failed to assert crypt key.\n")
		return nil, &appError{err, "", http.StatusInternalServerError}
	}

	seafileKey := new(seafileCrypt)

	if cryptKey != nil {
		key, ok := cryptKey["key"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt key.\n")
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
		iv, ok := cryptKey["iv"].(string)
		if !ok {
			err := fmt.Errorf("failed to parse crypt iv.\n")
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
		seafileKey.key, err = hex.DecodeString(key)
		if err != nil {
			err := fmt.Errorf("failed to decode key: %v.\n", err)
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
		seafileKey.iv, err = hex.DecodeString(iv)
		if err != nil {
			err := fmt.Errorf("failed to decode iv: %v.\n", err)
			return nil, &appError{err, "", http.StatusInternalServerError}
		}
	}

	return seafileKey, nil
}

func doFile(rsp http.ResponseWriter, r *http.Request, repo *repomgr.Repo, fileID string,
	fileName string, operation string, cryptKey *seafileCrypt, user string) *appError {
	file, err := fsmgr.GetSeafile(repo.StoreID, fileID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v.\n", err)
		return &appError{err, "", http.StatusBadRequest}
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
		err := fmt.Errorf("failed to get seafile : %v\n", err)
		return &appError{err, "", http.StatusBadRequest}
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
			err := fmt.Errorf("failed to stat block %s : %v.\n", v, err)
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
			i++
			break
		}
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
		msg := "Invalid URL"
		return &appError{nil, msg, http.StatusBadRequest}
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
		err := fmt.Errorf("failed to get seafile : %v.\n", err)
		return &appError{err, "", http.StatusBadRequest}
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
		return &appError{err, "", http.StatusBadRequest}
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

	accessInfo, err := parseWebaccessInfo(rsp, token)
	if err != nil {
		return err
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	data := accessInfo.objID

	if op != "download-dir" && op != "download-dir-link" &&
		op != "download-multi" && op != "download-multi-link" {
		msg := "Bad access token"
		return &appError{nil, msg, http.StatusBadRequest}
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
		err := fmt.Errorf("failed to get repo %s.\n", repoID)
		return &appError{err, "", http.StatusBadRequest}
	}

	obj := make(map[string]interface{})
	err := json.Unmarshal([]byte(data), &obj)
	if err != nil {
		err := fmt.Errorf("failed to parse obj data for zip: %v.\n", err)
		return &appError{err, "", http.StatusBadRequest}
	}

	ar := zip.NewWriter(rsp)
	defer ar.Close()

	if op == "download-dir" || op == "download-dir-link" {
		dirName, ok := obj["dir_name"].(string)
		if !ok || dirName == "" {
			err := fmt.Errorf("invalid download dir data: miss dir_name field.\n")
			return &appError{err, "", http.StatusBadRequest}
		}

		objID, ok := obj["obj_id"].(string)
		if !ok || objID == "" {
			err := fmt.Errorf("invalid download dir data: miss obj_id field.\n")
			return &appError{err, "", http.StatusBadRequest}
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
			return &appError{err, "", http.StatusBadRequest}
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
		err := fmt.Errorf("invalid download multi data, miss parent_dir field.\n")
		return nil, err
	}

	dir, err := fsmgr.GetSeafdirByPath(repo.StoreID, repo.RootID, parentDir)
	if err != nil {
		err := fmt.Errorf("failed to get dir %s repo %s.\n", parentDir, repo.StoreID)
		return nil, err
	}

	fileList, ok := obj["file_list"].([]interface{})
	if !ok || fileList == nil {
		err := fmt.Errorf("invalid download multi data, miss file_list field.\n")
		return nil, err
	}

	direntHash := make(map[string]fsmgr.SeafDirent)
	for _, v := range dir.Entries {
		direntHash[v.Name] = v
	}

	direntList := make([]fsmgr.SeafDirent, 0)

	for _, fileName := range fileList {
		name, ok := fileName.(string)
		if !ok {
			err := fmt.Errorf("invalid download multi data.\n")
			return nil, err
		}

		v, ok := direntHash[name]
		if !ok {
			err := fmt.Errorf("invalid download multi data.\n")
			return nil, err
		}

		direntList = append(direntList, v)
	}

	return direntList, nil
}

func packDir(ar *zip.Writer, repo *repomgr.Repo, dirID, dirPath string) error {
	dirent, err := fsmgr.GetSeafdir(repo.StoreID, dirID)
	if err != nil {
		err := fmt.Errorf("failed to get dir for zip: %v.\n", err)
		return err
	}

	if dirent.Entries == nil {
		fileDir := filepath.Join(dirPath)
		fileDir = strings.TrimLeft(fileDir, "/")
		_, err := ar.Create(fileDir + "/")
		if err != nil {
			err := fmt.Errorf("failed to create zip dir: %v.\n", err)
			return err
		}

		return nil
	}

	entries := dirent.Entries

	for _, v := range entries {
		fileDir := filepath.Join(dirPath, v.Name)
		fileDir = strings.TrimLeft(fileDir, "/")
		if fsmgr.IsDir(v.Mode) {
			fileHeader := new(zip.FileHeader)
			fileHeader.Name = fileDir + "/"
			fileHeader.Modified = time.Unix(v.Mtime, 0)
			_, err := ar.CreateHeader(fileHeader)
			if err != nil {
				err := fmt.Errorf("failed to create zip dir: %v.\n", err)
				return err
			}

			if err := packDir(ar, repo, v.ID, fileDir); err != nil {
				return err
			}
		} else {
			if err := packFiles(ar, &v, repo, dirPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func packFiles(ar *zip.Writer, dirent *fsmgr.SeafDirent, repo *repomgr.Repo, parentPath string) error {
	file, err := fsmgr.GetSeafile(repo.StoreID, dirent.ID)
	if err != nil {
		err := fmt.Errorf("failed to get seafile : %v.\n", err)
		return err
	}

	filePath := filepath.Join(parentPath, dirent.Name)
	filePath = strings.TrimLeft(filePath, "/")

	fileHeader := new(zip.FileHeader)
	fileHeader.Name = filePath
	fileHeader.Modified = time.Unix(dirent.Mtime, 0)
	zipFile, err := ar.CreateHeader(fileHeader)
	if err != nil {
		err := fmt.Errorf("failed to create zip file : %v.\n", err)
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

type webaccessInfo struct {
	repoID string
	objID  string
	op     string
	user   string
}

func parseWebaccessInfo(rsp http.ResponseWriter, token string) (*webaccessInfo, *appError) {
	webaccess, err := rpcclient.Call("seafile_web_query_access_token", token)
	if err != nil || webaccess == nil {
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
