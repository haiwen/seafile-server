package main

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/haiwen/seafile-server/fileserver/blockmgr"
	"github.com/haiwen/seafile-server/fileserver/commitmgr"
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
		return nil, &appError{nil, errMessage, http.StatusBadRequest}
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
		err := fmt.Errorf("wrong operation of token: %s.\n", op)
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
		err := fmt.Errorf("failed to parse obj data for zip: %v.\n", err)
		return &appError{err, "", http.StatusInternalServerError}
	}

	ar := zip.NewWriter(rsp)
	defer ar.Close()

	if op == "download-dir" || op == "download-dir-link" {
		dirName, ok := obj["dir_name"].(string)
		if !ok || dirName == "" {
			err := fmt.Errorf("invalid download dir data: miss dir_name field.\n")
			return &appError{err, "", http.StatusInternalServerError}
		}

		objID, ok := obj["obj_id"].(string)
		if !ok || objID == "" {
			err := fmt.Errorf("invalid download dir data: miss obj_id field.\n")
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
	fileHeader.Method = zip.Deflate
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

type recvFSM struct {
	parentDir string
	tokenType string
	repoID    string
	user      string
	rstart    int64
	rend      int64
	fsize     int64
	fileNames []string
	files     []string
}

func uploadApiCB(rsp http.ResponseWriter, r *http.Request) *appError {
	fsm, err := parseUploadHeaders(rsp, r)
	if err != nil {
		return err
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return &appError{nil, "", http.StatusBadRequest}
	}

	if err := doUpload(rsp, r, fsm, false); err != nil {
		return err
	}

	return nil
}

func uploadAjaxCB(rsp http.ResponseWriter, r *http.Request) *appError {
	fsm, err := parseUploadHeaders(rsp, r)
	if err != nil {
		return err
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return &appError{nil, "", http.StatusBadRequest}
	}

	if err := doUpload(rsp, r, fsm, true); err != nil {
		return err
	}

	return nil
}

func doUpload(rsp http.ResponseWriter, r *http.Request, fsm *recvFSM, isAjax bool) *appError {
	rsp.Header().Set("Access-Control-Allow-Origin", "*")
	rsp.Header().Set("Access-Control-Allow-Headers", "x-requested-with, content-type, content-range, content-disposition, accept, origin, authorization")
	rsp.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	rsp.Header().Set("Access-Control-Max-Age", "86400")

	if r.Method == "OPTIONS" {
		rsp.WriteHeader(http.StatusOK)
		return nil
	}

	repoID := fsm.repoID
	user := fsm.user

	formValues, err := parseFormValue(r)
	if err != nil {
		msg := "Invalid form data.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return errReply
	}

	replaceStr, ok := formValues["replace"]
	var replaceExisted int64
	if ok && replaceStr != `` {
		replace, err := strconv.ParseInt(replaceStr, 10, 64)
		if err != nil || (replace != 0 && replace != 1) {
			msg := "Invalid argument.\n"
			errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
			return errReply
		}
		replaceExisted = replace
	}

	parentDir, ok := formValues["parent_dir"]
	if !ok || parentDir == "" {
		msg := "Invalid URL.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return errReply
	}

	relativePath, ok := formValues["relative_path"]
	if ok && relativePath != "" {
		if relativePath[0] == '/' || relativePath[0] == '\\' {
			msg := "Invalid relative path"
			errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
			return errReply
		}
	}

	newParentDir := filepath.Join("/", parentDir, relativePath)

	if fsm.rstart >= 0 {
		if parentDir[0] != '/' {
			msg := "Invalid parent dir"
			errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
			return errReply
		}

		formFiles := r.MultipartForm.File
		files, ok := formFiles["file"]
		if !ok {
			msg := "Internal server.\n"
			errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
			errReply.Error = fmt.Errorf("failed to get file from multipart form.\n")
			return errReply
		}

		if len(files) > 1 {
			msg := "More files in one request"
			errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
			return errReply
		}

		err := writeBlockDataToTmpFile(r, fsm, formFiles, repoID, newParentDir)
		if err != nil {
			msg := "Internal error.\n"
			errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
			errReply.Error = fmt.Errorf("failed to write block data to tmp file: %v.\n", err)
			return errReply
		}

		if fsm.rend != fsm.fsize-1 {
			success := "{\"success\": true}"
			_, err := rsp.Write([]byte(success))
			if err != nil {
				log.Printf("failed to write data to response.\n")
			}
			accept, ok := r.Header["Accept"]
			if ok && strings.Index(strings.Join(accept, ""), "application/json") != -1 {
				rsp.Header().Set("Content-Type", "application/json; charset=utf-8")
			} else {
				rsp.Header().Set("Content-Type", "text/plain")
			}

			return nil
		}
	} else {
		formFiles := r.MultipartForm.File
		err := writeBlockDataToTmpFile(r, fsm, formFiles, repoID, newParentDir)
		if err != nil {
			msg := "Internal error.\n"
			errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
			errReply.Error = fmt.Errorf("failed to write block data to tmp file: %v.\n", err)
			return errReply
		}
	}

	if err := checkParentDir(rsp, repoID, parentDir); err != nil {
		clearTmpFile(fsm, newParentDir)
		return err
	}

	if !isParentMatched(fsm.parentDir, parentDir) {
		clearTmpFile(fsm, newParentDir)
		msg := "Permission denied."
		errReply := sendErrorReply(rsp, msg, http.StatusForbidden)
		return errReply
	}

	if err := checkTmpFileList(rsp, fsm.files); err != nil {
		clearTmpFile(fsm, newParentDir)
		return err
	}

	var contentLen int64
	if fsm.fsize > 0 {
		contentLen = fsm.fsize
	} else {
		lenstr := rsp.Header().Get("Content-Length")
		if lenstr == `` {
			contentLen = -1
		} else {
			tmpLen, err := strconv.ParseInt(lenstr, 10, 64)
			if err != nil {
				msg := "Internal error.\n"
				errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
				errReply.Error = fmt.Errorf("failed to parse content len: %v.\n", err)
				return errReply
			}
			contentLen = tmpLen
		}
	}

	if err := checkQuota(rsp, repoID, contentLen); err != nil {
		clearTmpFile(fsm, newParentDir)
		return err
	}

	if err := createRelativePath(rsp, repoID, parentDir, relativePath, user); err != nil {
		clearTmpFile(fsm, newParentDir)
		return err
	}

	fileNamesJson, err := json.Marshal(fsm.fileNames)
	if err != nil {
		clearTmpFile(fsm, newParentDir)
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("failed to encode file names to json: %v.\n", err)
		return errReply
	}
	tmpFilesJson, err := json.Marshal(fsm.files)
	if err != nil {
		clearTmpFile(fsm, newParentDir)
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("failed to encode temp files to json: %v.\n", err)
		return errReply
	}

	if err := postMultiFiles(rsp, r, repoID, newParentDir, user, string(fileNamesJson),
		string(tmpFilesJson), replaceExisted, isAjax); err != nil {
		return err
	}

	rsp.Header().Set("Content-Type", "application/json; charset=utf-8")

	oper := "web-file-upload"
	if fsm.tokenType == "upload-link" {
		oper = "link-file-upload"
	}
	err = sendStatisticMsg(repoID, user, oper, contentLen)
	if err != nil {
		clearTmpFile(fsm, newParentDir)
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("failed to send statistic message: %v.\n", err)
		return errReply
	}

	clearTmpFile(fsm, newParentDir)

	return nil
}

func clearTmpFile(fsm *recvFSM, parentDir string) {
	if fsm.rstart >= 0 && fsm.rend == fsm.fsize-1 {
		filePath := filepath.Join("/", parentDir, fsm.fileNames[0])
		tmpFile, err := repomgr.GetUploadTmpFile(fsm.repoID, filePath)
		if err == nil && tmpFile != `` {
			os.Remove(tmpFile)
		}
		repomgr.DelUploadTmpFile(fsm.repoID, filePath)
	}

	return
}

func sendStatisticMsg(repoID, user, eType string, bytes int64) error {
	buf := fmt.Sprintf("%s\t%s\t%s\t%d",
		eType, user, repoID, bytes)
	if _, err := rpcclient.Call("publish_event", "seaf_server.stats", buf); err != nil {
		return err
	}

	return nil
}

func parseUploadHeaders(rsp http.ResponseWriter, r *http.Request) (*recvFSM, *appError) {
	parts := strings.Split(r.URL.Path[1:], "/")
	if len(parts) < 2 {
		msg := "Invalid URL"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return nil, errReply
	}
	urlOp := parts[0]
	token := parts[1]

	accessInfo, appErr := parseWebaccessInfo(rsp, token)
	if appErr != nil {
		msg := "Access denied"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return nil, errReply
	}

	repoID := accessInfo.repoID
	op := accessInfo.op
	user := accessInfo.user
	id := accessInfo.objID

	status, err := repomgr.GetRepoStatus(repoID)
	if err != nil {
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		return nil, errReply
	}
	if status != 0 && status != -1 {
		msg := "Access denied"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return nil, errReply
	}

	if op == "upload-link" {
		op = "upload"
	}
	if strings.Index(urlOp, op) != 0 {
		msg := "Access denied"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return nil, errReply
	}

	obj := make(map[string]interface{})
	if err := json.Unmarshal([]byte(id), &obj); err != nil {
		err := fmt.Errorf("failed to decode obj data : %v.\n", err)
		return nil, &appError{err, "", http.StatusBadRequest}
	}

	parentDir, ok := obj["parent_dir"].(string)
	if !ok || parentDir == `` {
		msg := "Invalid URL"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return nil, errReply
	}

	fsm := new(recvFSM)

	fsm.parentDir = parentDir
	fsm.tokenType = accessInfo.op
	fsm.repoID = repoID
	fsm.user = user
	fsm.rstart = -1
	fsm.rend = -1
	fsm.fsize = -1

	ranges := r.Header.Get("Content-Range")
	if ranges != `` {
		parseContentRange(ranges, fsm)
	}

	return fsm, nil
}

func sendErrorReply(rsp http.ResponseWriter, errMsg string, code int) *appError {
	rsp.Header().Set("Content-Type", "application/json; charset=utf-8")

	msg := fmt.Sprintf("\"error\": \"%s\"", errMsg)
	return &appError{nil, msg, code}
}

func postMultiFiles(rsp http.ResponseWriter, r *http.Request, repoID, parentDir, user, fileNames, paths string, replaceExisted int64, isAjax bool) *appError {
	ret, err := rpcclient.Call("seafile_post_multi_files", repoID, parentDir, fileNames, paths, user, replaceExisted)
	if err != nil {
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("failed to call post multi files rpc: %v.\n", err)
		return errReply
	}

	retStr, ok := ret.(string)
	if !ok {
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("failed to assert returned data.\n")
		return errReply
	}
	_, ok = r.Form["ret-json"]
	if ok || isAjax {
		rsp.Write([]byte(retStr))
	} else {
		var array []map[string]interface{}
		err := json.Unmarshal([]byte(retStr), &array)
		if err != nil {
			msg := "Internal error.\n"
			errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
			errReply.Error = fmt.Errorf("failed to decode data to json: %v.\n", err)
			return errReply
		}

		var ids []string
		for _, v := range array {
			id, ok := v["id"].(string)
			if !ok {
				msg := "Internal error.\n"
				errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
				errReply.Error = fmt.Errorf("failed to assert.\n")
				return errReply
			}
			ids = append(ids, id)
		}
		newIDs := strings.Join(ids, "\t")
		rsp.Write([]byte(newIDs))
	}

	return nil
}

func checkQuota(rsp http.ResponseWriter, repoID string, contentLen int64) *appError {
	ret, err := rpcclient.Call("check_quota", repoID, contentLen)
	if err != nil {
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("failed to call check quota rpc: %v.\n", err)
		return errReply
	}
	if int(ret.(float64)) != 0 {
		msg := "Out of quota.\n"
		errReply := sendErrorReply(rsp, msg, 443)
		return errReply
	}

	return nil
}

func createRelativePath(rsp http.ResponseWriter, repoID, parentDir, relativePath, user string) *appError {
	if relativePath == `` {
		return nil
	}

	rc, err := rpcclient.Call("seafile_mkdir_with_parents", repoID, parentDir, relativePath, user)
	if err != nil || int(rc.(float64)) < 0 {
		msg := "Internal error.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("[upload folder] %v.\n", err)
		return errReply
	}

	return nil
}

func checkTmpFileList(rsp http.ResponseWriter, fileNames []string) *appError {
	var totalSize int64
	for _, tmpFile := range fileNames {
		fileInfo, err := os.Stat(tmpFile)
		if err != nil {
			msg := "Internal error.\n"
			errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
			errReply.Error = fmt.Errorf("[upload] Failed to stat temp file %s.\n", tmpFile)
			return errReply
		}
		totalSize += fileInfo.Size()
	}

	if options.maxUploadSize > 0 && uint64(totalSize) > options.maxUploadSize {
		msg := "File size is too large.\n"
		errReply := sendErrorReply(rsp, msg, 442)
		return errReply
	}

	return nil
}

func parseFormValue(r *http.Request) (map[string]string, error) {
	formValue := make(map[string]string)

	formFiles := r.MultipartForm.File
	for name, fileHeaders := range formFiles {
		if name != "parent_dir" && name != "relative_path" && name != "replace" {
			continue
		}
		if len(fileHeaders) > 1 {
			err := fmt.Errorf("wrong multipart form data.\n")
			return nil, err
		}
		for _, handler := range fileHeaders {
			file, err := handler.Open()
			if err != nil {
				err := fmt.Errorf("failed to open file for read: %v.\n", err)
				return nil, err
			}
			defer file.Close()

			var buf bytes.Buffer
			_, err = buf.ReadFrom(file)
			if err != nil {
				err := fmt.Errorf("failed to read file: %v.\n", err)
				return nil, err
			}
			formValue[name] = buf.String()
		}
	}
	return formValue, nil
}

func writeBlockDataToTmpFile(r *http.Request, fsm *recvFSM, formFiles map[string][]*multipart.FileHeader,
	repoID, parentDir string) error {
	httpTempDir := filepath.Join(absDataDir, "httptemp")

	for name, fileHeaders := range formFiles {
		if name != "file" {
			continue
		}
		if fsm.rstart < 0 {
			for _, handler := range fileHeaders {
				file, err := handler.Open()
				if err != nil {
					err := fmt.Errorf("failed to open file for read: %v.\n", err)
					return err
				}
				defer file.Close()

				fileName := filepath.Base(handler.Filename)
				tmpFile, err := ioutil.TempFile(httpTempDir, fileName)
				if err != nil {
					err := fmt.Errorf("failed to create temp file: %v.\n", err)
					return err
				}

				io.Copy(tmpFile, file)

				fsm.fileNames = append(fsm.fileNames, fileName)
				fsm.files = append(fsm.files, tmpFile.Name())

			}

			return nil
		}

		disposition := r.Header.Get("Content-Disposition")
		if disposition == "" {
			err := fmt.Errorf("missing content disposition.\n")
			return err
		}
		_, params, err := mime.ParseMediaType(disposition)
		if err != nil {
			return err
		}
		filename := params["filename"]
		for _, handler := range fileHeaders {
			file, err := handler.Open()
			if err != nil {
				err := fmt.Errorf("failed to open file for read: %v.\n", err)
				return err
			}
			defer file.Close()

			var f *os.File
			filePath := filepath.Join("/", parentDir, filename)
			tmpFile, err := repomgr.GetUploadTmpFile(repoID, filePath)
			if err != nil || tmpFile == `` {
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
		}

	}

	return nil
}

func checkParentDir(rsp http.ResponseWriter, repoID string, parentDir string) *appError {
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "Failed to get repo.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("Failed to get repo %s", repoID)
		return errReply
	}

	commit, err := commitmgr.Load(repoID, repo.HeadCommitID)
	if err != nil {
		msg := "Failed to get head commit.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusInternalServerError)
		errReply.Error = fmt.Errorf("Failed to get head commit for repo %s", repoID)
		return errReply
	}

	canonPath := filepath.Join("/", parentDir)

	_, err = fsmgr.GetSeafdirByPath(repo.StoreID, commit.RootID, canonPath)
	if err != nil {
		msg := "Parent dir doesn't exist.\n"
		errReply := sendErrorReply(rsp, msg, http.StatusBadRequest)
		return errReply
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

func parseContentRange(ranges string, fsm *recvFSM) bool {
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

func parseWebaccessInfo(rsp http.ResponseWriter, token string) (*webaccessInfo, *appError) {
	webaccess, err := rpcclient.Call("seafile_web_query_access_token", token)
	if err != nil {
		err := fmt.Errorf("failed to get web access token: %v.\n", err)
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
