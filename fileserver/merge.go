package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/option"
	"github.com/haiwen/seafile-server/fileserver/utils"
)

type mergeOptions struct {
	remoteRepoID    string
	remoteHead      string
	mergedRoot      string
	conflict        bool
	emailToNickname map[string]string
}

func mergeTrees(storeID string, roots []string, opt *mergeOptions) error {
	if len(roots) != 3 {
		err := fmt.Errorf("invalid argument")
		return err
	}

	opt.emailToNickname = make(map[string]string)

	var trees []*fsmgr.SeafDir
	for i := 0; i < 3; i++ {
		dir, err := fsmgr.GetSeafdir(storeID, roots[i])
		if err != nil {
			err := fmt.Errorf("failed to get dir: %v", err)
			return err
		}
		trees = append(trees, dir)
	}

	err := mergeTreesRecursive(storeID, trees, "", opt)
	if err != nil {
		err := fmt.Errorf("failed to merge trees: %v", err)
		return err
	}

	return nil
}

func mergeTreesRecursive(storeID string, trees []*fsmgr.SeafDir, baseDir string, opt *mergeOptions) error {
	var ptrs [3][]*fsmgr.SeafDirent
	var mergedDents []*fsmgr.SeafDirent

	n := 3
	for i := 0; i < n; i++ {
		if trees[i] != nil {
			ptrs[i] = trees[i].Entries
		}
	}

	var done bool
	var offset = make([]int, n)
	for {
		dents := make([]*fsmgr.SeafDirent, n)
		var firstName string
		done = true
		for i := 0; i < n; i++ {
			if len(ptrs[i]) > offset[i] {
				done = false
				dent := ptrs[i][offset[i]]
				if firstName == "" {
					firstName = dent.Name
				} else if dent.Name > firstName {
					firstName = dent.Name
				}
			}
		}

		if done {
			break
		}

		var nFiles, nDirs int
		for i := 0; i < n; i++ {
			if len(ptrs[i]) > offset[i] {
				dent := ptrs[i][offset[i]]
				if firstName == dent.Name {
					if fsmgr.IsDir(dent.Mode) {
						nDirs++
					} else {
						nFiles++
					}
					dents[i] = dent
					offset[i]++
				}
			}
		}

		if nFiles > 0 {
			retDents, err := mergeEntries(storeID, dents, baseDir, opt)
			if err != nil {
				return err
			}
			mergedDents = append(mergedDents, retDents...)
		}

		if nDirs > 0 {
			retDents, err := mergeDirectories(storeID, dents, baseDir, opt)
			if err != nil {
				return err
			}
			mergedDents = append(mergedDents, retDents...)
		}
	}

	sort.Sort(Dirents(mergedDents))
	mergedTree, err := fsmgr.NewSeafdir(1, mergedDents)
	if err != nil {
		err := fmt.Errorf("failed to new seafdir: %v", err)
		return err
	}

	opt.mergedRoot = mergedTree.DirID

	if trees[1] != nil && trees[1].DirID == mergedTree.DirID ||
		trees[2] != nil && trees[2].DirID == mergedTree.DirID {
		return nil
	}

	err = fsmgr.SaveSeafdir(storeID, mergedTree)
	if err != nil {
		err := fmt.Errorf("failed to save merged tree %s/%s", storeID, baseDir)
		return err
	}

	return nil
}

func mergeEntries(storeID string, dents []*fsmgr.SeafDirent, baseDir string, opt *mergeOptions) ([]*fsmgr.SeafDirent, error) {
	var mergedDents []*fsmgr.SeafDirent
	n := 3
	files := make([]*fsmgr.SeafDirent, n)

	for i := 0; i < n; i++ {
		if dents[i] != nil && !fsmgr.IsDir(dents[i].Mode) {
			files[i] = dents[i]
		}
	}

	base := files[0]
	head := files[1]
	remote := files[2]

	if head != nil && remote != nil {
		if head.ID == remote.ID {
			mergedDents = append(mergedDents, head)
		} else if base != nil && base.ID == head.ID {
			mergedDents = append(mergedDents, remote)
		} else if base != nil && base.ID == remote.ID {
			mergedDents = append(mergedDents, head)
		} else {
			conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, head.Name)
			if conflictName == "" {
				err := fmt.Errorf("failed to generate conflict file name")
				return nil, err
			}
			dents[2].Name = conflictName
			mergedDents = append(mergedDents, head)
			mergedDents = append(mergedDents, remote)
			opt.conflict = true
		}
	} else if base != nil && head == nil && remote != nil {
		if base.ID != remote.ID {
			if dents[1] != nil {
				conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, remote.Name)
				if conflictName == "" {
					err := fmt.Errorf("failed to generate conflict file name")
					return nil, err
				}
				dents[2].Name = conflictName
				mergedDents = append(mergedDents, remote)
				opt.conflict = true
			} else {
				mergedDents = append(mergedDents, remote)
			}
		}
	} else if base != nil && head != nil && remote == nil {
		if base.ID != head.ID {
			if dents[2] != nil {
				conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, dents[2].Name)
				if conflictName == "" {
					err := fmt.Errorf("failed to generate conflict file name")
					return nil, err
				}
				dents[2].Name = conflictName
				mergedDents = append(mergedDents, head)
				opt.conflict = true
			} else {
				mergedDents = append(mergedDents, head)
			}
		}
	} else if base == nil && head == nil && remote != nil {
		if dents[1] == nil {
			mergedDents = append(mergedDents, remote)
		} else if dents[0] != nil && dents[0].ID == dents[1].ID {
			mergedDents = append(mergedDents, remote)
		} else {
			conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, remote.Name)
			if conflictName == "" {
				err := fmt.Errorf("failed to generate conflict file name")
				return nil, err
			}
			dents[2].Name = conflictName
			mergedDents = append(mergedDents, remote)
			opt.conflict = true
		}
	} else if base == nil && head != nil && remote == nil {
		if dents[2] == nil {
			mergedDents = append(mergedDents, head)
		} else if dents[0] != nil && dents[0].ID == dents[2].ID {
			mergedDents = append(mergedDents, head)
		} else {
			conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, dents[2].Name)
			if conflictName == "" {
				err := fmt.Errorf("failed to generate conflict file name")
				return nil, err
			}
			dents[2].Name = conflictName
			mergedDents = append(mergedDents, head)
			opt.conflict = true
		}
	} /* else if base != nil && head == nil && remote == nil {
	    Don't need to add anything to mergeDents.
	}*/

	return mergedDents, nil
}

func mergeDirectories(storeID string, dents []*fsmgr.SeafDirent, baseDir string, opt *mergeOptions) ([]*fsmgr.SeafDirent, error) {
	var dirMask int
	var mergedDents []*fsmgr.SeafDirent
	var dirName string
	n := 3
	subDirs := make([]*fsmgr.SeafDir, n)
	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dirMask |= 1 << i
		}
	}

	switch dirMask {
	case 0:
		err := fmt.Errorf("no dirent for merge")
		return nil, err
	case 1:
		return mergedDents, nil
	case 2:
		mergedDents = append(mergedDents, dents[1])
		return mergedDents, nil
	case 3:
		if dents[0].ID == dents[1].ID {
			return mergedDents, nil
		}
	case 4:
		mergedDents = append(mergedDents, dents[2])
		return mergedDents, nil
	case 5:
		if dents[0].ID == dents[2].ID {
			return mergedDents, nil
		}
	case 6, 7:
		if dents[1].ID == dents[2].ID {
			mergedDents = append(mergedDents, dents[1])
			return mergedDents, nil
		} else if dents[0] != nil && dents[0].ID == dents[1].ID {
			mergedDents = append(mergedDents, dents[2])
			return mergedDents, nil
		} else if dents[0] != nil && dents[0].ID == dents[2].ID {
			mergedDents = append(mergedDents, dents[1])
			return mergedDents, nil
		}
	default:
		err := fmt.Errorf("wrong dir mask for merge")
		return nil, err
	}

	for i := 0; i < n; i++ {
		subDirs[i] = nil
	}

	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dir, err := fsmgr.GetSeafdir(storeID, dents[i].ID)
			if err != nil {
				err := fmt.Errorf("failed to get seafdir %s/%s", storeID, dents[i].ID)
				return nil, err
			}
			subDirs[i] = dir
			dirName = dents[i].Name
		}
	}

	newBaseDir := filepath.Join(baseDir, dirName)
	newBaseDir = newBaseDir + "/"
	err := mergeTreesRecursive(storeID, subDirs, newBaseDir, opt)
	if err != nil {
		err := fmt.Errorf("failed to merge trees: %v", err)
		return nil, err
	}

	if dirMask == 3 || dirMask == 6 || dirMask == 7 {
		dent := dents[1]
		dent.ID = opt.mergedRoot
		mergedDents = append(mergedDents, dent)
	} else if dirMask == 5 {
		dent := dents[2]
		dent.ID = opt.mergedRoot
		mergedDents = append(mergedDents, dent)
	}

	return mergedDents, nil
}

func mergeConflictFileName(storeID string, opt *mergeOptions, baseDir, fileName string) (string, error) {
	var modifier string
	var mtime int64
	filePath := filepath.Join(baseDir, fileName)
	modifier, mtime, err := getFileModifierMtime(opt.remoteRepoID, storeID, opt.remoteHead, filePath)
	if err != nil {
		commit, err := commitmgr.Load(opt.remoteRepoID, opt.remoteHead)
		if err != nil {
			err := fmt.Errorf("failed to get head commit")
			return "", err
		}
		modifier = commit.CreatorName
		mtime = time.Now().Unix()
	}

	nickname := getNickNameByModifier(opt.emailToNickname, modifier)

	conflictName := genConflictPath(fileName, nickname, mtime)

	return conflictName, nil
}

func genConflictPath(originPath, modifier string, mtime int64) string {
	var conflictPath string
	now := time.Now()
	timeBuf := now.Format("2006-Jan-2-15-04-05")
	dot := strings.Index(originPath, ".")
	if dot < 0 {
		if modifier != "" {
			conflictPath = fmt.Sprintf("%s (SFConflict %s %s)",
				originPath, modifier, timeBuf)
		} else {
			conflictPath = fmt.Sprintf("%s (SFConflict %s)",
				originPath, timeBuf)
		}
	} else {
		if modifier != "" {
			conflictPath = fmt.Sprintf("%s (SFConflict %s %s).%s",
				originPath, modifier, timeBuf, originPath[dot+1:])
		} else {
			conflictPath = fmt.Sprintf("%s (SFConflict %s).%s",
				originPath, timeBuf, originPath[dot+1:])
		}
	}

	return conflictPath
}

func getNickNameByModifier(emailToNickname map[string]string, modifier string) string {
	if modifier == "" {
		return ""
	}
	nickname, ok := emailToNickname[modifier]
	if ok {
		return nickname
	}
	if option.JWTPrivateKey != "" {
		nickname = postGetNickName(modifier)
	}

	if nickname == "" {
		nickname = modifier
	}

	emailToNickname[modifier] = nickname

	return nickname
}

func postGetNickName(modifier string) string {
	tokenString, err := utils.GenSeahubJWTToken()
	if err != nil {
		return ""
	}

	header := map[string][]string{
		"Authorization": {"Token " + tokenString},
	}

	data, err := json.Marshal(map[string]interface{}{
		"user_id_list": []string{modifier},
	})
	if err != nil {
		return ""
	}

	url := option.SeahubURL + "/user-list/"
	status, body, err := utils.HttpCommon("POST", url, header, bytes.NewReader(data))
	if err != nil {
		return ""
	}
	if status != http.StatusOK {
		return ""
	}

	results := make(map[string]interface{})
	err = json.Unmarshal(body, &results)
	if err != nil {
		return ""
	}

	userList, ok := results["user_list"].([]interface{})
	if !ok {
		return ""
	}
	nickname := ""
	for _, element := range userList {
		list, ok := element.(map[string]interface{})
		if !ok {
			continue
		}
		nickname, _ = list["name"].(string)
		if nickname != "" {
			break
		}
	}

	return nickname
}

func getFileModifierMtime(repoID, storeID, head, filePath string) (string, int64, error) {
	commit, err := commitmgr.Load(repoID, head)
	if err != nil {
		err := fmt.Errorf("failed to get head commit")
		return "", -1, err
	}

	parent := filepath.Dir(filePath)
	if parent == "." {
		parent = ""
	}

	fileName := filepath.Base(filePath)
	dir, err := fsmgr.GetSeafdirByPath(storeID, commit.RootID, parent)
	if err != nil {
		err := fmt.Errorf("dir %s doesn't exist in repo %s", parent, repoID)
		return "", -1, err
	}

	var dent *fsmgr.SeafDirent
	entries := dir.Entries
	for _, d := range entries {
		if d.Name == fileName {
			dent = d
			break
		}
	}

	if dent == nil {
		err := fmt.Errorf("file %s doesn't exist in repo %s", fileName, repoID)
		return "", -1, err
	}

	return dent.Modifier, dent.Mtime, nil
}
