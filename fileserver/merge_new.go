package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
)

type mergeOptions struct {
	nWays        int
	remoteRepoID string
	remoteHead   string
	doMerge      bool
	mergedRoot   string
	conflict     bool
}

func mergeTrees(storeID string, n int, roots []string, opt *mergeOptions) error {
	if n != 2 || n != 3 {
		err := fmt.Errorf("wrong merge number.\n")
		return err
	}
	if n != len(roots) {
		err := fmt.Errorf("invalid argument.\n")
		return err
	}

	var trees []*fsmgr.SeafDir
	for i := 0; i < n; i++ {
		dir, err := fsmgr.GetSeafdir(storeID, roots[i])
		if err != nil {
			err := fmt.Errorf("failed to get dir: %v.\n", err)
			return err
		}
		trees = append(trees, dir)
	}

	err := mergeTreesRecursive(storeID, n, trees, "", opt)
	if err != nil {
		err := fmt.Errorf("failed to merge trees: %v.\n", err)
		return err
	}

	return nil
}

func mergeTreesRecursive(storeID string, n int, trees []*fsmgr.SeafDir, baseDir string, opt *mergeOptions) error {
	var ptrs [][]fsmgr.SeafDirent
	var mergedDents []fsmgr.SeafDirent

	for i := 0; i < n; i++ {
		ptrs = append(ptrs, trees[i].Entries)
	}

	var done bool
	for {
		dents := make([]*fsmgr.SeafDirent, n)
		var firstName string
		done = true
		for i := 0; i < n; i++ {
			entries := ptrs[i]
			if len(entries) != 0 {
				done = false
				dent := entries[0]
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
			entries := ptrs[i]
			if len(entries) != 0 {
				dent := entries[0]
				if firstName == dent.Name {
					if fsmgr.IsDir(dent.Mode) {
						nDirs++
					} else {
						nFiles++
					}
					ptrs[i] = ptrs[i][1:]
					dents[i] = &dent
				}
			}
		}

		if nFiles > 0 {
			retDents, err := mergeEntries(storeID, n, dents, baseDir, opt)
			if err != nil {
				return err
			}
			mergedDents = append(mergedDents, retDents...)
		}

		if nDirs > 0 {
			retDents, err := mergeDirectories(storeID, n, dents, baseDir, opt)
			if err != nil {
				return err
			}
			mergedDents = append(mergedDents, retDents...)
		}
	}

	if n == 3 && opt.doMerge {
		sort.Sort(Dirents(mergedDents))
		mergedTree := new(fsmgr.SeafDir)
		mergedTree.Version = 1
		mergedTree.Entries = mergedDents
		jsonstr, err := json.Marshal(mergedTree)
		if err != nil {
			err := fmt.Errorf("failed to convert seafdir to json.\n")
			return err
		}
		checkSum := sha1.Sum(jsonstr)
		id := hex.EncodeToString(checkSum[:])
		mergedTree.DirID = id

		opt.mergedRoot = id

		if trees[1] != nil && trees[1].DirID == mergedTree.DirID ||
			trees[2] != nil && trees[2].DirID == mergedTree.DirID {
			return nil
		}

		err = fsmgr.SaveSeafdir(storeID, id, mergedTree)
		if err != nil {
			err := fmt.Errorf("failed to save merged tree %s/%s.\n", storeID, baseDir)
			return err
		}
	}

	return nil
}

func mergeEntries(storeID string, n int, dents []*fsmgr.SeafDirent, baseDir string, opt *mergeOptions) ([]fsmgr.SeafDirent, error) {
	var mergedDents []fsmgr.SeafDirent
	files := make([]*fsmgr.SeafDirent, n)

	for i := 0; i < n; i++ {
		if dents[i] != nil && !fsmgr.IsDir(dents[i].Mode) {
			files[i] = dents[i]
		}
	}

	if n == 2 || !opt.doMerge {
		return nil, nil
	}

	base := files[0]
	head := files[1]
	remote := files[2]

	if head != nil && remote != nil {
		if head.ID == remote.ID {
			mergedDents = append(mergedDents, *head)
		} else if base != nil && base.ID == head.ID {
			mergedDents = append(mergedDents, *remote)
		} else if base != nil && base.ID == remote.ID {
			mergedDents = append(mergedDents, *head)
		} else {
			conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, head.Name)
			if conflictName == "" {
				err := fmt.Errorf("failed to generate conflict file name.\n")
				return nil, err
			}
			dents[2].Name = conflictName
			mergedDents = append(mergedDents, *remote)
			opt.conflict = true
		}
	} else if base != nil && head == nil && remote != nil {
		if base.ID != remote.ID {
			if dents[1] != nil {
				conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, remote.Name)
				if conflictName == "" {
					err := fmt.Errorf("failed to generate conflict file name.\n")
					return nil, err
				}
				dents[2].Name = conflictName
				mergedDents = append(mergedDents, *remote)
				opt.conflict = true
			} else {
				mergedDents = append(mergedDents, *remote)
			}
		}
	} else if base != nil && head != nil && remote == nil {
		if base.ID != head.ID {
			if dents[2] != nil {
				conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, dents[2].Name)
				if conflictName == "" {
					err := fmt.Errorf("failed to generate conflict file name.\n")
					return nil, err
				}
				dents[2].Name = conflictName
				mergedDents = append(mergedDents, *head)
				opt.conflict = true
			} else {
				mergedDents = append(mergedDents, *head)
			}
		}
	} else if base == nil && head == nil && remote != nil {
		if dents[1] == nil {
			mergedDents = append(mergedDents, *remote)
		} else if dents[0] != nil && dents[0].ID == dents[1].ID {
			mergedDents = append(mergedDents, *remote)
		} else {
			conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, remote.Name)
			if conflictName == "" {
				err := fmt.Errorf("failed to generate conflict file name.\n")
				return nil, err
			}
			dents[2].Name = conflictName
			mergedDents = append(mergedDents, *remote)
			opt.conflict = true
		}
	} else if base == nil && head != nil && remote == nil {
		if dents[2] == nil {
			mergedDents = append(mergedDents, *head)
		} else if dents[0] != nil && dents[0].ID == dents[2].ID {
			mergedDents = append(mergedDents, *head)
		} else {
			conflictName, _ := mergeConflictFileName(storeID, opt, baseDir, dents[2].Name)
			if conflictName == "" {
				err := fmt.Errorf("failed to generate conflict file name.\n")
				return nil, err
			}
			dents[2].Name = conflictName
			mergedDents = append(mergedDents, *head)
			opt.conflict = true
		}
	} else if base != nil && head == nil && remote == nil {
	}

	return mergedDents, nil
}

func mergeDirectories(storeID string, n int, dents []*fsmgr.SeafDirent, baseDir string, opt *mergeOptions) ([]fsmgr.SeafDirent, error) {
	var dirMask int
	var mergedDents []fsmgr.SeafDirent
	var dirName string
	subDirs := make([]*fsmgr.SeafDir, n)
	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dirMask |= 1 << i
		}
	}

	if n == 3 && opt.doMerge {
		switch dirMask {
		case 0:
			err := fmt.Errorf("no dirent for merge.\n")
			return nil, err
		case 1:
			return mergedDents, nil
		case 2:
			mergedDents = append(mergedDents, *dents[1])
			return mergedDents, nil
		case 3:
			if dents[0].ID == dents[1].ID {
				return mergedDents, nil
			}
			break
		case 4:
			mergedDents = append(mergedDents, *dents[2])
			return mergedDents, nil
		case 5:
			if dents[0].ID == dents[2].ID {
				return mergedDents, nil
			}
			break
		case 6:
			if dents[1].ID == dents[2].ID {
				mergedDents = append(mergedDents, *dents[1])
			} else if dents[0] != nil && dents[0].ID == dents[1].ID {
				mergedDents = append(mergedDents, *dents[2])
			} else if dents[0] != nil && dents[0].ID == dents[2].ID {
				mergedDents = append(mergedDents, *dents[1])
			}
			break
		case 7:
			if dents[1].ID == dents[2].ID {
				mergedDents = append(mergedDents, *dents[1])
				return mergedDents, nil
			} else if dents[0] != nil && dents[0].ID == dents[1].ID {
				mergedDents = append(mergedDents, *dents[2])
				return mergedDents, nil
			} else if dents[0] != nil && dents[0].ID == dents[2].ID {
				mergedDents = append(mergedDents, *dents[1])
				return mergedDents, nil
			}
			break
		default:
			err := fmt.Errorf("wrong dir mask for merge.\n")
			return nil, err
		}
	}

	for i := 0; i < n; i++ {
		subDirs[i] = nil
	}

	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dir, err := fsmgr.GetSeafdir(storeID, dents[i].ID)
			if err != nil {
				err := fmt.Errorf("failed to get seafdir %s/%s.\n", storeID, dents[i].ID)
				return nil, err
			}
			subDirs[i] = dir
			dirName = dents[i].Name
		}
	}

	newBaseDir := filepath.Join(baseDir, dirName)
	newBaseDir = newBaseDir + "/"
	err := mergeTreesRecursive(storeID, n, subDirs, newBaseDir, opt)
	if err != nil {
		err := fmt.Errorf("failed to merge trees: %v.\n", err)
		return nil, err
	}

	if n == 3 && opt.doMerge {
		if dirMask == 3 || dirMask == 6 || dirMask == 7 {
			dent := *dents[1]
			dent.ID = opt.mergedRoot
			mergedDents = append(mergedDents, dent)
		} else if dirMask == 5 {
			dent := *dents[2]
			dent.ID = opt.mergedRoot
			mergedDents = append(mergedDents, dent)
		}
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
			err := fmt.Errorf("failed to get head commit.\n")
			return "", err
		}
		modifier = commit.CreatorName
		mtime = time.Now().Unix()
	}

	conflictName := genConflictPath(fileName, modifier, mtime)

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

func getFileModifierMtime(repoID, storeID, head, filePath string) (string, int64, error) {
	commit, err := commitmgr.Load(repoID, head)
	if err != nil {
		err := fmt.Errorf("failed to get head commit.\n")
		return "", -1, err
	}

	parent := filepath.Dir(filePath)
	if parent == "." {
		parent = ""
	}

	fileName := filepath.Base(filePath)
	dir, err := fsmgr.GetSeafdirByPath(storeID, commit.RootID, parent)
	if err != nil {
		err := fmt.Errorf("dir %s doesn't exist in repo %s.\n", parent, repoID)
		return "", -1, err
	}

	var dent *fsmgr.SeafDirent
	entries := dir.Entries
	for _, d := range entries {
		if d.Name == fileName {
			dent = &d
			break
		}
	}

	if dent == nil {
		err := fmt.Errorf("file %s doesn't exist in repo %s.\n", fileName, repoID)
		return "", -1, err
	}

	return dent.Modifier, dent.Mtime, nil
}
