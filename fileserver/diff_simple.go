package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

const (
	EMPTY_SHA1 = "0000000000000000000000000000000000000000"
)

type diffOptions struct {
	storeID string
	fileCB  diffFileCB
	dirCB   diffDirCB
	data    diffData
}

type diffData struct {
	results     *[]*diffEntry
	foldDirDiff bool
}

const (
	DIFF_TYPE_WORKTREE = 'W' /* diff from index to worktree */
	DIFF_TYPE_INDEX    = 'I' /* diff from commit to index */
	DIFF_TYPE_COMMITS  = 'C' /* diff between two commits*/

	DIFF_STATUS_ADDED       = 'A'
	DIFF_STATUS_DELETED     = 'D'
	DIFF_STATUS_MODIFIED    = 'M'
	DIFF_STATUS_RENAMED     = 'R'
	DIFF_STATUS_UNMERGED    = 'U'
	DIFF_STATUS_DIR_ADDED   = 'B'
	DIFF_STATUS_DIR_DELETED = 'C'
	DIFF_STATUS_DIR_RENAMED = 'E'
)

type diffEntry struct {
	diffType     rune
	status       rune
	unmergeState int
	dirID        string
	name         string
	newName      string
	size         int64
	originSize   int64
}

type diffFileCB func(n int, baseDir string, dents []*fsmgr.SeafDirent, data *diffData) error

type diffDirCB func(n int, baseDir string, dents []*fsmgr.SeafDirent, data *diffData, recurse *bool) error

func threewayDiffFiles(n int, baseDir string, dents []*fsmgr.SeafDirent, data *diffData) error {
	m := dents[0]
	p1 := dents[1]
	p2 := dents[2]
	results := data.results

	if m != nil && p1 != nil && p2 != nil {
		if !direntSame(m, p1) && !direntSame(m, p2) {
			de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED, m, baseDir)
			*results = append(*results, de)
		}
	} else if m == nil && p1 != nil && p2 != nil {
		de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_DELETED, p1, baseDir)
		*results = append(*results, de)
	} else if m != nil && p1 == nil && p2 != nil {
		if !direntSame(m, p2) {
			de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED, m, baseDir)
			*results = append(*results, de)
		}
	} else if m != nil && p1 != nil && p2 == nil {
		if !direntSame(m, p1) {
			de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED, m, baseDir)
			*results = append(*results, de)
		}
	} else if m != nil && p1 == nil && p2 == nil {
		de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_ADDED, m, baseDir)
		*results = append(*results, de)
	}

	return nil
}

func threewayDiffDirs(n int, baseDir string, dents []*fsmgr.SeafDirent, data *diffData, recurse *bool) error {
	*recurse = true
	return nil
}

func diffEntryNewFromDirent(diffType, status rune, dent *fsmgr.SeafDirent, baseDir string) *diffEntry {
	de := new(diffEntry)
	de.dirID = dent.ID
	de.diffType = diffType
	de.status = status
	de.size = dent.Size
	de.name = filepath.Join(baseDir, dent.Name)

	return de
}

func diffEntryNew(diffType, status rune, dirID, name string) *diffEntry {
	de := new(diffEntry)
	de.diffType = diffType
	de.status = status
	de.dirID = dirID
	de.name = name

	return de
}

func diffMergeRoots(storeID, mergedRoot, p1Root, p2Root string, results *[]*diffEntry, foldDirDiff bool) error {
	var roots []string
	roots = append(roots, p1Root)
	roots = append(roots, p2Root)

	opt := new(diffOptions)
	opt.storeID = storeID
	opt.fileCB = threewayDiffFiles
	opt.dirCB = threewayDiffDirs
	opt.data.results = results

	err := diffTrees(3, roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v.\n", err)
		return err
	}
	diffResolveRenames(results)

	return nil
}

func diffCommitRoots(storeID, p1Root, p2Root string, results *[]*diffEntry, foldDirDiff bool) error {
	var roots []string
	roots = append(roots, p1Root)
	roots = append(roots, p2Root)

	opt := new(diffOptions)
	opt.storeID = storeID
	opt.fileCB = twowayDiffFiles
	opt.dirCB = twowayDiffDirs
	opt.data.results = results
	opt.data.foldDirDiff = foldDirDiff

	err := diffTrees(2, roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v.\n", err)
		return err
	}
	diffResolveRenames(results)

	return nil
}

func diffCommits(commit1, commit2 *commitmgr.Commit, results *[]*diffEntry, foldDirDiff bool) error {
	repo := repomgr.Get(commit1.RepoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %s.\n", commit1.RepoID)
		return err
	}
	var roots []string
	roots = append(roots, commit1.RootID)
	roots = append(roots, commit2.RootID)

	opt := new(diffOptions)
	opt.storeID = repo.StoreID
	opt.fileCB = twowayDiffFiles
	opt.dirCB = twowayDiffDirs
	opt.data.results = results
	opt.data.foldDirDiff = foldDirDiff

	err := diffTrees(2, roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v.\n", err)
		return err
	}
	diffResolveRenames(results)

	return nil
}

func twowayDiffFiles(n int, baseDir string, dents []*fsmgr.SeafDirent, data *diffData) error {
	p1 := dents[0]
	p2 := dents[1]
	results := data.results

	if p1 == nil {
		de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_ADDED, p2, baseDir)
		*results = append(*results, de)
		return nil
	}

	if p2 == nil {
		de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_DELETED, p1, baseDir)
		*results = append(*results, de)
		return nil
	}

	if !direntSame(p1, p2) {
		de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED, p2, baseDir)
		de.originSize = p1.Size
		*results = append(*results, de)
	}

	return nil
}

func twowayDiffDirs(n int, baseDir string, dents []*fsmgr.SeafDirent, data *diffData, recurse *bool) error {
	p1 := dents[0]
	p2 := dents[1]
	results := data.results

	if p1 == nil {
		if p2.ID == EMPTY_SHA1 || data.foldDirDiff {
			de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_DIR_ADDED, p2, baseDir)
			*results = append(*results, de)
			*recurse = false
		} else {
			*recurse = true
		}

		return nil
	}

	if p2 == nil {
		de := diffEntryNewFromDirent(DIFF_TYPE_COMMITS, DIFF_STATUS_DIR_DELETED, p1, baseDir)
		de.originSize = p1.Size
		*results = append(*results, de)
		if data.foldDirDiff {
			*recurse = false
		} else {
			*recurse = true
		}
	}

	return nil
}

func diffResolveRenames(des *[]*diffEntry) error {
	var deletedEmptyCount, deletedEmptyDirCount, addedEmptyCount, addedEmptyDirCount int
	for _, de := range *des {
		if de.dirID == EMPTY_SHA1 {
			if de.status == DIFF_STATUS_DELETED {
				deletedEmptyCount++
			}
			if de.status == DIFF_STATUS_DIR_DELETED {
				deletedEmptyDirCount++
			}
			if de.status == DIFF_STATUS_ADDED {
				addedEmptyCount++
			}
			if de.status == DIFF_STATUS_DIR_ADDED {
				addedEmptyDirCount++
			}
		}
	}

	deletedFiles := make(map[string]*diffEntry)
	deletedDirs := make(map[string]*diffEntry)
	var added []*diffEntry

	checkEmptyDir := (deletedEmptyDirCount == 1 && addedEmptyDirCount == 1)
	checkEmptyFile := (deletedEmptyCount == 1 && addedEmptyCount == 1)

	for _, de := range *des {
		if de.status == DIFF_STATUS_DELETED {
			if de.dirID == EMPTY_SHA1 && !checkEmptyFile {
				continue
			}
			deletedFiles[de.dirID] = de
		}

		if de.status == DIFF_STATUS_DIR_DELETED {
			if de.dirID == EMPTY_SHA1 && !checkEmptyDir {
				continue
			}
			deletedDirs[de.dirID] = de
		}

		if de.status == DIFF_STATUS_ADDED {
			if de.dirID == EMPTY_SHA1 && !checkEmptyFile {
				continue
			}
			added = append(added, de)
		}

		if de.status == DIFF_STATUS_DIR_ADDED {
			if de.dirID == EMPTY_SHA1 && !checkEmptyDir {
				continue
			}

			added = append(added, de)
		}
	}

	for _, de := range added {
		var deAdd, deDel, deRename *diffEntry
		var renameStatus rune

		deAdd = de
		if deAdd.status == DIFF_STATUS_ADDED {
			deTmp, ok := deletedFiles[de.dirID]
			if !ok {
				continue
			}
			deDel = deTmp
		} else {
			deTmp, ok := deletedDirs[de.dirID]
			if !ok {
				continue
			}
			deDel = deTmp
		}

		if deAdd.status == DIFF_STATUS_DIR_ADDED {
			renameStatus = DIFF_STATUS_DIR_RENAMED
		} else {
			renameStatus = DIFF_STATUS_RENAMED
		}

		deRename = diffEntryNew(deDel.diffType, renameStatus, deDel.dirID, deDel.name)
		deRename.newName = de.name
		*des = removeElems(*des, deAdd)
		*des = removeElems(*des, deDel)
		*des = append(*des, deRename)
		if deDel.status == DIFF_STATUS_DIR_DELETED {
			delete(deletedDirs, deAdd.dirID)
		} else {
			delete(deletedFiles, deAdd.dirID)
		}
	}

	return nil
}

func removeElems(s []*diffEntry, e *diffEntry) []*diffEntry {
	for i, v := range s {
		if v == e {
			s = append(s[:i], s[i+1:]...)
			break
		}
	}

	return s
}

func diffTrees(n int, roots []string, opt *diffOptions) error {
	if n != 2 && n != 3 {
		err := fmt.Errorf("wrong diff number.\n")
		return err
	}
	if n != len(roots) {
		err := fmt.Errorf("invalid argument.\n")
		return err
	}

	var trees []*fsmgr.SeafDir
	for i := 0; i < n; i++ {
		dir, err := fsmgr.GetSeafdir(opt.storeID, roots[i])
		if err != nil {
			err := fmt.Errorf("failed to get dir: %v.\n", err)
			return err
		}
		trees = append(trees, dir)
	}

	err := diffTreesRecursive(n, trees, "", opt)
	if err != nil {
		err := fmt.Errorf("failed ot diff trees recursive: %v.\n", err)
		return err
	}
	return nil
}

func diffTreesRecursive(n int, trees []*fsmgr.SeafDir, baseDir string, opt *diffOptions) error {
	var ptrs [3][]*fsmgr.SeafDirent
	for i := 0; i < n; i++ {
		if trees[i] != nil {
			ptrs[i] = trees[i].Entries
		}
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

		for i := 0; i < n; i++ {
			entries := ptrs[i]
			if len(entries) != 0 {
				dent := entries[0]
				if firstName == dent.Name {
					ptrs[i] = ptrs[i][1:]
					dents[i] = dent
				}
			}
		}

		if n == 2 && dents[0] != nil && dents[1] != nil && direntSame(dents[0], dents[1]) {
			continue
		}

		if n == 3 && dents[0] != nil && dents[1] != nil && dents[2] != nil && direntSame(dents[0], dents[1]) && direntSame(dents[0], dents[2]) {
			continue
		}

		err := diffFiles(n, dents, baseDir, opt)
		if err != nil {
			err := fmt.Errorf("failed to diff files.\n")
			return err
		}

		err = diffDirectories(n, dents, baseDir, opt)
		if err != nil {
			err := fmt.Errorf("failed to diff directories.\n")
			return err
		}

	}

	return nil
}

func diffFiles(n int, dents []*fsmgr.SeafDirent, baseDir string, opt *diffOptions) error {
	var nFiles int
	files := make([]*fsmgr.SeafDirent, n)
	for i := 0; i < n; i++ {
		if dents[i] != nil && !fsmgr.IsDir(dents[i].Mode) {
			files[i] = dents[i]
			nFiles++
		}
	}

	if nFiles == 0 {
		return nil
	}

	return opt.fileCB(n, baseDir, files, &opt.data)
}

func diffDirectories(n int, dents []*fsmgr.SeafDirent, baseDir string, opt *diffOptions) error {
	var nDirs int
	var dirName string
	dirs := make([]*fsmgr.SeafDirent, n)
	subDirs := make([]*fsmgr.SeafDir, n)
	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dirs[i] = dents[i]
			nDirs++
		}
	}

	if nDirs == 0 {
		return nil
	}

	recurse := true
	err := opt.dirCB(n, baseDir, dirs, &opt.data, &recurse)
	if err != nil {
		err := fmt.Errorf("failed to call dir callback: %v.\n", err)
		return err
	}

	if !recurse {
		return nil
	}

	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dir, err := fsmgr.GetSeafdir(opt.storeID, dents[i].ID)
			if err != nil {
				err := fmt.Errorf("failed to find dir %s:%s.\n", opt.storeID, dents[i].ID)
				return err
			}
			subDirs[i] = dir
			dirName = dents[i].Name
		}
	}

	newBaseDir := filepath.Join(baseDir, dirName)
	newBaseDir = newBaseDir + "/"
	err = diffTreesRecursive(n, subDirs, newBaseDir, opt)
	if err != nil {
		err := fmt.Errorf("failed ot diff trees recursive: %v.\n", err)
		return err
	}

	return nil
}

func direntSame(denta *fsmgr.SeafDirent, dentb *fsmgr.SeafDirent) bool {
	return dentb.ID == denta.ID &&
		denta.Mode == dentb.Mode &&
		denta.Mtime == dentb.Mtime
}

func diffResultsToDesc(results []*diffEntry) string {
	var nAddMod, nRemoved, nRenamed int
	var nNewDir, nRemovedDir int
	var addModFile, removedFile string
	var renamedFile string
	var newDir, removedDir string
	var desc string

	if results == nil {
		return ""
	}

	for _, de := range results {
		switch de.status {
		case DIFF_STATUS_ADDED:
			if nAddMod == 0 {
				addModFile = getBaseName(de.name)
			}
			nAddMod++
		case DIFF_STATUS_DELETED:
			if nRemoved == 0 {
				removedFile = getBaseName(de.name)
			}
			nRemoved++
		case DIFF_STATUS_RENAMED:
			if nRenamed == 0 {
				renamedFile = getBaseName(de.name)
			}
			nRenamed++
		case DIFF_STATUS_MODIFIED:
			if nAddMod == 0 {
				addModFile = getBaseName(de.name)
			}
			nAddMod++
		case DIFF_STATUS_DIR_ADDED:
			if nNewDir == 0 {
				newDir = getBaseName(de.name)
			}
			nNewDir++
		case DIFF_STATUS_DIR_DELETED:
			if nRemovedDir == 0 {
				removedDir = getBaseName(de.name)
			}
			nRemovedDir++
		}
	}

	if nAddMod == 1 {
		desc = fmt.Sprintf("Added or modified \"%s\".\n", addModFile)
	} else if nAddMod > 1 {
		desc = fmt.Sprintf("Added or modified \"%s\" and %d more files.\n", addModFile, nAddMod-1)
	}

	if nRemoved == 1 {
		desc += fmt.Sprintf("Deleted \"%s\".\n", removedFile)
	} else if nRemoved > 1 {
		desc += fmt.Sprintf("Deleted \"%s\" and %d more files.\n", removedFile, nRemoved-1)
	}

	if nRenamed == 1 {
		desc += fmt.Sprintf("Renamed \"%s\".\n", renamedFile)
	} else if nRenamed > 1 {
		desc += fmt.Sprintf("Renamed \"%s\" and %d more files.\n", renamedFile, nRenamed-1)
	}

	if nNewDir == 1 {
		desc += fmt.Sprintf("Added directory \"%s\".\n", newDir)
	} else if nNewDir > 1 {
		desc += fmt.Sprintf("Added \"%s\" and %d more directories.\n", newDir, nNewDir-1)
	}

	if nRemovedDir == 1 {
		desc += fmt.Sprintf("Removed directory \"%s\".\n", removedDir)
	} else if nRemovedDir > 1 {
		desc += fmt.Sprintf("Removed \"%s\" and %d more directories.\n", removedDir, nRemovedDir-1)
	}

	return desc
}

func getBaseName(fileName string) string {
	slash := strings.Index(fileName, "/")
	if slash < 0 {
		return fileName
	}

	return fileName[slash+1:]
}
