package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

// Empty value of sha1
const (
	EmptySha1 = "0000000000000000000000000000000000000000"
)

type fileCB func(string, []*fsmgr.SeafDirent, *diffData) error
type dirCB func(string, []*fsmgr.SeafDirent, *diffData, *bool) error

type diffOptions struct {
	fileCB fileCB
	dirCB  dirCB
	repoID string
	data   diffData
}

type diffData struct {
	foldDirDiff bool
	results     *[]interface{}
}

func diffTrees(roots []string, opt *diffOptions) error {
	n := len(roots)
	if n != 2 && n != 3 {
		err := fmt.Errorf("the number of commit trees is illegal")
		return err
	}
	trees := make([]*fsmgr.SeafDir, n)
	for i := 0; i < n; i++ {
		root, err := fsmgr.GetSeafdir(opt.repoID, roots[i])
		if err != nil {
			err := fmt.Errorf("Failed to find dir %s:%s", opt.repoID, roots[i])
			return err
		}
		trees[i] = root
	}

	return diffTreesRecursive(trees, "", opt)
}

func diffTreesRecursive(trees []*fsmgr.SeafDir, baseDir string, opt *diffOptions) error {
	n := len(trees)
	ptrs := make([][]*fsmgr.SeafDirent, 3)
	dents := make([]*fsmgr.SeafDirent, 3)

	for i := 0; i < n; i++ {
		if trees[i] != nil {
			ptrs[i] = trees[i].Entries
		} else {
			ptrs[i] = nil
		}
	}

	var firstName string
	var done bool
	var offset = make([]int, n)
	for {
		firstName = ""
		done = true
		for i := 0; i < n; i++ {
			if len(ptrs[i]) > offset[i] {
				done = false
				dent := ptrs[i][offset[i]]

				if firstName == "" {
					firstName = dent.Name
				} else if strings.Compare(dent.Name, firstName) > 0 {
					firstName = dent.Name
				}
			}

		}
		if done {
			break
		}

		for i := 0; i < n; i++ {
			if len(ptrs[i]) > offset[i] {
				dent := ptrs[i][offset[i]]
				if firstName == dent.Name {
					dents[i] = dent
					offset[i]++
				}

			}
		}

		if n == 2 && dents[0] != nil && dents[1] != nil &&
			direntSame(dents[0], dents[1]) {
			continue
		}
		if n == 3 && dents[0] != nil && dents[1] != nil &&
			dents[2] != nil && direntSame(dents[0], dents[1]) &&
			direntSame(dents[0], dents[2]) {
			continue
		}

		if err := diffFiles(baseDir, dents, opt); err != nil {
			return err
		}
		if err := diffDirectories(baseDir, dents, opt); err != nil {
			return err
		}
	}
	return nil
}

func diffFiles(baseDir string, dents []*fsmgr.SeafDirent, opt *diffOptions) error {
	n := len(dents)
	var nFiles int
	files := make([]*fsmgr.SeafDirent, 3)
	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsRegular(dents[i].Mode) {
			files[i] = dents[i]
			nFiles++
		}
	}

	if nFiles == 0 {
		return nil
	}

	return opt.fileCB(baseDir, files, &opt.data)
}

func diffDirectories(baseDir string, dents []*fsmgr.SeafDirent, opt *diffOptions) error {
	n := len(dents)
	dirs := make([]*fsmgr.SeafDirent, 3)
	subDirs := make([]*fsmgr.SeafDir, 3)
	var nDirs int
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
	err := opt.dirCB(baseDir, dirs, &opt.data, &recurse)
	if err != nil {
		err := fmt.Errorf("failed to call dir callback: %v", err)
		return err
	}

	if !recurse {
		return nil
	}

	var dirName string
	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dir, err := fsmgr.GetSeafdir(opt.repoID, dents[i].ID)
			if err != nil {
				err := fmt.Errorf("Failed to find dir %s:%s", opt.repoID, dents[i].ID)
				return err
			}
			subDirs[i] = dir
			dirName = dents[i].Name
		}
	}

	newBaseDir := baseDir + "/" + dirName
	return diffTreesRecursive(subDirs, newBaseDir, opt)
}

func direntSame(dentA, dentB *fsmgr.SeafDirent) bool {
	return dentA.ID == dentB.ID &&
		dentA.Mode == dentB.Mode &&
		dentA.Mtime == dentA.Mtime
}

// Diff type and diff status.
const (
	DiffTypeWorktree = 'W' /* diff from index to worktree */
	DiffTypeIndex    = 'I' /* diff from commit to index */
	DiffTypeCommits  = 'C' /* diff between two commits*/

	DiffStatusAdded      = 'A'
	DiffStatusDeleted    = 'D'
	DiffStatusModified   = 'M'
	DiffStatusRenamed    = 'R'
	DiffStatusUnmerged   = 'U'
	DiffStatusDirAdded   = 'B'
	DiffStatusDirDeleted = 'C'
	DiffStatusDirRenamed = 'E'
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

func diffMergeRoots(storeID, mergedRoot, p1Root, p2Root string, results *[]interface{}, foldDirDiff bool) error {
	roots := []string{p1Root, p2Root}

	opt := new(diffOptions)
	opt.repoID = storeID
	opt.fileCB = threewayDiffFiles
	opt.dirCB = threewayDiffDirs
	opt.data.results = results

	err := diffTrees(roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v", err)
		return err
	}
	diffResolveRenames(results)

	return nil
}

func threewayDiffFiles(baseDir string, dents []*fsmgr.SeafDirent, data *diffData) error {
	m := dents[0]
	p1 := dents[1]
	p2 := dents[2]
	results := data.results

	if m != nil && p1 != nil && p2 != nil {
		if !direntSame(m, p1) && !direntSame(m, p2) {
			de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusModified, m, baseDir)
			*results = append(*results, de)
		}
	} else if m == nil && p1 != nil && p2 != nil {
		de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusDeleted, p1, baseDir)
		*results = append(*results, de)
	} else if m != nil && p1 == nil && p2 != nil {
		if !direntSame(m, p2) {
			de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusModified, m, baseDir)
			*results = append(*results, de)
		}
	} else if m != nil && p1 != nil && p2 == nil {
		if !direntSame(m, p1) {
			de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusModified, m, baseDir)
			*results = append(*results, de)
		}
	} else if m != nil && p1 == nil && p2 == nil {
		de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusAdded, m, baseDir)
		*results = append(*results, de)
	}

	return nil
}

func threewayDiffDirs(baseDir string, dents []*fsmgr.SeafDirent, data *diffData, recurse *bool) error {
	*recurse = true
	return nil
}

func diffCommitRoots(storeID, p1Root, p2Root string, results *[]interface{}, foldDirDiff bool) error {
	roots := []string{p1Root, p2Root}

	opt := new(diffOptions)
	opt.repoID = storeID
	opt.fileCB = twowayDiffFiles
	opt.dirCB = twowayDiffDirs
	opt.data.results = results
	opt.data.foldDirDiff = foldDirDiff

	err := diffTrees(roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v", err)
		return err
	}
	diffResolveRenames(results)

	return nil
}

func diffCommits(commit1, commit2 *commitmgr.Commit, results *[]interface{}, foldDirDiff bool) error {
	repo := repomgr.Get(commit1.RepoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %s", commit1.RepoID)
		return err
	}
	roots := []string{commit1.RootID, commit2.RootID}

	opt := new(diffOptions)
	opt.repoID = repo.StoreID
	opt.fileCB = twowayDiffFiles
	opt.dirCB = twowayDiffDirs
	opt.data.results = results
	opt.data.foldDirDiff = foldDirDiff

	err := diffTrees(roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v", err)
		return err
	}
	diffResolveRenames(results)

	return nil
}

func twowayDiffFiles(baseDir string, dents []*fsmgr.SeafDirent, data *diffData) error {
	p1 := dents[0]
	p2 := dents[1]
	results := data.results

	if p1 == nil {
		de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusAdded, p2, baseDir)
		*results = append(*results, de)
		return nil
	}

	if p2 == nil {
		de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusDeleted, p1, baseDir)
		*results = append(*results, de)
		return nil
	}

	if !direntSame(p1, p2) {
		de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusModified, p2, baseDir)
		de.originSize = p1.Size
		*results = append(*results, de)
	}

	return nil
}

func twowayDiffDirs(baseDir string, dents []*fsmgr.SeafDirent, data *diffData, recurse *bool) error {
	p1 := dents[0]
	p2 := dents[1]
	results := data.results

	if p1 == nil {
		if p2.ID == EmptySha1 || data.foldDirDiff {
			de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusDirAdded, p2, baseDir)
			*results = append(*results, de)
			*recurse = false
		} else {
			*recurse = true
		}

		return nil
	}

	if p2 == nil {
		de := diffEntryNewFromDirent(DiffTypeCommits, DiffStatusDirDeleted, p1, baseDir)
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

func diffResolveRenames(des *[]interface{}) error {
	var deletedEmptyCount, deletedEmptyDirCount, addedEmptyCount, addedEmptyDirCount int
	for _, v := range *des {
		de, ok := v.(*diffEntry)
		if !ok {
			err := fmt.Errorf("failed to assert diff entry")
			return err
		}
		if de.dirID == EmptySha1 {
			if de.status == DiffStatusDeleted {
				deletedEmptyCount++
			}
			if de.status == DiffStatusDirDeleted {
				deletedEmptyDirCount++
			}
			if de.status == DiffStatusAdded {
				addedEmptyCount++
			}
			if de.status == DiffStatusDirAdded {
				addedEmptyDirCount++
			}
		}
	}

	deletedFiles := make(map[string]*diffEntry)
	deletedDirs := make(map[string]*diffEntry)
	var added []*diffEntry

	checkEmptyDir := (deletedEmptyDirCount == 1 && addedEmptyDirCount == 1)
	checkEmptyFile := (deletedEmptyCount == 1 && addedEmptyCount == 1)

	for _, v := range *des {
		de, ok := v.(*diffEntry)
		if !ok {
			err := fmt.Errorf("failed to assert diff entry")
			return err
		}
		if de.status == DiffStatusDeleted {
			if de.dirID == EmptySha1 && !checkEmptyFile {
				continue
			}
			deletedFiles[de.dirID] = de
		}

		if de.status == DiffStatusDirDeleted {
			if de.dirID == EmptySha1 && !checkEmptyDir {
				continue
			}
			deletedDirs[de.dirID] = de
		}

		if de.status == DiffStatusAdded {
			if de.dirID == EmptySha1 && !checkEmptyFile {
				continue
			}
			added = append(added, de)
		}

		if de.status == DiffStatusDirAdded {
			if de.dirID == EmptySha1 && !checkEmptyDir {
				continue
			}

			added = append(added, de)
		}
	}

	for _, de := range added {
		var deAdd, deDel, deRename *diffEntry
		var renameStatus rune

		deAdd = de
		if deAdd.status == DiffStatusAdded {
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

		if deAdd.status == DiffStatusDirAdded {
			renameStatus = DiffStatusDirRenamed
		} else {
			renameStatus = DiffStatusRenamed
		}

		deRename = diffEntryNew(deDel.diffType, renameStatus, deDel.dirID, deDel.name)
		deRename.newName = de.name
		*des = removeElems(*des, deAdd)
		*des = removeElems(*des, deDel)
		*des = append(*des, deRename)
		if deDel.status == DiffStatusDirDeleted {
			delete(deletedDirs, deAdd.dirID)
		} else {
			delete(deletedFiles, deAdd.dirID)
		}
	}

	return nil
}

func removeElems(s []interface{}, e *diffEntry) []interface{} {
	for i, v := range s {
		de, ok := v.(*diffEntry)
		if !ok {
			continue
		}
		if de == e {
			s = append(s[:i], s[i+1:]...)
			break
		}
	}

	return s
}

func diffResultsToDesc(results []interface{}) string {
	var nAddMod, nRemoved, nRenamed int
	var nNewDir, nRemovedDir int
	var addModFile, removedFile string
	var renamedFile string
	var newDir, removedDir string
	var desc string

	if results == nil {
		return ""
	}

	for _, v := range results {
		de, ok := v.(*diffEntry)
		if !ok {
			return ""
		}
		switch de.status {
		case DiffStatusAdded:
			if nAddMod == 0 {
				addModFile = filepath.Base(de.name)
			}
			nAddMod++
		case DiffStatusDeleted:
			if nRemoved == 0 {
				removedFile = filepath.Base(de.name)
			}
			nRemoved++
		case DiffStatusRenamed:
			if nRenamed == 0 {
				renamedFile = filepath.Base(de.name)
			}
			nRenamed++
		case DiffStatusModified:
			if nAddMod == 0 {
				addModFile = filepath.Base(de.name)
			}
			nAddMod++
		case DiffStatusDirAdded:
			if nNewDir == 0 {
				newDir = filepath.Base(de.name)
			}
			nNewDir++
		case DiffStatusDirDeleted:
			if nRemovedDir == 0 {
				removedDir = filepath.Base(de.name)
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
