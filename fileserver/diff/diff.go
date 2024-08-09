package diff

import (
	"context"
	"fmt"
	"io"
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

type fileCB func(context.Context, string, []*fsmgr.SeafDirent, interface{}) error
type dirCB func(context.Context, string, []*fsmgr.SeafDirent, interface{}, *bool) error

type DiffOptions struct {
	FileCB fileCB
	DirCB  dirCB
	RepoID string
	Ctx    context.Context
	Data   interface{}
	Reader io.ReadCloser
}

type diffData struct {
	foldDirDiff bool
	results     *[]*DiffEntry
}

func DiffTrees(roots []string, opt *DiffOptions) error {
	reader := fsmgr.GetOneZlibReader()
	defer fsmgr.ReturnOneZlibReader(reader)
	opt.Reader = reader

	n := len(roots)
	if n != 2 && n != 3 {
		err := fmt.Errorf("the number of commit trees is illegal")
		return err
	}
	trees := make([]*fsmgr.SeafDir, n)
	for i := 0; i < n; i++ {
		root, err := fsmgr.GetSeafdirWithZlibReader(opt.RepoID, roots[i], opt.Reader)
		if err != nil {
			err := fmt.Errorf("Failed to find dir %s:%s", opt.RepoID, roots[i])
			return err
		}
		trees[i] = root
	}

	return diffTreesRecursive(trees, "", opt)
}

func diffTreesRecursive(trees []*fsmgr.SeafDir, baseDir string, opt *DiffOptions) error {
	n := len(trees)
	ptrs := make([][]*fsmgr.SeafDirent, 3)

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
		dents := make([]*fsmgr.SeafDirent, 3)
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

func diffFiles(baseDir string, dents []*fsmgr.SeafDirent, opt *DiffOptions) error {
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

	return opt.FileCB(opt.Ctx, baseDir, files, opt.Data)
}

func diffDirectories(baseDir string, dents []*fsmgr.SeafDirent, opt *DiffOptions) error {
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
	err := opt.DirCB(opt.Ctx, baseDir, dirs, opt.Data, &recurse)
	if err != nil {
		err := fmt.Errorf("failed to call dir callback: %w", err)
		return err
	}

	if !recurse {
		return nil
	}

	var dirName string
	for i := 0; i < n; i++ {
		if dents[i] != nil && fsmgr.IsDir(dents[i].Mode) {
			dir, err := fsmgr.GetSeafdirWithZlibReader(opt.RepoID, dents[i].ID, opt.Reader)
			if err != nil {
				err := fmt.Errorf("Failed to find dir %s:%s", opt.RepoID, dents[i].ID)
				return err
			}
			subDirs[i] = dir
			dirName = dents[i].Name
		}
	}

	newBaseDir := baseDir + dirName + "/"
	return diffTreesRecursive(subDirs, newBaseDir, opt)
}

func direntSame(dentA, dentB *fsmgr.SeafDirent) bool {
	return dentA.ID == dentB.ID &&
		dentA.Mode == dentB.Mode &&
		dentA.Mtime == dentB.Mtime
}

// Diff type and diff status.
const (
	DiffTypeCommits = 'C' /* diff between two commits*/

	DiffStatusAdded      = 'A'
	DiffStatusDeleted    = 'D'
	DiffStatusModified   = 'M'
	DiffStatusRenamed    = 'R'
	DiffStatusUnmerged   = 'U'
	DiffStatusDirAdded   = 'B'
	DiffStatusDirDeleted = 'C'
	DiffStatusDirRenamed = 'E'
)

type DiffEntry struct {
	DiffType   rune
	Status     rune
	Sha1       string
	Name       string
	NewName    string
	Size       int64
	OriginSize int64
}

func diffEntryNewFromDirent(diffType, status rune, dent *fsmgr.SeafDirent, baseDir string) *DiffEntry {
	de := new(DiffEntry)
	de.Sha1 = dent.ID
	de.DiffType = diffType
	de.Status = status
	de.Size = dent.Size
	de.Name = filepath.Join(baseDir, dent.Name)

	return de
}

func diffEntryNew(diffType, status rune, dirID, name string) *DiffEntry {
	de := new(DiffEntry)
	de.DiffType = diffType
	de.Status = status
	de.Sha1 = dirID
	de.Name = name

	return de
}

func DiffMergeRoots(storeID, mergedRoot, p1Root, p2Root string, results *[]*DiffEntry, foldDirDiff bool) error {
	roots := []string{mergedRoot, p1Root, p2Root}

	opt := new(DiffOptions)
	opt.RepoID = storeID
	opt.FileCB = threewayDiffFiles
	opt.DirCB = threewayDiffDirs
	opt.Data = diffData{foldDirDiff, results}

	err := DiffTrees(roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v", err)
		return err
	}

	diffResolveRenames(results)

	return nil
}

func threewayDiffFiles(ctx context.Context, baseDir string, dents []*fsmgr.SeafDirent, optData interface{}) error {
	m := dents[0]
	p1 := dents[1]
	p2 := dents[2]
	data, ok := optData.(diffData)
	if !ok {
		err := fmt.Errorf("failed to assert diff data")
		return err
	}
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

func threewayDiffDirs(ctx context.Context, baseDir string, dents []*fsmgr.SeafDirent, optData interface{}, recurse *bool) error {
	*recurse = true
	return nil
}

func DiffCommitRoots(storeID, p1Root, p2Root string, results *[]*DiffEntry, foldDirDiff bool) error {
	roots := []string{p1Root, p2Root}

	opt := new(DiffOptions)
	opt.RepoID = storeID
	opt.FileCB = twowayDiffFiles
	opt.DirCB = twowayDiffDirs
	opt.Data = diffData{foldDirDiff, results}

	err := DiffTrees(roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v", err)
		return err
	}

	diffResolveRenames(results)

	return nil
}

func DiffCommits(commit1, commit2 *commitmgr.Commit, results *[]*DiffEntry, foldDirDiff bool) error {
	repo := repomgr.Get(commit1.RepoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %s", commit1.RepoID)
		return err
	}
	roots := []string{commit1.RootID, commit2.RootID}

	opt := new(DiffOptions)
	opt.RepoID = repo.StoreID
	opt.FileCB = twowayDiffFiles
	opt.DirCB = twowayDiffDirs
	opt.Data = diffData{foldDirDiff, results}

	err := DiffTrees(roots, opt)
	if err != nil {
		err := fmt.Errorf("failed to diff trees: %v", err)
		return err
	}

	diffResolveRenames(results)

	return nil
}

func twowayDiffFiles(ctx context.Context, baseDir string, dents []*fsmgr.SeafDirent, optData interface{}) error {
	p1 := dents[0]
	p2 := dents[1]
	data, ok := optData.(diffData)
	if !ok {
		err := fmt.Errorf("failed to assert diff data")
		return err
	}
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
		de.OriginSize = p1.Size
		*results = append(*results, de)
	}

	return nil
}

func twowayDiffDirs(ctx context.Context, baseDir string, dents []*fsmgr.SeafDirent, optData interface{}, recurse *bool) error {
	p1 := dents[0]
	p2 := dents[1]
	data, ok := optData.(diffData)
	if !ok {
		err := fmt.Errorf("failed to assert diff data")
		return err
	}
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
		*results = append(*results, de)
		if data.foldDirDiff {
			*recurse = false
		} else {
			*recurse = true
		}
	}

	return nil
}

func diffResolveRenames(des *[]*DiffEntry) error {
	var deletedEmptyCount, deletedEmptyDirCount, addedEmptyCount, addedEmptyDirCount int
	for _, de := range *des {
		if de.Sha1 == EmptySha1 {
			if de.Status == DiffStatusDeleted {
				deletedEmptyCount++
			}
			if de.Status == DiffStatusDirDeleted {
				deletedEmptyDirCount++
			}
			if de.Status == DiffStatusAdded {
				addedEmptyCount++
			}
			if de.Status == DiffStatusDirAdded {
				addedEmptyDirCount++
			}
		}
	}

	deletedFiles := make(map[string]*DiffEntry)
	deletedDirs := make(map[string]*DiffEntry)
	var results []*DiffEntry
	var added []*DiffEntry

	checkEmptyDir := (deletedEmptyDirCount == 1 && addedEmptyDirCount == 1)
	checkEmptyFile := (deletedEmptyCount == 1 && addedEmptyCount == 1)

	for _, de := range *des {
		if de.Status == DiffStatusDeleted {
			if de.Sha1 == EmptySha1 && !checkEmptyFile {
				results = append(results, de)
				continue
			}
			deletedFiles[de.Sha1] = de
		}

		if de.Status == DiffStatusDirDeleted {
			if de.Sha1 == EmptySha1 && !checkEmptyDir {
				results = append(results, de)
				continue
			}
			deletedDirs[de.Sha1] = de
		}

		if de.Status == DiffStatusAdded {
			if de.Sha1 == EmptySha1 && !checkEmptyFile {
				results = append(results, de)
				continue
			}
			added = append(added, de)
		}

		if de.Status == DiffStatusDirAdded {
			if de.Sha1 == EmptySha1 && !checkEmptyDir {
				results = append(results, de)
				continue
			}

			added = append(added, de)
		}

		if de.Status == DiffStatusModified {
			results = append(results, de)
		}
	}

	for _, de := range added {
		var deAdd, deDel, deRename *DiffEntry
		var renameStatus rune

		deAdd = de
		if deAdd.Status == DiffStatusAdded {
			deTmp, ok := deletedFiles[de.Sha1]
			if !ok {
				results = append(results, deAdd)
				continue
			}
			deDel = deTmp
		} else {
			deTmp, ok := deletedDirs[de.Sha1]
			if !ok {
				results = append(results, deAdd)
				continue
			}
			deDel = deTmp
		}

		if deAdd.Status == DiffStatusDirAdded {
			renameStatus = DiffStatusDirRenamed
		} else {
			renameStatus = DiffStatusRenamed
		}

		deRename = diffEntryNew(deDel.DiffType, renameStatus, deDel.Sha1, deDel.Name)
		deRename.NewName = de.Name
		results = append(results, deRename)
		if deDel.Status == DiffStatusDirDeleted {
			delete(deletedDirs, deAdd.Sha1)
		} else {
			delete(deletedFiles, deAdd.Sha1)
		}
	}

	for _, de := range deletedFiles {
		results = append(results, de)
	}

	for _, de := range deletedDirs {
		results = append(results, de)
	}
	*des = results

	return nil
}

func DiffResultsToDesc(results []*DiffEntry) string {
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
		switch de.Status {
		case DiffStatusAdded:
			if nAddMod == 0 {
				addModFile = filepath.Base(de.Name)
			}
			nAddMod++
		case DiffStatusDeleted:
			if nRemoved == 0 {
				removedFile = filepath.Base(de.Name)
			}
			nRemoved++
		case DiffStatusRenamed:
			if nRenamed == 0 {
				renamedFile = filepath.Base(de.Name)
			}
			nRenamed++
		case DiffStatusModified:
			if nAddMod == 0 {
				addModFile = filepath.Base(de.Name)
			}
			nAddMod++
		case DiffStatusDirAdded:
			if nNewDir == 0 {
				newDir = filepath.Base(de.Name)
			}
			nNewDir++
		case DiffStatusDirDeleted:
			if nRemovedDir == 0 {
				removedDir = filepath.Base(de.Name)
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
