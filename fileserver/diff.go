package main

import (
	"fmt"
	"strings"

	"github.com/haiwen/seafile-server/fileserver/fsmgr"
)

type fileCB func(string, []*fsmgr.SeafDirent, *[]interface{})
type dirCB func(string, []*fsmgr.SeafDirent, *[]interface{})

type diffOptions struct {
	fileCB  fileCB
	dirCB   dirCB
	repoID  string
	results *[]interface{}
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
	ptrs := make([][]fsmgr.SeafDirent, 3)
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
					dents[i] = &dent
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

	opt.fileCB(baseDir, files, opt.results)
	return nil
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

	opt.dirCB(baseDir, dirs, opt.results)

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
