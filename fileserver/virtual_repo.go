package main

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"math/rand"
	"sort"
	"syscall"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

func mergeVirtualRepo(repoID, excludeRepo string) {
	virtual, err := repomgr.IsVirtualRepo(repoID)
	if err != nil {
		return
	}

	if virtual {
		mergeRepo(repoID)
		return
	}

	vRepos, _ := repomgr.GetVirtualRepoIDsByOrigin(repoID)
	for _, id := range vRepos {
		if id == excludeRepo {
			continue
		}

		mergeRepo(id)
	}

	return
}

func mergeRepo(repoID string) error {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get virt repo %.10s.\n", repoID)
		return err
	}
	vInfo := repo.VirtualInfo
	if vInfo == nil {
		return nil
	}
	origRepo := repomgr.Get(vInfo.OriginRepoID)
	if origRepo == nil {
		err := fmt.Errorf("failed to get orig repo %.10s.\n", repoID)
		return err
	}

	head, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%.8s.\n", repo.ID, repo.HeadCommitID)
		return err
	}
	origHead, err := commitmgr.Load(origRepo.ID, origRepo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%.8s.\n", origRepo.ID, origRepo.HeadCommitID)
		return err
	}

	var origRoot string
	origRoot, _ = fsmgr.GetSeafdirIDByPath(origRepo.StoreID, origHead.RootID, vInfo.Path)
	if origRoot == "" {
		newPath, _ := handleMissingVirtualRepo(origRepo, origHead, vInfo)
		if newPath != "" {
			origRoot, _ = fsmgr.GetSeafdirIDByPath(origRepo.StoreID, origHead.RootID, newPath)
		}
		if origRoot == "" {
			err := fmt.Errorf("path %s not found in origin repo %.8s, delete or rename virtual repo %.8s\n", vInfo.Path, vInfo.OriginRepoID, repoID)
			return err
		}
	}

	base, err := commitmgr.Load(origRepo.ID, vInfo.BaseCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%.8s.\n", origRepo.ID, vInfo.BaseCommitID)
		return err
	}

	root := head.RootID
	baseRoot, _ := fsmgr.GetSeafdirIDByPath(origRepo.StoreID, base.RootID, vInfo.Path)
	if baseRoot == "" {
		err := fmt.Errorf("cannot find seafdir for repo %.10s path %s.\n", vInfo.OriginRepoID, vInfo.Path)
		return err
	}

	if root == origRoot {
	} else if baseRoot == root {
		_, err := updateDir(repoID, "/", origRoot, origHead.CreatorName, head.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update root of virtual repo %.10s.\n", repoID)
			return err
		}
		repomgr.SetVirtualRepoBaseCommitPath(repo.ID, origRepo.HeadCommitID, vInfo.Path)
	} else if baseRoot == origRoot {
		newBaseCommit, err := updateDir(vInfo.OriginRepoID, vInfo.Path, root, head.CreatorName, origHead.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update origin repo%.10s path %s.\n", vInfo.OriginRepoID, vInfo.Path)
			return err
		}
		repomgr.SetVirtualRepoBaseCommitPath(repo.ID, newBaseCommit, vInfo.Path)
		CleanupVirtualRepos(vInfo.OriginRepoID)
		mergeVirtualRepo(vInfo.OriginRepoID, repoID)
	} else {
		roots := []string{baseRoot, origRoot, root}
		opt := new(mergeOptions)
		opt.remoteRepoID = repoID
		opt.remoteHead = head.CommitID

		err := mergeTrees(origRepo.StoreID, roots, opt)
		if err != nil {
			err := fmt.Errorf("failed to merge.\n")
			return err
		}

		_, err = updateDir(repoID, "/", opt.mergedRoot, origHead.CreatorName, head.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update root of virtual repo %.10s.\n", repoID)
			return err
		}

		newBaseCommit, err := updateDir(vInfo.OriginRepoID, vInfo.Path, opt.mergedRoot, head.CreatorName, origHead.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update origin repo %.10s path %s.\n", vInfo.OriginRepoID, vInfo.Path)
			return err
		}
		repomgr.SetVirtualRepoBaseCommitPath(repo.ID, newBaseCommit, vInfo.Path)
		CleanupVirtualRepos(vInfo.OriginRepoID)
		mergeVirtualRepo(vInfo.OriginRepoID, repoID)
	}

	return nil
}

func updateDir(repoID, dirPath, newDirID, user, headID string) (string, error) {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %.10s.\n", repoID)
		return "", err
	}

	var base string
	if headID == "" {
		base = repo.HeadCommitID
	} else {
		base = headID
	}

	headCommit, err := commitmgr.Load(repo.ID, base)
	if err != nil {
		err := fmt.Errorf("failed to get head commit for repo %s", repo.ID)
		return "", err
	}

	if dirPath == "/" {
		commitDesc := genCommitDesc(repo, newDirID, headCommit.RootID)
		if commitDesc == "" {
			commitDesc = fmt.Sprintf("Auto merge by system")
		}
		newCommitID, err := genNewCommit(repo, headCommit, newDirID, user, commitDesc)
		if err != nil {
			err := fmt.Errorf("failed to generate new commit: %v.\n", err)
			return "", err
		}
		return newCommitID, nil
	}

	parent := filepath.Dir(dirPath)
	canonPath := getCanonPath(parent)
	dirName := filepath.Base(dirPath)

	dir, err := fsmgr.GetSeafdirByPath(repo.StoreID, headCommit.RootID, canonPath)
	if err != nil {
		err := fmt.Errorf("dir %s doesn't exist in repo %s.\n", canonPath, repo.StoreID)
		return "", err
	}
	var exists bool
	for _, de := range dir.Entries {
		if de.Name == dirName {
			exists = true
		}
	}
	if !exists {
		err := fmt.Errorf("file %s doesn't exist in repo %s.\n", dirName, repo.StoreID)
		return "", err
	}
	newDent := new(fsmgr.SeafDirent)
	newDent.ID = newDirID
	newDent.Mode = (syscall.S_IFDIR | 0644)
	newDent.Mtime = time.Now().Unix()
	newDent.Name = dirName

	rootID, err := doPutFile(repo, headCommit.RootID, canonPath, newDent)
	if err != nil || rootID == "" {
		err := fmt.Errorf("failed to put file.\n", err)
		return "", err
	}

	commitDesc := genCommitDesc(repo, rootID, headCommit.RootID)
	if commitDesc == "" {
		commitDesc = fmt.Sprintf("Auto merge by system")
	}

	newCommitID, err := genNewCommit(repo, headCommit, rootID, user, commitDesc)
	if err != nil {
		err := fmt.Errorf("failed to generate new commit: %v.\n", err)
		return "", err
	}

	return newCommitID, nil
}

func genCommitDesc(repo *repomgr.Repo, root, parentRoot string) string {
	var results []interface{}
	err := diffCommitRoots(repo.StoreID, parentRoot, root, &results, true)
	if err != nil {
		return ""
	}

	desc := diffResultsToDesc(results)

	return desc
}

func doPutFile(repo *repomgr.Repo, rootID, parentDir string, dent *fsmgr.SeafDirent) (string, error) {
	if strings.Index(parentDir, "/") == 0 {
		parentDir = parentDir[1:]
	}

	return putFileRecursive(repo, rootID, parentDir, dent)
}

func putFileRecursive(repo *repomgr.Repo, dirID, toPath string, newDent *fsmgr.SeafDirent) (string, error) {
	olddir, err := fsmgr.GetSeafdir(repo.StoreID, dirID)
	if err != nil {
		err := fmt.Errorf("failed to get dir.\n")
		return "", err
	}
	entries := olddir.Entries
	sort.Sort(Dirents(entries))

	var ret string

	if toPath == "" {
		var newEntries []*fsmgr.SeafDirent
		for _, dent := range entries {
			if dent.Name == newDent.Name {
				newEntries = append(newEntries, newDent)
			} else {
				newEntries = append(newEntries, dent)
			}
		}

		newdir, err := fsmgr.NewSeafdir(1, newEntries)
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v.\n", err)
			return "", err
		}
		err = fsmgr.SaveSeafdir(repo.StoreID, newdir)
		if err != nil {
			err := fmt.Errorf("failed to save seafdir %s/%s.\n", repo.ID, newdir.DirID)
			return "", err
		}

		return newdir.DirID, nil
	}

	var remain string
	if slash := strings.Index(toPath, "/"); slash >= 0 {
		remain = toPath[slash+1:]
	}

	for _, dent := range entries {
		if dent.Name != toPath {
			continue
		}
		id, err := putFileRecursive(repo, dent.ID, remain, newDent)
		if err != nil {
			err := fmt.Errorf("failed to put dirent %s: %v.\n", dent.Name, err)
			return "", err
		}
		if id != "" {
			dent.ID = id
			dent.Mtime = time.Now().Unix()
		}
		ret = id
		break
	}

	if ret != "" {
		newdir, err := fsmgr.NewSeafdir(1, entries)
		if err != nil {
			err := fmt.Errorf("failed to new seafdir: %v.\n", err)
			return "", err
		}
		err = fsmgr.SaveSeafdir(repo.StoreID, newdir)
		if err != nil {
			err := fmt.Errorf("failed to save seafdir %s/%s.\n", repo.ID, newdir.DirID)
			return "", err
		}
		ret = newdir.DirID
	}

	return ret, nil
}

func CleanupVirtualRepos(repoID string) error {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %.10s.\n", repoID)
		return err
	}

	head, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to load commit %s/%s : %v.\n", repo.ID, repo.HeadCommitID, err)
		return err
	}

	vRepos, err := repomgr.GetVirtualRepoInfoByOrigin(repoID)
	if err != nil {
		err := fmt.Errorf("failed to get virtual repo ids by origin repo %.10s.\n", repoID)
		return err
	}
	for _, vInfo := range vRepos {
		_, err := fsmgr.GetSeafdirByPath(repo.StoreID, head.RootID, vInfo.Path)
		if err != nil {
			if err == fsmgr.PathNoExist {
				handleMissingVirtualRepo(repo, head, vInfo)
			}
		}
	}

	return nil
}

func handleMissingVirtualRepo(repo *repomgr.Repo, head *commitmgr.Commit, vInfo *repomgr.VRepoInfo) (string, error) {
	parent, err := commitmgr.Load(head.RepoID, head.ParentID)
	if err != nil {
		err := fmt.Errorf("failed to load commit %s/%s : %v.\n", head.RepoID, head.ParentID, err)
		return "", err
	}

	var results []interface{}
	err = diffCommits(parent, head, &results, true)
	if err != nil {
		err := fmt.Errorf("failed to diff commits.\n")
		return "", err
	}

	parPath := vInfo.Path
	var isRenamed bool
	var subPath string
	var returnPath string
	for {
		var newPath string
		oldDirID, err := fsmgr.GetSeafdirIDByPath(repo.StoreID, parent.RootID, parPath)
		if err != nil || oldDirID == "" {

			if err == fsmgr.PathNoExist {
				repomgr.DelVirtualRepo(vInfo.RepoID, cloudMode)
			}
			err := fmt.Errorf("failed to find %s under commit %s in repo %s.\n", parPath, parent.CommitID, repo.StoreID)
			return "", err
		}

		for _, v := range results {
			de, ok := v.(*diffEntry)
			if !ok {
				err := fmt.Errorf("failed to assert diff entry.\n")
				return "", err
			}
			if de.status == DIFF_STATUS_DIR_RENAMED {
				if de.dirID == oldDirID {
					if subPath != "" {
						newPath = filepath.Join("/", de.newName, subPath)
					} else {
						newPath = filepath.Join("/", de.newName)
					}
					repomgr.SetVirtualRepoBaseCommitPath(vInfo.RepoID, head.CommitID, newPath)
					returnPath = newPath
					if subPath == "" {
						newName := filepath.Base(newPath)
						err := editRepo(repo.ID, newName, "Changed library name", "")
						if err != nil {
							log.Printf("falied to rename repo %s.\n", newName)
						}
					}
					isRenamed = true
					break
				}
			}
		}

		if isRenamed {
			break
		}

		slash := strings.Index(parPath, "/")
		if slash <= 0 {
			break
		}
		subPath = filepath.Base(parPath)
		parPath = filepath.Dir(parPath)
	}

	if !isRenamed {
		repomgr.DelVirtualRepo(vInfo.RepoID, cloudMode)
	}

	return returnPath, nil
}

func editRepo(repoID, name, desc, user string) error {
	if name == "" && desc == "" {
		err := fmt.Errorf("at least one argument should be non-null.\n")
		return err
	}

	var retryCnt int
	for err, retry := editRepoNeedRetry(repoID, name, desc, user); err != nil || retry; {
		if err != nil {
			err := fmt.Errorf("failed to edit repo: %v.\n", err)
			return err
		}
		if retryCnt < 3 {
			random := rand.Intn(10) + 1
			time.Sleep(time.Duration(random*100) * time.Millisecond)
			retryCnt++
		} else {
			err := fmt.Errorf("stop edit repo %s after 3 retries.\n", repoID)
			return err
		}
	}

	return nil
}

func editRepoNeedRetry(repoID, name, desc, user string) (error, bool) {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("no such library")
		return err, false
	}
	if name == "" {
		name = repo.Name
	}
	if desc == "" {
		desc = repo.Desc
	}

	parent, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%s.\n", repo.ID, repo.HeadCommitID)
		return err, false
	}

	if user == "" {
		user = parent.CreatorName
	}

	commit := commitmgr.NewCommit(repoID, parent.CommitID, parent.RootID, user, "Changed library name or description")
	repomgr.RepoToCommit(repo, commit)
	commit.RepoName = name
	commit.RepoDesc = desc

	err = commitmgr.Save(commit)
	if err != nil {
		err := fmt.Errorf("failed to add commit: %v.\n", err)
		return err, false
	}

	err = updateBranch(repoID, commit.CommitID, parent.CommitID)
	if err != nil {
		return nil, true
	}

	updateRepoInfo(repoID, commit.CommitID)

	return nil, true
}

func updateRepoInfo(repoID, commitID string) error {
	head, err := commitmgr.Load(repoID, commitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%s.\n", repoID, commitID)
		return err
	}

	repomgr.SetRepoCommitToDb(repoID, head.RepoName, head.Ctime, head.Version, head.Encrypted, head.CreatorName)

	return nil
}
