package main

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"math/rand"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/diff"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/workerpool"
)

const mergeVirtualRepoWorkerNumber = 5

var mergeVirtualRepoPool *workerpool.WorkPool

func virtualRepoInit() {
	mergeVirtualRepoPool = workerpool.CreateWorkerPool(mergeVirtualRepoWorkerNumber)
}

func mergeVirtualRepo(repoID string, args ...string) error {
	virtual, err := repomgr.IsVirtualRepo(repoID)
	if err != nil {
		return err
	}

	if virtual {
		mergeRepo(repoID)

		updateSizePool.AddTask(computeRepoSize, repoID)

		return nil
	}

	excludeRepo := ""
	if len(args) > 0 {
		excludeRepo = args[0]
	}
	vRepos, _ := repomgr.GetVirtualRepoIDsByOrigin(repoID)
	for _, id := range vRepos {
		if id == excludeRepo {
			continue
		}

		mergeRepo(id)
	}

	updateSizePool.AddTask(computeRepoSize, repoID)

	return nil
}

func mergeRepo(repoID string) error {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get virt repo %.10s", repoID)
		return err
	}
	vInfo := repo.VirtualInfo
	if vInfo == nil {
		return nil
	}
	origRepo := repomgr.Get(vInfo.OriginRepoID)
	if origRepo == nil {
		err := fmt.Errorf("failed to get orig repo %.10s", repoID)
		return err
	}

	head, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%.8s", repo.ID, repo.HeadCommitID)
		return err
	}
	origHead, err := commitmgr.Load(origRepo.ID, origRepo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%.8s", origRepo.ID, origRepo.HeadCommitID)
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
			return nil
		}
	}

	base, err := commitmgr.Load(origRepo.ID, vInfo.BaseCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%.8s", origRepo.ID, vInfo.BaseCommitID)
		return err
	}

	root := head.RootID
	baseRoot, _ := fsmgr.GetSeafdirIDByPath(origRepo.StoreID, base.RootID, vInfo.Path)
	if baseRoot == "" {
		err := fmt.Errorf("cannot find seafdir for repo %.10s path %s", vInfo.OriginRepoID, vInfo.Path)
		return err
	}

	if root == origRoot {
	} else if baseRoot == root {
		_, err := updateDir(repoID, "/", origRoot, origHead.CreatorName, head.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update root of virtual repo %.10s", repoID)
			return err
		}
		repomgr.SetVirtualRepoBaseCommitPath(repo.ID, origRepo.HeadCommitID, vInfo.Path)
	} else if baseRoot == origRoot {
		newBaseCommit, err := updateDir(vInfo.OriginRepoID, vInfo.Path, root, head.CreatorName, origHead.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update origin repo%.10s path %s", vInfo.OriginRepoID, vInfo.Path)
			return err
		}
		repomgr.SetVirtualRepoBaseCommitPath(repo.ID, newBaseCommit, vInfo.Path)
		cleanupVirtualRepos(vInfo.OriginRepoID)
		mergeVirtualRepo(vInfo.OriginRepoID, repoID)
	} else {
		roots := []string{baseRoot, origRoot, root}
		opt := new(mergeOptions)
		opt.remoteRepoID = repoID
		opt.remoteHead = head.CommitID

		err := mergeTrees(origRepo.StoreID, roots, opt)
		if err != nil {
			err := fmt.Errorf("failed to merge")
			return err
		}

		_, err = updateDir(repoID, "/", opt.mergedRoot, origHead.CreatorName, head.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update root of virtual repo %.10s", repoID)
			return err
		}

		newBaseCommit, err := updateDir(vInfo.OriginRepoID, vInfo.Path, opt.mergedRoot, head.CreatorName, origHead.CommitID)
		if err != nil {
			err := fmt.Errorf("failed to update origin repo %.10s path %s", vInfo.OriginRepoID, vInfo.Path)
			return err
		}
		repomgr.SetVirtualRepoBaseCommitPath(repo.ID, newBaseCommit, vInfo.Path)
		cleanupVirtualRepos(vInfo.OriginRepoID)
		mergeVirtualRepo(vInfo.OriginRepoID, repoID)
	}

	return nil
}

func cleanupVirtualRepos(repoID string) error {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %.10s", repoID)
		return err
	}

	head, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to load commit %s/%s : %v", repo.ID, repo.HeadCommitID, err)
		return err
	}

	vRepos, err := repomgr.GetVirtualRepoInfoByOrigin(repoID)
	if err != nil {
		err := fmt.Errorf("failed to get virtual repo ids by origin repo %.10s", repoID)
		return err
	}
	for _, vInfo := range vRepos {
		_, err := fsmgr.GetSeafdirByPath(repo.StoreID, head.RootID, vInfo.Path)
		if err != nil {
			if err == fsmgr.ErrPathNoExist {
				handleMissingVirtualRepo(repo, head, vInfo)
			}
		}
	}

	return nil
}

func handleMissingVirtualRepo(repo *repomgr.Repo, head *commitmgr.Commit, vInfo *repomgr.VRepoInfo) (string, error) {
	parent, err := commitmgr.Load(head.RepoID, head.ParentID)
	if err != nil {
		err := fmt.Errorf("failed to load commit %s/%s : %v", head.RepoID, head.ParentID, err)
		return "", err
	}

	var results []*diff.DiffEntry
	err = diff.DiffCommits(parent, head, &results, true)
	if err != nil {
		err := fmt.Errorf("failed to diff commits")
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

			if err == fsmgr.ErrPathNoExist {
				repomgr.DelVirtualRepo(vInfo.RepoID, cloudMode)
			}
			err := fmt.Errorf("failed to find %s under commit %s in repo %s", parPath, parent.CommitID, repo.StoreID)
			return "", err
		}

		for _, de := range results {
			if de.Status == diff.DiffStatusDirRenamed {
				if de.Sha1 == oldDirID {
					if subPath != "" {
						newPath = filepath.Join("/", de.NewName, subPath)
					} else {
						newPath = filepath.Join("/", de.NewName)
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

		slash := strings.LastIndex(parPath, "/")
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
		err := fmt.Errorf("at least one argument should be non-null")
		return err
	}

	var retryCnt int
	for retry, err := editRepoNeedRetry(repoID, name, desc, user); err != nil || retry; {
		if err != nil {
			err := fmt.Errorf("failed to edit repo: %v", err)
			return err
		}
		if retryCnt < 3 {
			random := rand.Intn(10) + 1
			time.Sleep(time.Duration(random*100) * time.Millisecond)
			retryCnt++
		} else {
			err := fmt.Errorf("stop edit repo %s after 3 retries", repoID)
			return err
		}
	}

	return nil
}

func editRepoNeedRetry(repoID, name, desc, user string) (bool, error) {
	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("no such library")
		return false, err
	}
	if name == "" {
		name = repo.Name
	}
	if desc == "" {
		desc = repo.Desc
	}

	parent, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%s", repo.ID, repo.HeadCommitID)
		return false, err
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
		err := fmt.Errorf("failed to add commit: %v", err)
		return false, err
	}

	err = updateBranch(repoID, commit.CommitID, parent.CommitID)
	if err != nil {
		return true, nil
	}

	updateRepoInfo(repoID, commit.CommitID)

	return true, nil
}

func updateRepoInfo(repoID, commitID string) error {
	head, err := commitmgr.Load(repoID, commitID)
	if err != nil {
		err := fmt.Errorf("failed to get commit %s:%s", repoID, commitID)
		return err
	}

	repomgr.SetRepoCommitToDb(repoID, head.RepoName, head.Ctime, head.Version, head.Encrypted, head.CreatorName)

	return nil
}
