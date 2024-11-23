package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"math/rand"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/diff"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/option"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/workerpool"
	log "github.com/sirupsen/logrus"
)

const mergeVirtualRepoWorkerNumber = 5

var mergeVirtualRepoPool *workerpool.WorkPool

var runningRepo = make(map[string]struct{})
var runningRepoMutex sync.Mutex

func virtualRepoInit() {
	mergeVirtualRepoPool = workerpool.CreateWorkerPool(mergeVirtualRepo, mergeVirtualRepoWorkerNumber)
}

func mergeVirtualRepo(args ...interface{}) error {
	if len(args) < 1 {
		return nil
	}
	repoID := args[0].(string)
	virtual, err := repomgr.IsVirtualRepo(repoID)
	if err != nil {
		return err
	}

	if virtual {
		runningRepoMutex.Lock()
		if _, ok := runningRepo[repoID]; ok {
			log.Debugf("a task for repo %s is already running", repoID)
			go mergeVirtualRepoPool.AddTask(repoID)
			runningRepoMutex.Unlock()
			return nil
		}
		runningRepo[repoID] = struct{}{}
		runningRepoMutex.Unlock()

		err := mergeRepo(repoID)
		if err != nil {
			log.Errorf("%v", err)
		}
		runningRepoMutex.Lock()
		delete(runningRepo, repoID)
		runningRepoMutex.Unlock()

		go updateSizePool.AddTask(repoID)

		return nil
	}

	excludeRepo := ""
	if len(args) > 1 {
		excludeRepo = args[1].(string)
	}
	vRepos, _ := repomgr.GetVirtualRepoIDsByOrigin(repoID)
	for _, id := range vRepos {
		if id == excludeRepo {
			continue
		}
		runningRepoMutex.Lock()
		if _, ok := runningRepo[id]; ok {
			log.Debugf("a task for repo %s is already running", id)
			go mergeVirtualRepoPool.AddTask(id)
			runningRepoMutex.Unlock()
			continue
		}
		runningRepo[id] = struct{}{}
		runningRepoMutex.Unlock()

		err := mergeRepo(id)
		if err != nil {
			log.Errorf("%v", err)
		}
		runningRepoMutex.Lock()
		delete(runningRepo, id)
		runningRepoMutex.Unlock()
	}

	go updateSizePool.AddTask(repoID)

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
		err := fmt.Errorf("merge repo %.8s failed: failed to get origin repo commit %s:%.8s", repoID, origRepo.ID, origRepo.HeadCommitID)
		return err
	}

	var origRoot string
	origRoot, err = fsmgr.GetSeafdirIDByPath(origRepo.StoreID, origHead.RootID, vInfo.Path)
	if err != nil && !errors.Is(err, fsmgr.ErrPathNoExist) {
		err := fmt.Errorf("merge repo %.10s failed: failed to get seafdir id by path in origin repo %.10s: %v", repoID, origRepo.StoreID, err)
		return err
	}
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
		err := fmt.Errorf("merge repo %.8s failed: failed to get origin repo commit %s:%.8s", repoID, origRepo.ID, vInfo.BaseCommitID)
		return err
	}

	root := head.RootID
	baseRoot, _ := fsmgr.GetSeafdirIDByPath(origRepo.StoreID, base.RootID, vInfo.Path)
	if baseRoot == "" {
		err := fmt.Errorf("merge repo %.10s failed: cannot find seafdir for origin repo %.10s path %s", repoID, vInfo.OriginRepoID, vInfo.Path)
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
			err := fmt.Errorf("merge repo %.8s failed: failed to update origin repo%.10s path %s", repoID, vInfo.OriginRepoID, vInfo.Path)
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
			err := fmt.Errorf("merge repo %.10s failed: failed to update origin repo %.10s path %s", repoID, vInfo.OriginRepoID, vInfo.Path)
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
	parent, err := commitmgr.Load(head.RepoID, head.ParentID.String)
	if err != nil {
		err := fmt.Errorf("failed to load commit %s/%s : %v", head.RepoID, head.ParentID.String, err)
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
				repomgr.DelVirtualRepo(vInfo.RepoID, option.CloudMode)
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
						err := editRepo(vInfo.RepoID, newName, "Changed library name", "")
						if err != nil {
							log.Warnf("falied to rename repo %s.\n", newName)
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
		repomgr.DelVirtualRepo(vInfo.RepoID, option.CloudMode)
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

	_, err = updateBranch(repoID, repo.StoreID, commit.CommitID, parent.CommitID, "", false, "")
	if err != nil {
		return true, nil
	}

	repomgr.UpdateRepoInfo(repoID, commit.CommitID)

	return true, nil
}
