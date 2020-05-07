package main

import (
	"fmt"
	"log"
	"path/filepath"

	"gopkg.in/ini.v1"

	"database/sql"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/diff"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

// Job is the job object of workpool.
type Job struct {
	callback jobCB
	repoID   string
}

type jobCB func(repoID string) error

var jobs = make(chan Job, 100)

func sizeSchedulerInit() {
	var n int = 1
	var seafileConfPath string
	if centralDir != "" {
		seafileConfPath = filepath.Join(centralDir, "seafile.conf")
	} else {
		seafileConfPath = filepath.Join(absDataDir, "seafile.conf")
	}
	config, err := ini.Load(seafileConfPath)
	if err != nil {
		log.Fatalf("Failed to load seafile.conf: %v", err)
	}
	if section, err := config.GetSection("scheduler"); err == nil {
		if key, err := section.GetKey("size_sched_thread_num"); err == nil {
			num, err := key.Int()
			if err == nil {
				n = num
			}
		}
	}
	go createWorkerPool(n)
}

// need to start a go routine
func createWorkerPool(n int) {
	for i := 0; i < n; i++ {
		go worker()
	}
}

func worker() {
	for {
		select {
		case job := <-jobs:
			if job.callback != nil {
				err := job.callback(job.repoID)
				if err != nil {
					log.Printf("failed to call jobs: %v.\n", err)
				}
			}
		}
	}
}

func updateRepoSize(repoID string) {
	job := Job{computeRepoSize, repoID}
	jobs <- job
}

func computeRepoSize(repoID string) error {
	var size int64
	var fileCount int64

	repo := repomgr.Get(repoID)
	if repo == nil {
		err := fmt.Errorf("failed to get repo %s", repoID)
		return err
	}

	info, err := getOldRepoInfo(repoID)
	if err != nil {
		err := fmt.Errorf("failed to get old repo info: %v", err)
		return err
	}

	if info != nil && info.HeadID == repo.HeadCommitID {
		return nil
	}

	head, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("failed to get head commit %s", repo.HeadCommitID)
		return err
	}

	var oldHead *commitmgr.Commit
	if info != nil {
		commit, _ := commitmgr.Load(repo.ID, info.HeadID)
		oldHead = commit
	}

	if info != nil && oldHead != nil {
		var results []*diff.DiffEntry
		var changeSize int64
		var changeFileCount int64
		err := diff.DiffCommits(oldHead, head, &results, false)
		if err != nil {
			err := fmt.Errorf("failed to do diff commits: %v", err)
			return err
		}

		for _, de := range results {
			if de.Status == diff.DiffStatusDeleted {
				changeSize -= de.Size
				changeFileCount--
			} else if de.Status == diff.DiffStatusAdded {
				changeSize += de.Size
				changeFileCount++
			} else if de.Status == diff.DiffStatusModified {
				changeSize = changeSize + de.Size - de.OriginSize
			}
		}
		size = info.Size + changeSize
		fileCount = info.FileCount + changeFileCount
	} else {
		info, err := fsmgr.GetFileCountInfoByPath(repo.StoreID, repo.RootID, "/")
		if err != nil {
			err := fmt.Errorf("failed to get file count")
			return err
		}

		fileCount = info.FileCount
		size = info.Size
	}

	err = setRepoSizeAndFileCount(repoID, repo.HeadCommitID, size, fileCount)
	if err != nil {
		err := fmt.Errorf("failed to set repo size and file count %s: %v", repoID, err)
		return err
	}

	return nil
}

func setRepoSizeAndFileCount(repoID, newHeadID string, size, fileCount int64) error {
	trans, err := seafileDB.Begin()
	if err != nil {
		err := fmt.Errorf("failed to start transaction: %v", err)
		return err
	}

	var headID string
	sqlStr := "SELECT head_id FROM RepoSize WHERE repo_id=?"

	row := trans.QueryRow(sqlStr, repoID)
	if err := row.Scan(&headID); err != nil {
		if err != sql.ErrNoRows {
			trans.Rollback()
			return err
		}
	}

	if headID == "" {
		sqlStr := "INSERT INTO RepoSize (repo_id, size, head_id) VALUES (?, ?, ?)"
		_, err = trans.Exec(sqlStr, repoID, size, newHeadID)
		if err != nil {
			trans.Rollback()
			return err
		}
	} else {
		sqlStr = "UPDATE RepoSize SET size = ?, head_id = ? WHERE repo_id = ?"
		_, err = trans.Exec(sqlStr, size, newHeadID, repoID)
		if err != nil {
			trans.Rollback()
			return err
		}
	}

	var exist int
	sqlStr = "SELECT 1 FROM RepoFileCount WHERE repo_id=?"
	row = trans.QueryRow(sqlStr, repoID)
	if err := row.Scan(&exist); err != nil {
		if err != sql.ErrNoRows {
			trans.Rollback()
			return err
		}
	}

	if exist != 0 {
		sqlStr := "UPDATE RepoFileCount SET file_count=? WHERE repo_id=?"
		_, err = trans.Exec(sqlStr, fileCount, repoID)
		if err != nil {
			trans.Rollback()
			return err
		}
	} else {
		sqlStr := "INSERT INTO RepoFileCount (repo_id,file_count) VALUES (?,?)"
		_, err = trans.Exec(sqlStr, repoID, fileCount)
		if err != nil {
			trans.Rollback()
			return err
		}
	}

	trans.Commit()

	return nil
}

// RepoInfo contains repo information.
type RepoInfo struct {
	HeadID    string
	Size      int64
	FileCount int64
}

func getOldRepoInfo(repoID string) (*RepoInfo, error) {
	sqlStr := "select s.head_id,s.size,f.file_count FROM RepoSize s LEFT JOIN RepoFileCount f ON " +
		"s.repo_id=f.repo_id WHERE s.repo_id=?"

	repoInfo := new(RepoInfo)
	row := seafileDB.QueryRow(sqlStr, repoID)
	if err := row.Scan(&repoInfo.HeadID, &repoInfo.Size, &repoInfo.FileCount); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}

		return nil, nil
	}

	return repoInfo, nil
}
