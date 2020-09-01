package main

import (
	"fmt"
	"gopkg.in/ini.v1"
	"log"
	"path/filepath"
	"sync"

	"database/sql"

	"github.com/haiwen/seafile-server/fileserver/commitmgr"
	"github.com/haiwen/seafile-server/fileserver/fsmgr"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
)

// Job is the job object of workpool.
type Job struct {
	callback jobCB
	repoID   string
}

type jobCB func(repoID string) error

var jobs = make(chan Job, 10)

func sizeSchedulerInit() {
	var n int = 1
	seafileConfPath := filepath.Join(absDataDir, "seafile.conf")
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
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go worker(&wg)
	}
	wg.Wait()
}

func worker(wg *sync.WaitGroup) {
	for {
		select {
		case job := <-jobs:
			if job.callback != nil {
				err := job.callback(job.repoID)
				if err != nil {
					log.Printf("failed to call jobs: %v.\n", err)
				}
			}
		default:
		}
	}
	wg.Done()
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
		err := fmt.Errorf("[scheduler] failed to get repo %s", repoID)
		return err
	}

	info, err := repomgr.GetOldRepoInfo(repoID)
	if err != nil {
		err := fmt.Errorf("[scheduler] failed to get old repo info: %v", err)
		return err
	}

	if info != nil && info.HeadID == repo.HeadCommitID {
		return nil
	}

	head, err := commitmgr.Load(repo.ID, repo.HeadCommitID)
	if err != nil {
		err := fmt.Errorf("[scheduler] failed to get head commit %s", repo.HeadCommitID)
		return err
	}

	var oldHead *commitmgr.Commit
	if info != nil {
		commit, _ := commitmgr.Load(repo.ID, info.HeadID)
		oldHead = commit
	}

	if info != nil && oldHead != nil {
		var results []interface{}
		var changeSize int64
		var changeFileCount int64
		err := diffCommits(oldHead, head, &results, false)
		if err != nil {
			err := fmt.Errorf("[scheduler] failed to do diff commits: %v", err)
			return err
		}

		for _, v := range results {
			de, ok := v.(*diffEntry)
			if !ok {
				err := fmt.Errorf("failed to assert diff entry")
				return err
			}
			if de.status == DiffStatusDeleted {
				changeSize -= de.size
				changeFileCount--
			} else if de.status == DiffStatusAdded {
				changeSize += de.size
				changeFileCount++
			} else if de.status == DiffStatusModified {
				changeSize = changeSize + de.size + de.originSize
			}
		}
		size = info.Size + changeSize
		fileCount = info.FileCount + changeFileCount
	} else {
		info, err := fsmgr.GetFileCountInfoByPath(repo.StoreID, repo.RootID, "/")
		if err != nil {
			err := fmt.Errorf("[scheduler] failed to get file count")
			return err
		}

		fileCount = info.FileCount
		size = info.Size
	}

	err = setRepoSizeAndFileCount(repoID, repo.HeadCommitID, size, fileCount)
	if err != nil {
		err := fmt.Errorf("[scheduler] failed to set repo size and file count %s: %v", repoID, err)
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
