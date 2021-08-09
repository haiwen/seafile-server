package workerpool

import (
	"log"
	"runtime/debug"
)

type WorkPool struct {
	jobs chan Job
}

// Job is the job object of workpool.
type Job struct {
	callback jobCB
	args     []string
}

type jobCB func(repoID string, args ...string) error

func CreateWorkerPool(n int) *WorkPool {
	pool := new(WorkPool)
	pool.jobs = make(chan Job, 100)
	for i := 0; i < n; i++ {
		go worker(pool.jobs)
	}
	return pool
}

func (pool *WorkPool) AddTask(f jobCB, args ...string) {
	job := Job{f, args}
	pool.jobs <- job
}

func worker(jobs chan Job) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("panic: %v\n%s", err, debug.Stack())
		}
	}()

	for job := range jobs {
		if job.callback != nil {
			err := job.callback(job.args[0], job.args[1:]...)
			if err != nil {
				log.Printf("failed to call jobs: %v.\n", err)
			}
		}
	}
}
