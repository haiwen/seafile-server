package workerpool

import (
	log "github.com/sirupsen/logrus"
	"runtime/debug"
)

type WorkPool struct {
	jobs  chan Job
	jobCB JobCB
}

// Job is the job object of workpool.
type Job struct {
	callback JobCB
	args     []interface{}
}

type JobCB func(args ...interface{}) error

func CreateWorkerPool(jobCB JobCB, n int) *WorkPool {
	pool := new(WorkPool)
	pool.jobCB = jobCB
	pool.jobs = make(chan Job, 100)
	for i := 0; i < n; i++ {
		go worker(pool.jobs)
	}
	return pool
}

func (pool *WorkPool) AddTask(args ...interface{}) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("panic: %v\n%s", err, debug.Stack())
		}
	}()
	job := Job{pool.jobCB, args}
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
			err := job.callback(job.args...)
			if err != nil {
				log.Printf("failed to call jobs: %v.\n", err)
			}
		}
	}
}
