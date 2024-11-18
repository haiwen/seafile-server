package workerpool

import (
	"runtime/debug"

	"github.com/dgraph-io/ristretto/z"
	log "github.com/sirupsen/logrus"
)

type WorkPool struct {
	jobs   chan Job
	jobCB  JobCB
	closer *z.Closer
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
	pool.closer = z.NewCloser(n)
	for i := 0; i < n; i++ {
		go pool.run(pool.jobs)
	}
	return pool
}

func (pool *WorkPool) AddTask(args ...interface{}) {
	job := Job{pool.jobCB, args}
	pool.jobs <- job
}

func (pool *WorkPool) run(jobs chan Job) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panic: %v\n%s", err, debug.Stack())
		}
	}()
	defer pool.closer.Done()

	for {
		select {
		case job := <-pool.jobs:
			if job.callback != nil {
				err := job.callback(job.args...)
				if err != nil {
					log.Errorf("failed to call jobs: %v.\n", err)
				}
			}
		case <-pool.closer.HasBeenClosed():
			return
		}
	}
}

func (pool *WorkPool) Shutdown() {
	pool.closer.SignalAndWait()
}
