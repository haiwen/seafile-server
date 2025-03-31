package metrics

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/z"
	"github.com/go-redis/redis/v8"
	"github.com/haiwen/seafile-server/fileserver/option"

	log "github.com/sirupsen/logrus"
)

const (
	RedisChannel   = "metric_channel"
	ComponentName  = "go_fileserver"
	MetricInterval = 30 * time.Second
)

type MetricMgr struct {
	sync.Mutex
	inFlightRequestList *list.List
}

type RequestInfo struct {
	urlPath string
	method  string
	start   time.Time
}

func (m *MetricMgr) AddReq(urlPath, method string) *list.Element {
	req := new(RequestInfo)
	req.urlPath = urlPath
	req.method = method
	req.start = time.Now()

	m.Lock()
	defer m.Unlock()
	e := m.inFlightRequestList.PushBack(req)

	return e
}

func (m *MetricMgr) DecReq(e *list.Element) {
	m.Lock()
	defer m.Unlock()

	m.inFlightRequestList.Remove(e)
}

var (
	client *redis.Client
	closer *z.Closer

	metricMgr *MetricMgr
)

func Init() {
	if !option.HasRedisOptions {
		return
	}
	metricMgr = new(MetricMgr)
	metricMgr.inFlightRequestList = list.New()

	closer = z.NewCloser(1)
	go metricsHandler()
}

func Stop() {
	if !option.HasRedisOptions {
		return
	}
	closer.SignalAndWait()
}

func metricsHandler() {
	defer closer.Done()
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panic: %v\n%s", err, debug.Stack())
		}
	}()

	server := fmt.Sprintf("%s:%d", option.RedisHost, option.RedisPort)
	opt := &redis.Options{
		Addr:     server,
		Password: option.RedisPasswd,
	}
	opt.PoolSize = 1

	client = redis.NewClient(opt)

	ticker := time.NewTicker(MetricInterval)
	defer ticker.Stop()

	for {
		select {
		case <-closer.HasBeenClosed():
			return
		case <-ticker.C:
			err := publishMetrics()
			if err != nil {
				log.Warnf("Failed to publish metrics to redis channel: %v", err)
				continue
			}
		}
	}
}

func MetricMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := metricMgr.AddReq(r.URL.Path, r.Method)
		next.ServeHTTP(w, r)
		metricMgr.DecReq(req)
	})
}

type MetricMessage struct {
	MetricName    string `json:"metric_name"`
	MetricValue   any    `json:"metric_value"`
	MetricType    string `json:"metric_type"`
	ComponentName string `json:"component_name"`
	MetricHelp    string `json:"metric_help"`
	NodeName      string `json:"node_name"`
}

func publishMetrics() error {
	metricMgr.Lock()
	inFlightRequestCount := metricMgr.inFlightRequestList.Len()
	metricMgr.Unlock()

	msg := &MetricMessage{MetricName: "in_flight_request_total",
		MetricValue:   inFlightRequestCount,
		MetricType:    "gauge",
		ComponentName: ComponentName,
		MetricHelp:    "The number of currently running http requests.",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	err = publishRedisMsg(RedisChannel, data)
	if err != nil {
		return err
	}

	return nil
}

func publishRedisMsg(channel string, msg []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Publish(ctx, channel, msg).Err()
	if err != nil {
		return fmt.Errorf("failed to publish redis message: %w", err)
	}
	return nil
}
