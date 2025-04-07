package option

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

// InfiniteQuota indicates that the quota is unlimited.
const InfiniteQuota = -2

// Storage unit.
const (
	KB = 1000
	MB = 1000000
	GB = 1000000000
	TB = 1000000000000
)

var (
	// fileserver options
	Host                   string
	Port                   uint32
	MaxUploadSize          uint64
	FsIdListRequestTimeout int64
	// Block size for indexing uploaded files
	FixedBlockSize uint64
	// Maximum number of goroutines to index uploaded files
	MaxIndexingThreads uint32
	WebTokenExpireTime uint32
	// File mode for temp files
	ClusterSharedTempFileMode uint32
	WindowsEncoding           string
	SkipBlockHash             bool
	FsCacheLimit              int64
	VerifyClientBlocks        bool

	// general options
	CloudMode bool

	// notification server
	EnableNotification bool
	NotificationURL    string

	// GROUP options
	GroupTableName string

	// quota options
	DefaultQuota int64

	// redis options
	HasRedisOptions bool
	RedisHost       string
	RedisPasswd     string
	RedisPort       uint32
	RedisExpiry     uint32
	RedisMaxConn    uint32
	RedisTimeout    time.Duration

	// Profile password
	ProfilePassword string
	EnableProfiling bool

	// Go log level
	LogLevel string

	// DB default timeout
	DBOpTimeout time.Duration

	// seahub
	SeahubURL     string
	JWTPrivateKey string
)

func initDefaultOptions() {
	Host = "0.0.0.0"
	Port = 8082
	FixedBlockSize = 1 << 23
	MaxIndexingThreads = 1
	WebTokenExpireTime = 7200
	ClusterSharedTempFileMode = 0600
	DefaultQuota = InfiniteQuota
	FsCacheLimit = 4 << 30
	VerifyClientBlocks = true
	FsIdListRequestTimeout = -1
	DBOpTimeout = 60 * time.Second
	RedisHost = "127.0.0.1"
	RedisPort = 6379
	RedisExpiry = 24 * 3600
	RedisMaxConn = 100
	RedisTimeout = 1 * time.Second
}

func LoadFileServerOptions(centralDir string) {
	initDefaultOptions()

	seafileConfPath := filepath.Join(centralDir, "seafile.conf")

	opts := ini.LoadOptions{}
	opts.SpaceBeforeInlineComment = true
	config, err := ini.LoadSources(opts, seafileConfPath)
	if err != nil {
		log.Fatalf("Failed to load seafile.conf: %v", err)
	}
	CloudMode = false
	if section, err := config.GetSection("general"); err == nil {
		if key, err := section.GetKey("cloud_mode"); err == nil {
			CloudMode, _ = key.Bool()
		}
	}

	notifServer := os.Getenv("NOTIFICATION_SERVER_URL")
	if notifServer != "" {
		NotificationURL = fmt.Sprintf("%s:8083", notifServer)
		EnableNotification = true
	}

	if section, err := config.GetSection("httpserver"); err == nil {
		parseFileServerSection(section)
	}
	if section, err := config.GetSection("fileserver"); err == nil {
		parseFileServerSection(section)
	}

	if section, err := config.GetSection("quota"); err == nil {
		if key, err := section.GetKey("default"); err == nil {
			quotaStr := key.String()
			DefaultQuota = parseQuota(quotaStr)
		}
	}

	loadCacheOptionFromEnv()

	GroupTableName = os.Getenv("SEAFILE_MYSQL_DB_GROUP_TABLE_NAME")
	if GroupTableName == "" {
		GroupTableName = "Group"
	}
}

func parseFileServerSection(section *ini.Section) {
	if key, err := section.GetKey("host"); err == nil {
		Host = key.String()
	}
	if key, err := section.GetKey("port"); err == nil {
		port, err := key.Uint()
		if err == nil {
			Port = uint32(port)
		}
	}
	if key, err := section.GetKey("max_upload_size"); err == nil {
		size, err := key.Uint()
		if err == nil {
			MaxUploadSize = uint64(size) * 1000000
		}
	}
	if key, err := section.GetKey("max_indexing_threads"); err == nil {
		threads, err := key.Uint()
		if err == nil {
			MaxIndexingThreads = uint32(threads)
		}
	}
	if key, err := section.GetKey("fixed_block_size"); err == nil {
		blkSize, err := key.Uint64()
		if err == nil {
			FixedBlockSize = blkSize * (1 << 20)
		}
	}
	if key, err := section.GetKey("web_token_expire_time"); err == nil {
		expire, err := key.Uint()
		if err == nil {
			WebTokenExpireTime = uint32(expire)
		}
	}
	if key, err := section.GetKey("cluster_shared_temp_file_mode"); err == nil {
		fileMode, err := key.Uint()
		if err == nil {
			ClusterSharedTempFileMode = uint32(fileMode)
		}
	}
	if key, err := section.GetKey("enable_profiling"); err == nil {
		EnableProfiling, _ = key.Bool()
	}
	if EnableProfiling {
		if key, err := section.GetKey("profile_password"); err == nil {
			ProfilePassword = key.String()
		} else {
			log.Fatal("password of profiling must be specified.")
		}
	}
	if key, err := section.GetKey("go_log_level"); err == nil {
		LogLevel = key.String()
	}
	if key, err := section.GetKey("fs_cache_limit"); err == nil {
		fsCacheLimit, err := key.Int64()
		if err == nil {
			FsCacheLimit = fsCacheLimit * 1024 * 1024
		}
	}
	// The ratio of physical memory consumption and fs objects is about 4:1,
	// and this part of memory is generally not subject to GC. So the value is
	// divided by 4.
	FsCacheLimit = FsCacheLimit / 4
	if key, err := section.GetKey("fs_id_list_request_timeout"); err == nil {
		fsIdListRequestTimeout, err := key.Int64()
		if err == nil {
			FsIdListRequestTimeout = fsIdListRequestTimeout
		}
	}
	if key, err := section.GetKey("verify_client_blocks_after_sync"); err == nil {
		VerifyClientBlocks, _ = key.Bool()
	}
}

func parseQuota(quotaStr string) int64 {
	var quota int64
	var multiplier int64 = GB
	if end := strings.Index(quotaStr, "kb"); end > 0 {
		multiplier = KB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "mb"); end > 0 {
		multiplier = MB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "gb"); end > 0 {
		multiplier = GB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else if end := strings.Index(quotaStr, "tb"); end > 0 {
		multiplier = TB
		quotaInt, err := strconv.ParseInt(quotaStr[:end], 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	} else {
		quotaInt, err := strconv.ParseInt(quotaStr, 10, 0)
		if err != nil {
			return InfiniteQuota
		}
		quota = quotaInt * multiplier
	}

	return quota
}

func loadCacheOptionFromEnv() {
	cacheProvider := os.Getenv("CACHE_PROVIDER")
	if cacheProvider != "redis" {
		return
	}

	HasRedisOptions = true

	redisHost := os.Getenv("REDIS_HOST")
	if redisHost != "" {
		RedisHost = redisHost
	}
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort != "" {
		port, err := strconv.ParseUint(redisPort, 10, 32)
		if err != nil {
			RedisPort = uint32(port)
		}
	}
	redisPasswd := os.Getenv("REDIS_PASSWORD")
	if redisPasswd != "" {
		RedisPasswd = redisPasswd
	}
	redisMaxConn := os.Getenv("REDIS_MAX_CONNECTIONS")
	if redisMaxConn != "" {
		maxConn, err := strconv.ParseUint(redisMaxConn, 10, 32)
		if err != nil {
			RedisMaxConn = uint32(maxConn)
		}
	}
	redisExpiry := os.Getenv("REDIS_EXPIRY")
	if redisExpiry != "" {
		expiry, err := strconv.ParseUint(redisExpiry, 10, 32)
		if err != nil {
			RedisExpiry = uint32(expiry)
		}
	}
}

func LoadSeahubConfig() error {
	JWTPrivateKey = os.Getenv("JWT_PRIVATE_KEY")
	if JWTPrivateKey == "" {
		return fmt.Errorf("failed to read JWT_PRIVATE_KEY")
	}

	siteRoot := os.Getenv("SITE_ROOT")
	if siteRoot != "" {
		SeahubURL = fmt.Sprintf("http://127.0.0.1:8000%sapi/v2.1/internal", siteRoot)
	} else {
		SeahubURL = "http://127.0.0.1:8000/api/v2.1/internal"
	}

	return nil
}
