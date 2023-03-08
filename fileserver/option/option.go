package option

import (
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

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
	MaxDownloadDirSize     uint64
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

	// general options
	CloudMode bool

	// notification server
	EnableNotification bool
	NotificationURL    string
	// notification options
	PrivateKey string

	// GROUP options
	GroupTableName string

	// quota options
	DefaultQuota int64

	// Profile password
	ProfilePassword string
	EnableProfiling bool

	// Go log level
	LogLevel string
)

func initDefaultOptions() {
	Host = "0.0.0.0"
	Port = 8082
	MaxDownloadDirSize = 100 * (1 << 20)
	FixedBlockSize = 1 << 23
	MaxIndexingThreads = 1
	WebTokenExpireTime = 7200
	ClusterSharedTempFileMode = 0600
	DefaultQuota = InfiniteQuota
	FsCacheLimit = 2 << 30
	FsIdListRequestTimeout = -1
}

func LoadFileServerOptions(centralDir string) {
	seafileConfPath := filepath.Join(centralDir, "seafile.conf")

	config, err := ini.Load(seafileConfPath)
	if err != nil {
		log.Fatalf("Failed to load seafile.conf: %v", err)
	}
	CloudMode = false
	if section, err := config.GetSection("general"); err == nil {
		if key, err := section.GetKey("cloud_mode"); err == nil {
			CloudMode, _ = key.Bool()
		}
	}

	if section, err := config.GetSection("notification"); err == nil {
		if key, err := section.GetKey("enabled"); err == nil {
			EnableNotification, _ = key.Bool()
		}
	}

	if EnableNotification {
		var notifServer string
		var notifPort uint32
		if section, err := config.GetSection("notification"); err == nil {
			if key, err := section.GetKey("jwt_private_key"); err == nil {
				PrivateKey = key.String()
			}
		}
		if section, err := config.GetSection("notification"); err == nil {
			if key, err := section.GetKey("host"); err == nil {
				notifServer = key.String()
			}
		}
		if section, err := config.GetSection("notification"); err == nil {
			if key, err := section.GetKey("port"); err == nil {
				port, err := key.Uint()
				if err == nil {
					notifPort = uint32(port)
				}
			}
		}
		NotificationURL = fmt.Sprintf("%s:%d", notifServer, notifPort)
	}

	initDefaultOptions()

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

	ccnetConfPath := filepath.Join(centralDir, "ccnet.conf")
	config, err = ini.Load(ccnetConfPath)
	if err != nil {
		log.Fatalf("Failed to load ccnet.conf: %v", err)
	}
	GroupTableName = "Group"
	if section, err := config.GetSection("GROUP"); err == nil {
		if key, err := section.GetKey("TABLE_NAME"); err == nil {
			GroupTableName = key.String()
		}
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
			MaxUploadSize = uint64(size) * (1 << 20)
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
	if key, err := section.GetKey("fs_id_list_request_timeout"); err == nil {
		fsIdListRequestTimeout, err := key.Int64()
		if err == nil {
			FsIdListRequestTimeout = fsIdListRequestTimeout
		}
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
