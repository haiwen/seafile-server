package main

import (
	log "github.com/sirupsen/logrus"
)

const (
	timestampFormat = "2006/01/02 15:04:05 "
)

type LogFormatter struct{}

func (f *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	buf := make([]byte, 0, len(timestampFormat)+len(entry.Message)+1)
	buf = entry.Time.AppendFormat(buf, timestampFormat)
	buf = append(buf, entry.Message...)
	buf = append(buf, '\n')
	return buf, nil
}
