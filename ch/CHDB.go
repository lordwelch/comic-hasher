package ch

import "gitea.narnian.us/lordwelch/comic-hasher/log"

type CHDB interface {
	PathHashed(path string) bool
	PathDownloaded(path string) bool
	AddPath(path string)
	// CheckURL return true if the url is known to be a bad url
	CheckURL(url string) bool
	AddURL(url string)
	Close() error

	GetSourceID(string) byte
	GetSourceName(sourceID byte) string
	Compact() error
}

var CHDBLogger = log.NewLogger("chdb")
