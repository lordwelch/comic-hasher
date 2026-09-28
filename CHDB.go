package ch

import "gitea.narnian.us/lordwelch/comic-hasher/log"

type CHDB interface {
	// OpenCHDB(path string, comicvinePath string, deleteExisting bool) (CHDB, error)
	PathHashed(path string) bool
	PathDownloaded(path string) bool
	AddPath(path string)
	// CheckURL return true if the url is known to be a bad url
	CheckURL(url string) bool
	AddURL(url string)
	Close() error
}

var CHDBLogger = log.NewLogger("chdb")
