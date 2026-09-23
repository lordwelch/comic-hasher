// Package metron
package metron

import (
	"context"
	"os"
	"sync"
	"time"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	dl "gitea.narnian.us/lordwelch/comic-hasher/download"
	"golang.org/x/time/rate"
)

const defaultLimit = 5000 / rate.Limit(time.Hour*24)

type MetronDownloader struct {
	Context context.Context

	basePath             string
	version              string
	SendExistingImages   bool
	KeepDownloadedImages bool
	onlyHashNewIDs       bool
	StartDownloadQueue   chan<- dl.Download

	currentLimit       rate.Limit
	username, password string

	fileList     []string
	totalResults int
	imageWG      sync.WaitGroup
	// notFound       chan download
	chdb    ch.CHDB
	bufPool *sync.Pool
	getID   func(id ch.ID) ch.IDList
}

func NewCVDownloader(
	ctx context.Context,
	version string,
	bufPool *sync.Pool,
	onlyHashNewIDs bool,
	getID func(id ch.ID) ch.IDList,
	chdb ch.CHDB,
	basePath, APIKey string,
	keepDownloadedImages, sendExistingImages bool,
	startDownloadQueue chan<- dl.Download,
) *MetronDownloader {
	if os.Getenv("METRON_KEEP_IMAGES") == "TRUE" {
		keepDownloadedImages = true
	}
	return &MetronDownloader{
		basePath:             basePath,
		Context:              ctx,
		version:              version,
		bufPool:              bufPool, // The buffers get sent back via finishedDownloadQueue
		StartDownloadQueue:   startDownloadQueue,
		SendExistingImages:   sendExistingImages,
		KeepDownloadedImages: keepDownloadedImages,
		chdb:                 chdb,
		getID:                getID,
		onlyHashNewIDs:       onlyHashNewIDs,
	}
}
