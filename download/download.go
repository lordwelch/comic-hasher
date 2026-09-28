// Package download
package download

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
)

type Download struct {
	// Request should already have any authentication added
	Request *http.Request
	IssueID ch.ID
	// Any rate limit should reserve the limit before sending this struct to the downloader
	// And any dynamic rate limit should happen in this function
	// If there are strict rate limits only send one download at a time
	Done func(*http.Response)

	Dest  string // Relative path to image file
	Image *bytes.Buffer
}
type RT string

func (rt RT) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", string(rt))
	}
	return http.DefaultTransport.RoundTrip(r)
}

var Client = &http.Client{
	Transport: RT("Comic-Hasher"),
}

// Get initiates the request with a 20 second timeout added to ctx
func Get(ctx context.Context, req *http.Request) (*http.Response, func(), error) {
	log.FromContext(ctx).Println(log.Trace, "Downloading", req.URL.String())
	ctx, cancel := context.WithTimeout(ctx, time.Second*20)
	req = req.WithContext(ctx)
	resp, err := Client.Do(req)
	return resp, cancel, err
}

func DownloadImage(dl Download, ctx context.Context, chdb ch.CHDB, baseDir string, keepImages bool, finished chan<- Download, id int) *http.Response {
	logger := log.FromContext(ctx)
	dest := filepath.Join(baseDir, dl.Dest)
	var resp http.Response
	if dl.Image == nil || dl.Image.Len() > 0 {
		finished <- dl
		return nil
	}
	res, cancelDownload, err := Get(ctx, dl.Request)
	if res != nil {
		resp = *res // needed for the defer above. May not be totally correct use of a http.Response struct
	}
	defer cancelDownload()
	if err != nil {
		logger.Println(log.Required, "Failed to download", dl.IssueID, dl.Request.URL, err)
		return &resp
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		chdb.AddURL(dl.Request.URL.String())
		return &resp
	}
	if resp.StatusCode != http.StatusOK {
		logger.Println(log.Required, "Failed to download", dl.Request.URL, resp.StatusCode)
		return &resp
	}

	if keepImages {
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		image, err := os.Create(dest)
		if err != nil {
			logger.Println(log.Required, "Unable to create image file", dl.Dest, err)
			_ = os.Remove(dest)
			return &resp
		}
		defer func() { _ = image.Close() }() // ensure it's always closed
		logger.Println(log.Verbose, "Downloading", dl.IssueID, "to file path", dl.Dest)
		dl.Image.Reset()
		writer := io.MultiWriter(dl.Image, image)
		_, err = io.Copy(writer, resp.Body)
		_ = image.Close() // close immediately after use
		if err != nil {
			logger.Println(log.Required, "Failed when downloading", dl.Dest, err)
			_ = os.Remove(dest)
			return &resp
		}
		finished <- dl
	} else {
		logger.Println(log.Verbose, "Downloading", dl.IssueID, "to memory")
		_, err = io.Copy(dl.Image, resp.Body)
		if err != nil {
			logger.Println(log.Required, "Failed when downloading", dl.Dest, err)
			_ = os.Remove(dest)
			// Something failed let this buffer GC instead of saving it
			// bufPool doesn't seem to like putting it back in directly after getting it out
			return &resp
		}

		finished <- dl
	}
	return &resp
}

func Worker(ctx context.Context, chdb ch.CHDB, baseDir string, keepImages bool, downloads <-chan Download, finished chan<- Download, id int) {
	log.Println(log.Verbose2, "starting downloader", id)
	for dl := range downloads {
		resp := DownloadImage(dl, ctx, chdb, baseDir, keepImages, finished, id)
		if resp != nil && dl.Done != nil {
			dl.Done(resp)
		}
	}
}

func ReadAll(fileName string, buf *bytes.Buffer) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck
	_, err = io.Copy(buf, file)
	return err
}
