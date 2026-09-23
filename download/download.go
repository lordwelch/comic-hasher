// Package download
package download

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
)

type Download struct {
	// Request should already have any authentication added
	Request *http.Request
	IssueID string
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

func Get(req *http.Request) (*http.Response, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	req = req.WithContext(ctx)
	resp, err := Client.Do(req)
	return resp, cancel, err
}

const StatusTwitterTooManyRequests = 420

func Worker(chdb ch.CHDB, baseDir string, keepImages bool, downloads chan Download, finished chan<- Download, id int) {
	log.Println("starting downloader", id)
	runDownload := func(dl Download) {
		dest := filepath.Join(baseDir, dl.Dest)
		var resp http.Response
		defer dl.Done(&resp) // dl.Done always needs to be called so that the downloader can continue
		if dl.Image == nil || dl.Image.Len() > 0 {
			finished <- dl
			return
		}
		dir := filepath.Dir(dest)
		res, cancelDownload, err := Get(dl.Request)
		resp = *res // needed for the defer above. May not be totally correct use of a http.Response struct
		defer cancelDownload()
		if err != nil {
			log.Println("Failed to download", dl.IssueID, dl.Request.URL, err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		// TODO: StatusTooManyRequests
		// TODO: StatusTwitterTooManyRequests
		if resp.StatusCode == http.StatusNotFound {
			chdb.AddURL(dl.Request.URL.String())
			return
		}
		if resp.StatusCode != http.StatusOK {
			log.Println("Failed to download", dl.Request.URL, resp.StatusCode)
			return
		}

		if keepImages {
			_ = os.MkdirAll(dir, 0o755)
			image, err := os.Create(dest)
			if err != nil {
				log.Println("Unable to create image file", dl.Dest, err)
				_ = os.Remove(dest)
				return
			}
			defer func() { _ = image.Close() }() // ensure it's always closed
			log.Println("downloading", dl.Dest)
			dl.Image.Reset()
			writer := io.MultiWriter(dl.Image, image)
			_, err = io.Copy(writer, resp.Body)
			_ = image.Close() // close immediately after use
			if err != nil {
				log.Println("Failed when downloading image", err)
				_ = os.Remove(dest)
				return
			}
			finished <- dl
		} else {
			log.Println("downloading", dl.Dest)
			_, err = io.Copy(dl.Image, resp.Body)
			if err != nil {
				log.Println("Failed when downloading image", err)
				_ = os.Remove(dest)
				// Something failed let this buffer GC instead of saving it
				// bufPool doesn't seem to like putting it back in directly after getting it out
				return
			}

			finished <- dl
		}
	}
	for dl := range downloads {
		runDownload(dl)
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
