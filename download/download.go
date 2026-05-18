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
	"golang.org/x/time/rate"
)

type Auth interface {
	Apply(*http.Request)
}

type Download struct {
	URL     string
	Auth    Auth
	Dest    string // Relative path to image file
	IssueID string
	Image   *bytes.Buffer
	Done    func()
	Limiter *rate.Limiter
}

func Get(url string, auth Auth, client *http.Client) (*http.Response, func(), error) {
	if client == nil {
		client = &http.Client{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, cancel, err
	}
	auth.Apply(req)
	resp, err := client.Do(req)
	return resp, cancel, err
}

const StatusTwitterTooManyRequests = 420

func Worker(chdb ch.CHDB, baseDir string, keepImages bool, downloads chan Download, finished chan<- Download, id int) {
	log.Println("starting downloader", id)
	for dl := range downloads {
		dest := filepath.Join(baseDir, dl.Dest)
		if dl.Limiter != nil && !dl.Limiter.Allow() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := dl.Limiter.Wait(ctx)
			cancel() // ctx is only used for the Limiter. We still need to cancel even if err is not nil
			if err != nil {
				go func() { // because this sends to itself. This can end up in a loop
					downloads <- dl
				}()
				continue
			}
		}
		if dl.Image == nil || dl.Image.Len() > 0 {
			finished <- dl
			dl.Done()
			continue
		}
		dir := filepath.Dir(dest)
		resp, cancelDownload, err := Get(dl.URL, dl.Auth, nil)
		if err != nil {
			cancelDownload()
			log.Println("Failed to download", dl.IssueID, dl.URL, err)
			dl.Done()
			continue
		}
		cleanup := func() {
			_ = resp.Body.Close()
			cancelDownload()
			dl.Done()
		}
		// TODO: StatusTooManyRequests
		// TODO: StatusTwitterTooManyRequests
		if resp.StatusCode == http.StatusNotFound {
			chdb.AddURL(dl.URL)
			cleanup()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Println("Failed to download", dl.URL, resp.StatusCode)
			cleanup()
			continue
		}

		if keepImages {
			_ = os.MkdirAll(dir, 0o755)
			image, err := os.Create(dest)
			if err != nil {
				log.Println("Unable to create image file", dl.Dest, err)
				_ = os.Remove(dest)
				_ = image.Close()
				cleanup()
				continue
			}
			log.Println("downloading", dl.Dest)
			dl.Image.Reset()
			writer := io.MultiWriter(dl.Image, image)
			_, err = io.Copy(writer, resp.Body)
			_ = image.Close()
			if err != nil {
				log.Println("Failed when downloading image", err)
				_ = os.Remove(dest)
				cleanup()
				continue
			}
			finished <- dl
		} else {
			log.Println("downloading", dl.Dest)
			_, err = io.Copy(dl.Image, resp.Body)
			if err != nil {
				log.Println("Failed when downloading image", err)
				cleanup()
				_ = os.Remove(dest)
				// Something failed let this buffer GC instead of saving it
				// bufPool doesn't seem to like putting it back in directly after getting it out
				continue
			}

			finished <- dl
		}
		cleanup()
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
