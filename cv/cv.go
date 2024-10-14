package cv

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"slices"
)

type Download struct {
	URL     string
	Dest    string
	IssueID string
}

type Issue struct {
	ID    int `json:"id"`
	Image struct {
		IconURL        string `json:"icon_url,omitempty"`
		MediumURL      string `json:"medium_url,omitempty"`
		ScreenURL      string `json:"screen_url,omitempty"`
		ScreenLargeURL string `json:"screen_large_url,omitempty"`
		SmallURL       string `json:"small_url,omitempty"`
		SuperURL       string `json:"super_url,omitempty"`
		ThumbURL       string `json:"thumb_url"`
		TinyURL        string `json:"tiny_url,omitempty"`
		OriginalURL    string `json:"original_url"`
		ImageTags      string `json:"image_tags"`
	} `json:"image"`
	Volume struct {
		ID int `json:"id"`
	} `json:"volume"`
}

type CVResult struct {
	// Error                string  `json:"error"`
	// Limit                int     `json:"limit"`
	Offset               int     `json:"offset"`
	NumberOfPageResults  int     `json:"number_of_page_results"`
	NumberOfTotalResults int     `json:"number_of_total_results"`
	StatusCode           int     `json:"status_code"`
	Results              []Issue `json:"results"`
	// Version              string  `json:"version"`
}

type CVDownloader struct {
	APIKey                string
	JSONPath              string
	ImagePath             string
	ImageTypes            []string
	SendExistingImages    bool
	Context               context.Context
	FinishedDownloadQueue chan Download

	fileList       []fs.DirEntry
	totalResults   int
	badURLs        []string
	bMut           sync.Mutex
	imageWG        sync.WaitGroup
	downloadQueue  chan *CVResult
	imageDownloads chan download
	notFound       chan download
}

var ErrQuit = errors.New("Quit")

func (c *CVDownloader) InsertBadURL(url string) {
	c.bMut.Lock()
	defer c.bMut.Unlock()
	index, itemFound := slices.BinarySearch(c.badURLs, url)
	if itemFound {
		return
	}
	c.badURLs = slices.Insert(c.badURLs, index, url)
}

func (c *CVDownloader) InsertBadURLs(url ...string) {
	c.bMut.Lock()
	defer c.bMut.Unlock()
	c.badURLs = append(c.badURLs, url...)
	slices.Sort(c.badURLs)
}
func (c *CVDownloader) IsBadURL(url string) bool {
	_, itemFound := slices.BinarySearch(c.badURLs, url)
	return itemFound
}
func (c *CVDownloader) readJson() ([]*CVResult, error) {
	var issues []*CVResult
	for _, file_entry := range c.fileList {
		if c.hasQuit() {
			return nil, ErrQuit
		}
		result, err := c.loadIssues(file_entry)
		if err != nil {
			return issues, err
		}
		if result.NumberOfTotalResults > c.totalResults {
			c.totalResults = result.NumberOfTotalResults
		}
		issues = append(issues, result)
	}
	return issues, nil
}
func (c *CVDownloader) loadIssues(file_entry fs.DirEntry) (*CVResult, error) {
	tmp := &CVResult{}
	file, err := os.Open(filepath.Join(c.JSONPath, file_entry.Name()))
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, tmp)
	if err != nil {
		return nil, err
	}
	return tmp, nil
}

func Get(ctx context.Context, url string) (*http.Response, error, func()) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err, cancel
	}
	resp, err := http.DefaultClient.Do(req)
	return resp, err, cancel
}

func getOffset(entry fs.DirEntry) int {
	i, _ := strconv.Atoi(entry.Name()[3 : len(entry.Name())-1-4])
	return i
}

// updateIssues  c.downloadQueue must not be closed before this function has returned
func (c *CVDownloader) updateIssues() {
	base_url, err := url.Parse("https://comicvine.gamespot.com/api/issues/?sort=date_added,id:asc&format=json&field_list=id,image,volume")
	if err != nil {
		log.Fatal(err)
	}

	query := base_url.Query()
	query.Add("api_key", c.APIKey)
	base_url.RawQuery = query.Encode()
	c.totalResults = max(c.totalResults, 1)
	// IDs := make([]int, 0, 1_000_000)
	// deleteIndexes := make([]int, 0, 100)
	// CV sucks remove duplicate IDs so that we can try to get all the comics
	// for i, issueList := range ssues {
	// 	for _, issue := range issueList.Results {
	// 		if _, found := slices.BinarySearch(IDs, issue.ID); found {
	// 			deleteIndexes = append(deleteIndexes, i)
	// 			slices.Sort(deleteIndexes)
	// 		}
	// 		IDs = append(IDs, issue.ID)
	// 	}
	// }
	// slices.Reverse(deleteIndexes)
	// for _, i := range deleteIndexes {
	// 	issues = slices.Delete(issues, i, min(i+1, len(issues)-1))
	// }
	failCount := 0
	prev := -1
	offset := 0
	retry := func(err error) bool {
		if errors.Is(err, context.Canceled) {
			log.Println("Server closed")
			return false
		}
		log.Printf("Failed to download at offset %v: %v Attempt #%d", offset, err, failCount+1)
		if prev == offset {
			sleepTime := time.Second * 36
			if failCount > 2 {
				sleepTime = time.Minute * 10
			}
			select {
			case <-c.Context.Done(): // allows us to return immediately even during a timeout
				return false
			case <-time.After(sleepTime):
			}
		}
		prev = offset
		failCount += 1
		offset -= 100
		return failCount < 15
	}
	for offset = 0; offset < c.totalResults; offset += 100 {
		if c.hasQuit() {
			return
		}
		if offset/100 < len(c.fileList) {
			if getOffset(c.fileList[offset/100]) == offset { // If it's in order and it's not missing it should be here
				if issue, err := c.loadIssues(c.fileList[offset/100]); err == nil && issue != nil {
					c.totalResults = max(c.totalResults, issue.NumberOfTotalResults)
					prev = -1
					failCount = 0
					// When canceled one of these will randomly be chosen, c.downloadQueue won't be closed until after this function returns
					select {
					case <-c.Context.Done():
					case c.downloadQueue <- issue:
					}
					continue
				} else {
					log.Println("Failed to read page at offset ", offset, err)
				}
			}
			log.Printf("Expected Offset %d got Offset %d", offset, getOffset(c.fileList[offset/100]))
		}
		index, found := slices.BinarySearchFunc(c.fileList, offset, func(a fs.DirEntry, b int) int {
			ai, _ := strconv.Atoi(a.Name()[3 : len(a.Name())-1-4])
			return cmp.Compare(ai, b)
		})
		if found {
			if issue, err := c.loadIssues(c.fileList[index]); err != nil && issue != nil {
				prev = -1
				failCount = 0
				// When canceled one of these will randomly be chosen, c.downloadQueue won't be closed until after this function returns
				select {
				case <-c.Context.Done():
				case c.downloadQueue <- issue:
				}
				continue
			}
		}

		log.Println("Starting download at offset", offset)
		issue := &CVResult{}
		URI := base_url
		query = base_url.Query()
		query.Add("offset", strconv.Itoa(offset))
		URI.RawQuery = query.Encode()

		select {
		case <-c.Context.Done(): // allows us to return immediately even during a timeout
			return
		case <-time.After(10 * time.Second):
		}
		resp, err, cancelDownloadCTX := Get(c.Context, URI.String())
		if err != nil {
			cancelDownloadCTX()
			if retry(err) {
				continue
			}
			return
		}
		file, err := os.Create(filepath.Join(c.JSONPath, "cv-"+strconv.Itoa(offset)+".json"))
		if err != nil {
			log.Fatal(err)
		}
		body := io.TeeReader(resp.Body, file)
		err = json.NewDecoder(bufio.NewReader(body)).Decode(issue)
		if err != nil {
			cancelDownloadCTX()
			if retry(err) {
				continue
			}
			return
		}
		_ = resp.Body.Close()
		_ = file.Close()
		cancelDownloadCTX()
		if issue.NumberOfTotalResults > c.totalResults {
			c.totalResults = issue.NumberOfTotalResults
		}
		prev = -1
		failCount = 0
		// When canceled one of these will randomly be chosen, c.downloadQueue won't be closed until after this function returns
		select {
		case <-c.Context.Done():
			return
		case c.downloadQueue <- issue:
		}
		log.Printf("Downloaded %s/cv-%v.json", c.JSONPath, offset)
	}
}

type download struct {
	url      string
	dest     string
	offset   int
	volumeID int
	issueID  int
	finished bool
}

func (c *CVDownloader) start_downloader() {
	for i := range 5 {
		go func() {
			log.Println("starting downloader", i)
			for dl := range c.imageDownloads {
				if c.hasQuit() {
					c.imageWG.Done()
					continue // We must continue so that c.imageWG will complete otherwise it will hang forever
				}
				if dl.finished {

					select {
					case <-c.Context.Done():
						c.imageWG.Done()
						continue
					case c.FinishedDownloadQueue <- Download{
						URL:     dl.url,
						Dest:    dl.dest,
						IssueID: strconv.Itoa(dl.issueID),
					}:
						c.imageWG.Done()
					}
					continue
				}
				resp, err, cancelDownload := Get(c.Context, dl.url)
				if err != nil {
					cancelDownload()
					log.Println("Failed to download", dl.url, err)
					c.imageWG.Done()
					continue
				}
				cleanup := func() {
					resp.Body.Close()
					cancelDownload()
					c.imageWG.Done()
				}
				if resp.StatusCode == 404 {

					c.notFound <- dl
					cleanup()
					continue
				}
				if resp.StatusCode != 200 {
					log.Println("Failed to download", dl.url, resp.StatusCode)
					cleanup()
					continue
				}
				image, err := os.Create(dl.dest)
				if err != nil {
					log.Println("Unable to create image file", dl.dest, err)
					os.Remove(dl.dest)
					cleanup()
					continue
				}
				log.Println("downloading", dl.dest)
				_, err = io.Copy(image, resp.Body)
				if err != nil {
					log.Println("Failed when downloading image", err)
					cleanup()
					os.Remove(dl.dest)
					continue
				}

				c.FinishedDownloadQueue <- Download{
					URL:     dl.url,
					Dest:    dl.dest,
					IssueID: strconv.Itoa(dl.issueID),
				}
				cleanup()
			}
		}()
	}
}

func (c *CVDownloader) loadBadURLs(path string) error {
	bad_urls_file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("Unable to read bad_urls: %w", err)
	}
	bad_urls_bytes, err := io.ReadAll(bad_urls_file)
	bad_urls_file.Close()
	if err != nil {
		return fmt.Errorf("Unable to read bad_urls: %w", err)
	}
	c.bMut.Lock()
	c.badURLs = strings.Split(string(bad_urls_bytes), "\n")
	c.bMut.Unlock()
	return nil
}

func (c *CVDownloader) handleNotFound() {
	err := c.loadBadURLs("bad_urls")
	if err != nil {
		panic(err)
	}
	file, err := os.OpenFile("bad_urls", os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		file.Close()
		panic(err)
	}
	for failedDownload := range c.notFound {
		c.InsertBadURL(failedDownload.url)
		log.Printf("Not found: volumeID: %d issueID: %d Offset: %d URL: %s\n", failedDownload.volumeID, failedDownload.issueID, failedDownload.offset, failedDownload.url)
		file.Write([]byte(failedDownload.url))
		file.Write([]byte("\n"))
		file.Sync()
	}
	file.Close()
}

func (c *CVDownloader) downloadImages() {
	defer func() {
		log.Println("Waiting for final images to complete download")
		c.imageWG.Wait()
	}()
	go c.start_downloader()

	go c.handleNotFound()
	added := 0
	dir_created := make(map[string]bool)
	for list := range c.downloadQueue {
		log.Printf("Checking downloads at offset %v\r", list.Offset)
		for _, issue := range list.Results {
			type i struct {
				url  string
				name string
			}
			imageURLs := []i{{issue.Image.IconURL, "icon_url"}, {issue.Image.MediumURL, "medium_url"}, {issue.Image.ScreenURL, "screen_url"}, {issue.Image.ScreenLargeURL, "screen_large_url"}, {issue.Image.SmallURL, "small_url"}, {issue.Image.SuperURL, "super_url"}, {issue.Image.ThumbURL, "thumb_url"}, {issue.Image.TinyURL, "tiny_url"}, {issue.Image.OriginalURL, "original_url"}}
			for _, image := range imageURLs {
				if c.hasQuit() {
					return
				}
				if len(c.ImageTypes) > 0 && !slices.Contains(c.ImageTypes, image.name) {
					continue
				}
				if c.IsBadURL(image.url) {
					log.Printf("Skipping known bad url %s", image.url)
					continue
				}

				uri, err := url.ParseRequestURI(image.url)
				if err != nil {
					c.notFound <- download{
						url:      image.url,
						offset:   list.Offset,
						volumeID: issue.Volume.ID,
						issueID:  issue.ID,
						finished: true,
					}
				}
				ext := strings.TrimSuffix(strings.ToLower(path.Ext(uri.Path)), "~original")
				if ext == "" || (len(ext) > 4 && !slices.Contains([]string{".avif", ".webp", ".tiff", ".heif"}, ext)) {
					ext = ".jpg"
				}
				path := filepath.Join(c.ImagePath, strconv.Itoa(issue.Volume.ID), strconv.Itoa(issue.ID), image.name+ext)

				image_file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
				if errors.Is(err, os.ErrExist) {
					if c.SendExistingImages {
						// We don't add to the count of added as these should be processed immediately

						c.imageWG.Add(1)
						c.imageDownloads <- download{
							url:      image.url,
							dest:     path,
							offset:   list.Offset,
							volumeID: issue.Volume.ID,
							issueID:  issue.ID,
							finished: true,
						}
					}
					continue // If it exists assume it is fine, adding some basic verification might be a good idea later
				}
				dir := filepath.Join(c.ImagePath, strconv.Itoa(issue.Volume.ID), strconv.Itoa(issue.ID))
				if !dir_created[dir] {
					os.MkdirAll(dir, 0o777)
					dir_created[dir] = true
				}
				added++
				image_file.Close()
				c.imageWG.Add(1)
				c.imageDownloads <- download{
					url:      image.url,
					dest:     path,
					offset:   list.Offset,
					volumeID: issue.Volume.ID,
					issueID:  issue.ID,
				}
			}
			if added > 200 {
				// On a clean single image type run each page would have 100 downloads of a single cover type but stuff happens so we only wait once we have sent 200 to the queue
				log.Println("waiting for", added, "downloads at offset", list.Offset)
				added = 0
				beforeWait := time.Now()
				c.imageWG.Wait()
				waited := time.Since(beforeWait)
				// If we had to wait for the arbitrarily picked time of 7.4 seconds it means we had a backed up queue, lets wait to give the CV servers a break
				if waited > time.Duration(7.4*float64(time.Second)) {
					t := 10 * time.Second
					log.Println("Waiting for", t, "at offset", list.Offset, "had to wait for", waited)
					select {
					case <-c.Context.Done(): // allows us to return immediately even during a timeout
						return
					case <-time.After(t):
					}
				}
			}
		}
	}
}

func (c *CVDownloader) cleanBadURLs() error {

	var indexesToRemove []int
list:
	for i, jsonFile := range c.fileList {
		list, err := c.loadIssues(jsonFile)
		if err != nil {
			indexesToRemove = append(indexesToRemove, i)
			os.Remove(filepath.Join(c.JSONPath, jsonFile.Name()))
			continue
		}
		for _, issue := range list.Results {
			for _, url := range []string{issue.Image.IconURL, issue.Image.MediumURL, issue.Image.ScreenURL, issue.Image.ScreenLargeURL, issue.Image.SmallURL, issue.Image.SuperURL, issue.Image.ThumbURL, issue.Image.TinyURL, issue.Image.OriginalURL} {
				if c.hasQuit() {
					return ErrQuit
				}
				if c.IsBadURL(url) {
					indexesToRemove = append(indexesToRemove, i)
					if err := os.Remove(filepath.Join(c.JSONPath, jsonFile.Name())); err != nil {
						return err
					}
					// We've removed the entire page, lets see if the new url works
					continue list
				}
			}
		}
	}
	slices.Reverse(indexesToRemove)
	for _, i := range indexesToRemove {
		c.fileList = slices.Delete(c.fileList, i, min(i+1, len(c.fileList)-1))
	}
	return nil
}

func (c *CVDownloader) hasQuit() bool {
	select {
	case <-c.Context.Done():
		return true
	default:
		return false
	}
}

func NewCVDownloader(ctx context.Context, workPath, APIKey string, imageTypes []string, sendExistingImages bool, finishedDownloadQueue chan Download) *CVDownloader {
	return &CVDownloader{
		Context:               ctx,
		JSONPath:              filepath.Join(workPath, "_json"),
		ImagePath:             filepath.Join(workPath, "_image"),
		APIKey:                APIKey,
		downloadQueue:         make(chan *CVResult, 1000),
		imageDownloads:        make(chan download, 250),
		notFound:              make(chan download, 100),
		FinishedDownloadQueue: finishedDownloadQueue,
		SendExistingImages:    sendExistingImages,
		ImageTypes:            imageTypes,
	}
}

func DownloadCovers(c *CVDownloader) {
	var (
		err error
	)
	os.MkdirAll(c.JSONPath, 0o777)
	c.fileList, err = os.ReadDir(c.JSONPath)
	if err != nil {
		panic(fmt.Errorf("Unable to open path for json files: %w", err))
	}

	slices.SortFunc(c.fileList, func(x, y fs.DirEntry) int {
		xi, _ := strconv.Atoi(x.Name()[3 : len(x.Name())-1-4])
		yi, _ := strconv.Atoi(y.Name()[3 : len(y.Name())-1-4])
		return cmp.Compare(xi, yi)
	})
	if len(c.fileList) > 0 {
		last_file := c.fileList[len(c.fileList)-1].Name()
		c.totalResults, _ = strconv.Atoi(last_file[3 : len(last_file)-1-4])
	}
	c.totalResults += 100
	log.Println("Reading json")
	log.Println("Number of pages", len(c.fileList), "Expected Pages:", c.totalResults/100)
	log.Println("Updating issues now")

	dwg := sync.WaitGroup{}
	dwg.Add(1)
	go func() {
		c.downloadImages()
		dwg.Done()
	}()

	c.updateIssues()
	issueCount := len(c.fileList) * 100

	log.Println("Number of issues", issueCount, " expected:", c.totalResults)

	close(c.downloadQueue) // sends only happen in c.updateIssues
	for range c.downloadQueue {
	}

	log.Println("Waiting for downloaders")
	dwg.Wait()
	close(c.imageDownloads)
	for range c.imageDownloads {
	}
	close(c.notFound)
	for range c.notFound {
	}

	log.Println("Completed downloading images")
}
