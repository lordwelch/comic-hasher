// Package cv
package cv

import (
	"bufio"
	"bytes"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	dl "gitea.narnian.us/lordwelch/comic-hasher/download"
)

type CVAuth string

func (c CVAuth) Apply(r *http.Request) {
	q := r.URL.Query()
	q.Set("api_key", string(c))
	r.URL.RawQuery = q.Encode()
}

type Images map[string]struct{}

var imageValues = map[string]struct{}{
	"icon":        {},
	"medium":      {},
	"screen":      {},
	"screenlarge": {},
	"small":       {},
	"super":       {},
	"thumb":       {},
	"tiny":        {},
	"original":    {},
}

func (f Images) String() string {
	var value strings.Builder
	for key := range f {
		value.WriteString(key + ",")
	}
	return strings.TrimRight(value.String(), ",")
}

func (f *Images) Get() any {
	delete(*f, "started")
	return *f
}

func (f *Images) Set(s string) error {
	if (*f) == nil {
		*f = Images{"started": {}}
	} else if _, started := (*f)["started"]; !started {
		*f = Images{"started": {}} // clear the map if this is the first time it's called
	}
	images := strings.SplitSeq(strings.ToLower(s), ",")
	for image := range images {
		if _, known := imageValues[image]; known {
			(*f)[s] = struct{}{}
		} else {
			return fmt.Errorf("unknown image type: %v", f)
		}
	}
	return nil
}

type Issue struct {
	ID          int    `json:"id"`
	IssueNumber string `json:"issue_number"`
	Image       struct {
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

const (
	WorkDirectory  = "comicvine"
	imageDirectory = "_image"
	jsonDirectory  = "_json"
)

type CVDownloader struct {
	basePath             string
	version              string
	APIKey               *CVAuth
	ImageTypes           Images
	SendExistingImages   bool
	KeepDownloadedImages bool
	Context              context.Context
	StartDownloadQueue   chan<- dl.Download

	fileList       []string
	totalResults   int
	imageWG        sync.WaitGroup
	downloadQueue  chan *CVResult
	notFound       chan download
	chdb           ch.CHDB
	bufPool        *sync.Pool
	getID          func(id ch.ID) ch.IDList
	onlyHashNewIDs bool
}

var (
	ErrQuit         = errors.New("quit")
	ErrInvalidPage  = errors.New("invalid ComicVine page")
	ErrInvalidIndex = errors.New("invalid page index")
	ErrDownloadFail = errors.New("download failed")
	ErrMissingPage  = errors.New("page missing")
	ErrUpdateNeeded = errors.New("update needed")
)

func (c *CVDownloader) loadIssues(filename string) (*CVResult, error) {
	tmp := &CVResult{Results: make([]Issue, 0, 100)}
	file, err := os.Open(filepath.Join(c.basePath, jsonDirectory, filename))
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
	if getOffset(filename) != tmp.Offset {
		return nil, ErrInvalidPage
	}
	return tmp, nil
}

func getOffset(name string) int {
	i, _ := strconv.Atoi(name[3 : len(name)-1-4])
	return i
}

func (c *CVDownloader) findDownloadedPage(offset int) int {
	index := offset / 100
	if index < len(c.fileList) && getOffset(c.fileList[index]) == offset { // If it's in order and it's not missing it should be here
		return index
	}
	index, found := slices.BinarySearchFunc(c.fileList, offset, func(a string, b int) int {
		return cmp.Compare(getOffset(a), b)
	})
	if found {
		return index
	}
	return -1
}

func (c *CVDownloader) getDownloadedIssues(offset int, update bool) (*CVResult, error) {
	index := c.findDownloadedPage(offset)
	if index < 0 {
		return nil, ErrMissingPage
	}
	JSONPath := filepath.Join(c.basePath, jsonDirectory)
	issue, err := c.loadIssues(c.fileList[index])
	if err != nil || issue == nil {
		err = fmt.Errorf("failed to read page at offset %d: %w", offset, err)
		_ = os.Remove(filepath.Join(JSONPath, c.fileList[index]))
		c.fileList = slices.Delete(c.fileList, index, index+1)
		return nil, err
	}

	c.totalResults = max(c.totalResults, issue.NumberOfTotalResults)

	if update && (len(issue.Results) == 0 || issue.Results[0].IssueNumber == "") {
		err = fmt.Errorf("deleting page %d to update records from cv", offset)
		_ = os.Remove(filepath.Join(JSONPath, c.fileList[index]))
		c.fileList = slices.Delete(c.fileList, index, index+1)
		return nil, err
	}

	if c.totalResults-offset <= 100 {
		if index != len(c.fileList)-1 {
			err = fmt.Errorf("wrong index: expected %d got %d", len(c.fileList), index)
			return nil, err
		}
		log.Println("Deleting the last page to detect new comics on next run")
		_ = os.Remove(filepath.Join(JSONPath, c.fileList[index]))
		c.fileList = slices.Delete(c.fileList, index, index+1)
	}

	return issue, nil
}

// updateIssues  c.downloadQueue must not be closed before this function has returned
func (c *CVDownloader) updateIssues() (int, error) {
	baseURL, err := url.Parse("https://comicvine.gamespot.com/api/issues/?sort=date_added,id:asc&format=json&field_list=id,issue_number,image,volume")
	if err != nil {
		log.Fatal(err)
	}

	JSONPath := filepath.Join(c.basePath, jsonDirectory)
	c.totalResults = max(c.totalResults, 1)
	failCount := 0
	prev := -1
	offset := 0
	retry := func(url string, err error) bool {
		if errors.Is(err, context.Canceled) {
			log.Println("Server closed")
			return false
		}
		log.Printf("Failed to download %#v at offset %v: %v Attempt #%d", url, offset, err, failCount+1)
		if prev == offset {
			sleepTime := time.Second * 36
			if failCount > 2 {
				sleepTime = time.Minute * 10
			}
			log.Println("This page failed to download, lets wait for", sleepTime, "and hope it works")
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
	updated := 0
	for offset = 0; offset <= c.totalResults; offset += 100 {
		if c.hasQuit() {
			return offset - 100, ErrQuit
		}
		// Only update 9 existing pages at a time, assume that covers/issue ids are still accurate
		issue, err := c.getDownloadedIssues(offset, updated < 60)
		if err == nil && issue != nil {

			prev = -1
			failCount = 0
			select {
			case <-c.Context.Done(): // allows us to return immediately even during a timeout
				return offset - 100, ErrQuit
			case c.downloadQueue <- issue:
			}
			continue
		}
		if errors.Is(err, ErrInvalidIndex) {
			return offset - 100, err
		}
		if err != nil && !errors.Is(err, ErrMissingPage) {
			log.Println(err)
		}

		log.Println("Starting download at offset", offset)
		issue = &CVResult{}
		URI := (*baseURL)
		query := baseURL.Query()
		query.Add("offset", strconv.Itoa(offset))
		URI.RawQuery = query.Encode()

		select {
		case <-c.Context.Done(): // Allows us to return immediately even during a timeout
			return offset - 100, ErrQuit
		case <-time.After(10 * time.Second): // Enforces a minimum 10s wait between API hits
		}
		req, _ := http.NewRequest("GET", URI.String(), nil)
		c.APIKey.Apply(req)
		resp, cancelDownloadCTX, err := dl.Get(req)
		if err != nil {
			cancelDownloadCTX()
			if retry(URI.String(), err) {
				continue
			}
			// Fail and let comic-hasher try the whole thing again later
			return offset - 100, fmt.Errorf("%w: %w", ErrDownloadFail, err)
		}
		if resp.StatusCode != 200 {
			cancelDownloadCTX()
			if retry(URI.String(), nil) {
				_ = resp.Body.Close()
				continue
			}
			msg, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return offset - 100, fmt.Errorf("%w: response code: %d Message: %s", ErrDownloadFail, resp.StatusCode, string(msg))
		}

		file, err := os.Create(filepath.Join(JSONPath, "cv-"+strconv.Itoa(offset)+".json"))
		if err != nil {
			log.Fatal(err)
		}
		body := io.TeeReader(resp.Body, file)
		err = json.NewDecoder(bufio.NewReader(body)).Decode(issue)
		_ = resp.Body.Close()
		_ = file.Close()
		if err != nil || issue.Offset != offset {
			_ = os.Remove(filepath.Join(JSONPath, "cv-"+strconv.Itoa(offset)+".json"))
			cancelDownloadCTX()
			if retry(URI.String(), err) {
				continue
			}
			return offset - 100, fmt.Errorf("%w: %w", ErrDownloadFail, err)
		}
		cancelDownloadCTX()
		if issue.NumberOfTotalResults > c.totalResults {
			c.totalResults = issue.NumberOfTotalResults
		}
		prev = -1
		failCount = 0
		updated += 1
		c.downloadQueue <- issue
		c.insertIssuePage(offset)
		log.Printf("Downloaded %s/cv-%v.json", JSONPath, offset)
	}
	return offset, nil
}

type download struct {
	url      string
	dest     string
	offset   int
	volumeID int
	issueID  int
	finished bool
}

func (c *CVDownloader) handleNotFound() {
	for failedDownload := range c.notFound {
		c.chdb.AddURL(failedDownload.url)
		log.Printf("Not found: volumeID: %d issueID: %d Offset: %d URL: %s\n", failedDownload.volumeID, failedDownload.issueID, failedDownload.offset, failedDownload.url)
	}
}

func (c *CVDownloader) downloadImages() {
	defer func() {
		log.Println("Waiting for final images to complete download")
		c.imageWG.Wait()
	}()

	go c.handleNotFound()
	added := 0
	for list := range c.downloadQueue {
		c.processDownloadQueue(list, &added)
	}
}

func (c *CVDownloader) processDownloadQueue(list *CVResult, added *int) {
	for _, issue := range list.Results {
		imageURLs := []Image{{issue.Image.IconURL, "icon"}, {issue.Image.MediumURL, "medium"}, {issue.Image.ScreenURL, "screen"}, {issue.Image.ScreenLargeURL, "screenlarge"}, {issue.Image.SmallURL, "small"}, {issue.Image.SuperURL, "super"}, {issue.Image.ThumbURL, "thumb"}, {issue.Image.TinyURL, "tiny"}, {issue.Image.OriginalURL, "original"}}
		for _, image := range imageURLs {
			c.downloadImage(list, issue, image, added)
		}
		if *added > 200 {
			// On a clean single image type run each page would have 100 downloads of a single cover type but stuff happens so we only wait once we have sent 200 to the queue
			log.Println("waiting for", *added, "downloads at offset", list.Offset)
			beforeWait := time.Now()
			c.imageWG.Wait()
			waited := time.Since(beforeWait)
			*added = 0
			// If we had to wait for the arbitrarily picked time of 7.4 seconds it means we had a backed up queue (slow hashing can also cause it to wait longer), lets wait to give the CV servers a break
			if waited > time.Duration(7.4*float64(time.Second)) {
				t := 10 * time.Second
				log.Println("Waiting for", t, "at offset", list.Offset, "had to wait for", waited)
				time.Sleep(t) // TODO: why don't we allow canceling early here?
			} else {
				// Things are too fast we can't depend CV being slow to manage our download speed
				// We sleep for 3 seconds so we don't overload CV
				time.Sleep(3 * time.Second)
			}
		}
	}
}

type Image struct {
	url  string
	name string
}

func (c *CVDownloader) downloadImage(list *CVResult, issue Issue, image Image, added *int) {
	if _, imageAllowed := c.ImageTypes[image.name]; !imageAllowed {
		return
	}
	if c.chdb.CheckURL(image.url) {
		log.Printf("Skipping known bad url %s", image.url)
		return
	}
	if strings.HasSuffix(image.url, "6373148-blank.png") {
		c.notFound <- download{
			url:      image.url,
			offset:   list.Offset,
			volumeID: issue.Volume.ID,
			issueID:  issue.ID,
		}
		return
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
		return
	}
	ext := strings.TrimSuffix(strings.ToLower(path.Ext(uri.Path)), "~original")
	if ext == "" || (len(ext) > 4 && !slices.Contains([]string{".avif", ".webp", ".tiff", ".heif"}, ext)) {
		ext = ".jpg"
	}
	// Construct the relative path for the file
	// This is relative to to comic-hasher path. eg filepath.Join(c.basePath, "../")
	imagePath := filepath.Join(WorkDirectory, imageDirectory, strconv.Itoa(issue.Volume.ID), strconv.Itoa(issue.ID), image.name+ext)

	ids := c.getID(ch.ID{
		Domain: ch.NewSource(ch.ComicVine),
		ID:     strconv.Itoa(issue.ID),
	})
	buf := c.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	req, _ := http.NewRequest("GET", image.url, nil)
	if c.chdb.PathDownloaded(imagePath) || c.onlyHashNewIDs && len(ids) > 0 {
		if !c.SendExistingImages {
			return
		}
		if _, err = os.Stat(filepath.Join(c.basePath, imagePath)); err != nil {
			return // assume it's already been hashed and deleted
		}
		// We don't increment added as these should be processed immediately
		log.Printf("Sending Existing image %v/%v %v", issue.Volume.ID, issue.ID, imagePath)
		err = dl.ReadAll(imagePath, buf)
		if err != nil {
			log.Printf("Failed to read existing image %q: %v", imagePath, err)
			return // TODO: Handle the error?
		}
		c.imageWG.Add(1)

		c.StartDownloadQueue <- dl.Download{
			Request: req,
			Dest:    imagePath,
			IssueID: strconv.Itoa(issue.ID),
			Image:   buf,
			Done:    func(*http.Response) { c.imageWG.Done() },
		}
	}
	*added++

	c.imageWG.Add(1)
	c.StartDownloadQueue <- dl.Download{
		Request: req,
		Dest:    imagePath,
		IssueID: strconv.Itoa(issue.ID),
		Image:   buf,
		Done:    func(*http.Response) { c.imageWG.Done() },
	}
}

func (c *CVDownloader) cleanBadURLs() error {
	var indexesToRemove []int
	JSONPath := filepath.Join(c.basePath, jsonDirectory)
list:
	for i, jsonFile := range c.fileList {
		list, err := c.loadIssues(jsonFile)
		if err != nil {
			indexesToRemove = append(indexesToRemove, i)
			_ = os.Remove(filepath.Join(JSONPath, jsonFile))
			continue
		}
		for _, issue := range list.Results {
			for _, url := range []string{issue.Image.IconURL, issue.Image.MediumURL, issue.Image.ScreenURL, issue.Image.ScreenLargeURL, issue.Image.SmallURL, issue.Image.SuperURL, issue.Image.ThumbURL, issue.Image.TinyURL, issue.Image.OriginalURL} {
				if c.chdb.CheckURL(url) {
					indexesToRemove = append(indexesToRemove, i)
					if err := os.Remove(filepath.Join(JSONPath, jsonFile)); err != nil {
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

func (c *CVDownloader) cleanDirs() {
	_ = filepath.WalkDir(filepath.Join(c.basePath, imageDirectory), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			path, _ = filepath.Abs(path)
			err := ch.RmdirP(path)
			// The error is only for the first path value. EG ch.RmdirP("/test/t") will only return the error for os.Remove("/test/t") not os.Remove("test")
			if err == nil {
				return filepath.SkipDir
			}
		}
		return nil
	})
}

func (c *CVDownloader) insertIssuePage(offset int) {
	index, found := slices.BinarySearchFunc(c.fileList, offset, func(a string, b int) int {
		return cmp.Compare(getOffset(a), b)
	})
	if found {
		return
	}
	c.fileList = slices.Insert(c.fileList, index, fmt.Sprintf("cv-%v.json", offset))
}

func NewCVDownloader(
	ctx context.Context,
	version string,
	bufPool *sync.Pool,
	onlyHashNewIDs bool,
	getID func(id ch.ID) ch.IDList,
	chdb ch.CHDB,
	basePath, APIKey string,
	imageTypes Images,
	keepDownloadedImages, sendExistingImages bool,
	startDownloadQueue chan<- dl.Download,
) *CVDownloader {
	return &CVDownloader{
		basePath:             basePath,
		Context:              ctx,
		version:              version,
		APIKey:               new(CVAuth(APIKey)),
		bufPool:              bufPool, // The buffers get sent back via finishedDownloadQueue
		StartDownloadQueue:   startDownloadQueue,
		SendExistingImages:   sendExistingImages,
		KeepDownloadedImages: keepDownloadedImages,
		ImageTypes:           imageTypes,
		chdb:                 chdb,
		getID:                getID,
		onlyHashNewIDs:       onlyHashNewIDs,
	}
}

func DownloadCovers(c *CVDownloader) {
	var err error
	c.downloadQueue = make(chan *CVResult) // This is just json it shouldn't take up much more than 122 MB
	c.notFound = make(chan download, 1)    // Same here
	JSONPath := filepath.Join(c.basePath, jsonDirectory)
	ImagePath := filepath.Join(c.basePath, imageDirectory)
	_ = os.MkdirAll(JSONPath, 0o777)
	f, _ := os.Create(filepath.Join(ImagePath, ".keep"))
	_ = f.Close()
	if !c.KeepDownloadedImages {
		log.Println("Cleaning directories")
		c.cleanDirs()
	}
	log.Println("Reading json")
	var d *os.File
	d, err = os.Open(JSONPath)
	if err != nil {
		panic(fmt.Errorf("unable to open path for json files: %w", err))
	}
	c.fileList, err = d.Readdirnames(-1)
	if err != nil {
		panic(fmt.Errorf("unable to read directory for json files: %w", err))
	}
	for i := len(c.fileList) - 1; i >= 0; i-- {
		if !strings.Contains(c.fileList[i], "json") {
			c.fileList = slices.Delete(c.fileList, i, i+1)
		}
	}

	slices.SortFunc(c.fileList, func(x, y string) int {
		return cmp.Compare(getOffset(x), getOffset(y))
	})
	if len(c.fileList) > 0 {
		c.totalResults = getOffset(c.fileList[len(c.fileList)-1])
	}
	log.Println("Number of pages", len(c.fileList), "Expected Pages:", c.totalResults/100)
	log.Println("Updating issues now")

	dwg := sync.WaitGroup{}
	dwg.Go(c.downloadImages)

	offset, err := c.updateIssues()
	if err != nil {
		log.Printf("Failed to download CV Covers: %s", err)
	}
	issueCount := len(c.fileList) * 100

	log.Println("Number of issues", issueCount, " expected:", c.totalResults)

	close(c.downloadQueue) // sends only happen in c.updateIssues which has already been called
	// We don't drain here as we want to process them

	log.Println("Waiting for downloaders")
	dwg.Wait()
	close(c.notFound)
	for dw := range c.notFound {
		fmt.Println("Skipping not found", dw.issueID)
	}

	// We drain this at the end because we need to wait for the images to download
	for dw := range c.downloadQueue {
		fmt.Println("Skipping page download", dw.Offset)
	}

	log.Println("Completed downloading images")
	log.Println("Last offset", offset)
}
