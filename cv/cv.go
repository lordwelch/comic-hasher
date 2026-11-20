// Package cv
package cv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	dl "gitea.narnian.us/lordwelch/comic-hasher/download"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
	"gitea.narnian.us/lordwelch/comic-hasher/metron"
	minlz "github.com/minio/minlz"
	bolt "go.etcd.io/bbolt"
)

var logger = log.NewLogger("comicvine", "downloads")

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
	ID          int64  `json:"id"`
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
		ID int64 `json:"id"`
	} `json:"volume"`
}

type CVResult struct {
	Offset               int64   `json:"offset"`
	NumberOfPageResults  int     `json:"number_of_page_results"`
	NumberOfTotalResults int64   `json:"number_of_total_results"`
	StatusCode           int     `json:"status_code"`
	Results              []Issue `json:"results"`
}

const (
	WorkDirectory  = "comicvine"
	imageDirectory = "_image"
	jsonDirectory  = "_json"

	BucketIssue     = "issues"
	BucketPageCache = "page cache"
	BucketMeta      = "metadata"

	KeyTotalResults = "total_results"

	DBVersion        = "1.0.0"
	PageCacheVersion = "1.0.0"
)

type Downloader struct {
	basePath              string
	version               string
	APIKey                *CVAuth
	ImageTypes            Images
	SendExistingImages    bool
	KeepDownloadedImages  bool
	Context               context.Context
	FinishedDownloadQueue chan<- dl.Download
	StartDownloadQueue    chan dl.Download

	DB        Bolt
	PageCache Bolt

	fileList       []string
	totalResults   int64
	imageWG        sync.WaitGroup
	cvIssueQueue   chan *CVResult
	notFound       chan failedDownload
	chdb           ch.CHDB
	bufPool        *sync.Pool
	getID          func(id ch.ID) []ch.ID
	onlyHashNewIDs bool
}

var (
	ErrQuit         = errors.New("quit")                   // Context has been canceled
	ErrInvalidPage  = errors.New("invalid ComicVine page") // This page did not decode as valid json
	ErrMissingPage  = errors.New("page missing")           // This page hasn't been downloaded yet
	ErrUpdateNeeded = errors.New("update needed")          // We deleted this page because we want to download it again
	ErrDownloadFail = errors.New("download failed")
)

// Key is a key to an item in a bolt bucket
type Key string

type Bolt struct {
	ch.Bolt
}

// decodeBuf is the static array Issue functions decompress into.

// Issue returns the issue stored under id in tx. Issue data is decoded into
// the static decodeBuf.
func (b Bolt) Issue(tx *bolt.Tx, id int64) Issue {
	var issue Issue
	if tx == nil {
		b.View(func(tx *bolt.Tx) error {
			issue = b.Issue(tx, id)
			return nil
		})
		return issue
	}
	var decodeBuf [2048]byte
	bucket := tx.Bucket([]byte(BucketIssue))
	if bucket == nil {
		return Issue{}
	}
	value := bucket.Get(ch.IntToBolt(id))
	if ok, _, err := minlz.IsMinLZ(value); err == nil && ok {
		decoded, err := minlz.Decode(decodeBuf[:0], value)
		if err != nil {
			return Issue{}
		}
		value = decoded
	}
	if err := json.Unmarshal(value, &issue); err != nil {
		return Issue{}
	}
	return issue
}

func (b Bolt) PutIssue(tx *bolt.Tx, issue Issue) error {
	if tx == nil {
		return b.Update(func(tx *bolt.Tx) error {
			return b.PutIssue(tx, issue)
		})
	}

	content, err := json.Marshal(issue)
	if err != nil {
		return fmt.Errorf("failed to convert issue to bytes: %w", err)
	}
	content, err = minlz.AppendEncoded(nil, content, minlz.LevelFastest)
	if err != nil {
		return fmt.Errorf("failed to compress issue: %w", err)
	}
	return tx.Bucket([]byte(BucketIssue)).Put(ch.IntToBolt(issue.ID), content)
}

func (b Bolt) Get(bucket string, key []byte) []byte {
	buf := make([]byte, 0, 16)
	err := b.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(bucket))
		if bkt == nil {
			return nil
		}
		buf = append(buf, bkt.Get([]byte(key))...)
		return nil
	})
	if err != nil {
		return nil
	}
	return buf
}

func (b Bolt) Put(bucket string, key []byte, value []byte) error {
	return b.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Put([]byte(key), value)
	})
}

func (b Bolt) Delete(bucket, key string) error {
	return b.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Delete([]byte(key))
	})
}

func (b Bolt) TotalResults() int64 {
	data := b.Get(BucketMeta, []byte(KeyTotalResults))
	if len(data) == 0 {
		return 0
	}
	return int64(ch.BoltToInt(data))
}

func (b Bolt) PutTotalResults(n int64) error {
	return b.Put(BucketMeta, []byte(KeyTotalResults), ch.IntToBolt(n))
}

func OpenBolt(path string, version ch.Version, buckets []string) (Bolt, error) {
	b, err := ch.OpenBolt(path, version, buckets)
	if err != nil {
		return Bolt{b}, err
	}
	return Bolt{b}, nil
}

func getOffset(name string) int {
	i, _ := strconv.Atoi(name[3 : len(name)-1-4])
	return i
}

func (c *Downloader) GetIssue(id ch.ID) (ch.Issue, error) {
	idInt, err := strconv.Atoi(id.ID)
	if err != nil {
		return ch.Issue{}, fmt.Errorf("invalid ID: %w", err)
	}
	i := c.DB.Issue(nil, int64(idInt))
	url := ""
	for _, issueImage := range []Image{
		{i.Image.SmallURL, "small"},
		{i.Image.ThumbURL, "thumb"},
		{i.Image.TinyURL, "tiny"},
		{i.Image.IconURL, "icon"},
		{i.Image.MediumURL, "medium"},
		{i.Image.ScreenURL, "screen"},
		{i.Image.ScreenLargeURL, "screenlarge"},
		{i.Image.SuperURL, "super"},
		{i.Image.OriginalURL, "original"},
	} {
		if issueImage.url != "" {
			url = issueImage.url
			break
		}
	}
	if url == "" {
		return ch.Issue{}, fmt.Errorf("unable to find issue: %v", id)
	}
	return ch.Issue{id, url}, nil
}

func (c *Downloader) getCachedPage(offset int64, update bool) (*CVResult, error) {
	data := ch.DecompressMinLZ(c.PageCache.Get(BucketPageCache, ch.IntToBolt(offset)))
	if len(data) == 0 {
		return nil, ErrMissingPage
	}
	issue := &CVResult{Results: make([]Issue, 0, 100)}
	if err := json.Unmarshal(data, issue); err != nil {
		c.PageCache.Delete(BucketPageCache, "cv-"+strconv.FormatInt(offset, 10))
		return nil, fmt.Errorf("failed to read page at offset %d: %w", offset, err)
	}
	if issue.Offset != offset {
		c.PageCache.Delete(BucketPageCache, "cv-"+strconv.FormatInt(offset, 10))
		return nil, ErrInvalidPage
	}

	c.totalResults = max(c.totalResults, issue.NumberOfTotalResults)
	c.totalResults = max(c.totalResults, c.PageCache.TotalResults())

	if update && (len(issue.Results) == 0 || (len(issue.Results) > 0 && issue.Results[0].IssueNumber == "")) {
		c.PageCache.Delete(BucketPageCache, "cv-"+strconv.FormatInt(offset, 10))
	}

	if c.totalResults-offset <= 100 {
		c.PageCache.Delete(BucketPageCache, "cv-"+strconv.FormatInt(offset, 10))
	}

	return issue, nil
}

// downloadIssues  c.downloadQueue must not be closed before this function has returned
func (c *Downloader) downloadIssues() (int64, error) {
	c.totalResults = max(c.totalResults, 1)
	var failCount int64 = 0
	var prev int64 = -1
	var offset int64 = 0
	retry := func(url string, err error) bool {
		if errors.Is(err, context.Canceled) {
			logger.Println(log.MoreVerbose, "Server closed")
			return false
		}
		logger.Log(log.Standard, "Failed to download %#v at offset %v: %v Attempt #%d", url, offset, err, failCount+1)
		if prev == offset {
			sleepTime := time.Second * 36
			if failCount > 2 {
				sleepTime = time.Minute * 10
			}
			logger.Println(log.Standard, "This page failed to download, lets wait for", sleepTime, "and hope it works")
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
		logger.Log(log.MoreVerbose, "Checking page offset %d/%d", offset, c.totalResults)
		// Only update 9 existing pages at a time, assume that covers/issue ids are still accurate
		issue, err := c.getCachedPage(offset, updated < 60)
		if err == nil && issue != nil {

			prev = -1
			failCount = 0
			select {
			case c.cvIssueQueue <- issue:
			case <-c.Context.Done(): // allows us to return immediately even during a timeout
				return offset - 100, ErrQuit
			}
			continue
		}
		if err != nil && !errors.Is(err, ErrMissingPage) {
			logger.Println(log.Required, err)
		}

		logger.Println(log.Verbose, "Starting download at offset", offset)
		select {
		case <-c.Context.Done(): // Allows us to return immediately even during a timeout
			return offset - 100, ErrQuit
		case <-time.After(10 * time.Second): // Enforces a minimum 10s wait between API hits
		}
		body, err := c.getPage(offset)
		if err != nil {
			if retry("cv-"+strconv.FormatInt(offset, 10), err) {
				continue
			}
			return offset - 100, fmt.Errorf("%w: %w", ErrDownloadFail, err)
		}
		issue = &CVResult{}
		if err := json.Unmarshal(body, issue); err != nil || issue.Offset != offset {
			c.PageCache.Delete(BucketPageCache, "cv-"+strconv.FormatInt(offset, 10))
			if retry("cv-"+strconv.FormatInt(offset, 10), err) {
				continue
			}
			return offset - 100, fmt.Errorf("%w: %w", ErrDownloadFail, err)
		}
		if issue.NumberOfTotalResults > c.totalResults {
			c.totalResults = issue.NumberOfTotalResults
			c.PageCache.PutTotalResults(c.totalResults)
		}
		prev = -1
		failCount = 0
		updated += 1
		c.cvIssueQueue <- issue
		logger.Log(log.Standard, "Downloaded page at offset %v", offset)
	}
	return offset, nil
}

type failedDownload struct {
	url      string
	offset   int64
	volumeID int64
	issueID  int64
}

func (c *Downloader) handleNotFound() {
	for failedDownload := range c.notFound {
		c.chdb.AddURL(failedDownload.url)
		logger.Log(log.Verbose, "Not found: volumeID: %d issueID: %d Offset: %d URL: %s", failedDownload.volumeID, failedDownload.issueID, failedDownload.offset, failedDownload.url)
	}
}

func (c *Downloader) processCVIssues() {
	defer func() {
		logger.Println(log.Standard, "Waiting for final images to complete download")
		c.imageWG.Wait()
	}()

	go c.handleNotFound()
	added := 0
	for list := range c.cvIssueQueue {
		c.processDownloadQueue(list, &added)
	}
}

func (c *Downloader) processDownloadQueue(list *CVResult, added *int) {
	c.DB.DB.Update(func(tx *bolt.Tx) error {
		for _, issue := range list.Results {
			_ = c.DB.PutIssue(tx, issue)
		}
		return nil
	}) // This is only for the web so not critical
	for _, issue := range list.Results {
		imageURLs := []Image{{issue.Image.IconURL, "icon"}, {issue.Image.MediumURL, "medium"}, {issue.Image.ScreenURL, "screen"}, {issue.Image.ScreenLargeURL, "screenlarge"}, {issue.Image.SmallURL, "small"}, {issue.Image.SuperURL, "super"}, {issue.Image.ThumbURL, "thumb"}, {issue.Image.TinyURL, "tiny"}, {issue.Image.OriginalURL, "original"}}
		for _, image := range imageURLs {
			c.startCoverDownload(list, issue, image, added)
		}
		if *added > 200 {
			// On a clean single image type run each page would have 100 downloads of a single cover type but stuff happens so we only wait once we have sent 200 to the queue
			logger.Println(log.Verbose, "waiting for", *added, "downloads at offset", list.Offset)
			beforeWait := time.Now()
			c.imageWG.Wait()
			waited := time.Since(beforeWait)
			*added = 0
			// If we had to wait for the arbitrarily picked time of 7.4 seconds it means we had a backed up queue (slow hashing can also cause it to wait longer), lets wait to give the CV servers a break
			if waited > time.Duration(7.4*float64(time.Second)) {
				t := 10 * time.Second
				logger.Println(log.Verbose, "Waiting for", t, "at offset", list.Offset, "had to wait for", waited)
				select {
				case <-time.After(t):
				case <-c.Context.Done():
					return
				}
			} else {
				// Things are too fast we can't depend on CV being slow to manage our download speed
				// We sleep for 3 seconds so we don't overload CV
				select {
				case <-time.After(3 * time.Second):
				case <-c.Context.Done():
					return
				}
			}
		}
	}
}

type Image struct {
	url  string
	name string
}

func (c *Downloader) startCoverDownload(list *CVResult, issue Issue, image Image, added *int) {
	if _, imageAllowed := c.ImageTypes[image.name]; !imageAllowed {
		return
	}
	if c.chdb.CheckURL(image.url) {
		logger.Log(log.Verbose, "Skipping known bad url %s", image.url)
		return
	}
	if strings.HasSuffix(image.url, "6373148-blank.png") {
		c.notFound <- failedDownload{
			url:      image.url,
			offset:   list.Offset,
			volumeID: issue.Volume.ID,
			issueID:  issue.ID,
		}
		return
	}

	uri, err := url.ParseRequestURI(image.url)
	if err != nil {
		c.notFound <- failedDownload{
			url:      image.url,
			offset:   list.Offset,
			volumeID: issue.Volume.ID,
			issueID:  issue.ID,
		}
		return
	}
	ext := strings.TrimSuffix(strings.ToLower(path.Ext(uri.Path)), "~original")
	if ext == "" || (len(ext) > 4 && !slices.Contains([]string{".avif", ".webp", ".tiff", ".heif"}, ext)) {
		ext = ".jpg"
	}
	// Construct the relative path for the file
	// This is relative to to comic-hasher path. eg filepath.Join(c.basePath, "../")
	imagePath := filepath.Join(imageDirectory, strconv.FormatInt(issue.Volume.ID, 10), strconv.FormatInt(issue.ID, 10), image.name+ext)

	existingIDs := c.getID(ch.ID{
		Domain: ch.NewSource(ch.ComicVine),
		ID:     strconv.FormatInt(issue.ID, 10),
	})
	buf := c.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	req, _ := http.NewRequest("GET", image.url, nil)
	if c.chdb.PathDownloaded(filepath.Join(WorkDirectory, imagePath)) || c.onlyHashNewIDs && len(existingIDs) > 0 {
		if !c.SendExistingImages {
			return
		}
		if _, err = os.Stat(filepath.Join(c.basePath, imagePath)); err != nil {
			return // assume it's already been hashed and deleted
		}
		// We don't increment added as these should be processed immediately
		logger.Log(log.Standard, "Sending Existing image %v/%v %v", issue.Volume.ID, issue.ID, imagePath)
		err = dl.ReadAll(filepath.Join(c.basePath, imagePath), buf)
		if err != nil {
			logger.Log(log.Standard, "Failed to read existing image %q: %v", imagePath, err)
			return // TODO: Handle the error?
		}
		c.imageWG.Add(1)

		c.StartDownloadQueue <- dl.Download{
			Request: req,
			Dest:    filepath.Join(WorkDirectory, imagePath),
			IssueID: ch.ID{Domain: ch.NewSource("comicvine.gamespot.com"), ID: strconv.FormatInt(issue.ID, 10)},
			Image:   buf,
			Done:    func(*http.Response) { c.imageWG.Done() },
		}
		return
	}
	*added++

	c.imageWG.Add(1)
	c.StartDownloadQueue <- dl.Download{
		Request: req,
		Dest:    filepath.Join(WorkDirectory, imagePath), // TODO: somehow put in a check for this. It's too easy to forget WorkDirectory. Maybe always make it relative to basePath
		IssueID: ch.ID{Domain: ch.NewSource(ch.ComicVine), ID: strconv.FormatInt(issue.ID, 10)},
		Image:   buf,
		Done:    func(*http.Response) { c.imageWG.Done() },
	}
}

func (c *Downloader) cleanBadURLs() error {
	var toDelete [][]byte
	var page CVResult
	c.PageCache.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketPageCache))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if !bytes.HasPrefix(k, []byte("cv-")) {
				toDelete = append(toDelete, bytes.Clone(k))
				return nil
			}
			if err := json.Unmarshal(ch.DecompressMinLZ(v), &page); err != nil {
				toDelete = append(toDelete, bytes.Clone(k))
				return nil
			}
			for _, iss := range page.Results {
				if slices.ContainsFunc([]string{iss.Image.IconURL, iss.Image.MediumURL, iss.Image.ScreenURL, iss.Image.ScreenLargeURL, iss.Image.SmallURL, iss.Image.SuperURL, iss.Image.ThumbURL, iss.Image.TinyURL, iss.Image.OriginalURL}, c.chdb.CheckURL) {
					toDelete = append(toDelete, bytes.Clone(k))
					return nil
				}
			}
			return nil
		})
	})
	c.PageCache.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketPageCache))
		if b == nil {
			return nil
		}
		for _, key := range toDelete {
			err := b.Delete(key)
			if err != nil {
				return fmt.Errorf("failed to delete page: %v: %w", ch.BoltToInt(key), err)
			}
		}
		return nil
	})
	return nil
}

var baseURL = metron.MustParseURL("https://comicvine.gamespot.com/api/issues/?sort=date_added,id:asc&format=json&field_list=id,issue_number,image,volume")

func (c *Downloader) getPage(offset int64) ([]byte, error) {
	if data := ch.DecompressMinLZ(c.PageCache.Get(BucketPageCache, ch.IntToBolt(offset))); len(data) > 0 {
		return data, nil
	}
	URI := *baseURL
	q := baseURL.Query()
	q.Add("offset", strconv.FormatInt(offset, 10))
	URI.RawQuery = q.Encode()
	req, _ := http.NewRequest("GET", URI.String(), nil)
	c.APIKey.Apply(req)
	resp, cancel, err := dl.Get(c.Context, req)
	if err != nil {
		cancel()
		return nil, err
	}
	defer cancel()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return body, fmt.Errorf("response code: %d", resp.StatusCode)
	}
	toStore, err := minlz.AppendEncoded(nil, body, minlz.LevelFastestSIMD)
	if err != nil {
		return body, fmt.Errorf("failed to compress page: %w", err)
	}
	if err := c.PageCache.Put(BucketPageCache, ch.IntToBolt(offset), toStore); err != nil {
		return body, err
	}
	var issue CVResult
	if err := json.Unmarshal(body, &issue); err == nil {
		if issue.NumberOfTotalResults > c.totalResults {
			c.totalResults = issue.NumberOfTotalResults
			c.PageCache.PutTotalResults(c.totalResults)
		}
	}
	return body, nil
}

func (c *Downloader) hasQuit() bool {
	select {
	case <-c.Context.Done():
		return true
	default:
		return false
	}
}

func (c *Downloader) cleanDirs() {
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

func (c *Downloader) Close() error {
	c.PageCache.Close()
	c.DB.Close()
	return nil
}

func NewCVDownloader(
	version string,
	bufPool *sync.Pool,
	onlyHashNewIDs bool,
	getID func(id ch.ID) []ch.ID,
	chdb ch.CHDB,
	basePath, APIKey string,
	imageTypes Images,
	keepDownloadedImages, sendExistingImages bool,
	finishedDownloadQueue chan<- dl.Download,
) (*Downloader, error) {
	c := &Downloader{
		basePath:              basePath,
		version:               version,
		APIKey:                new(CVAuth(APIKey)),
		bufPool:               bufPool, // The buffers get sent back via finishedDownloadQueue
		FinishedDownloadQueue: finishedDownloadQueue,
		SendExistingImages:    sendExistingImages,
		KeepDownloadedImages:  keepDownloadedImages,
		ImageTypes:            imageTypes,
		chdb:                  chdb,
		getID:                 getID,
		onlyHashNewIDs:        onlyHashNewIDs,
	}
	var err error
	_ = os.MkdirAll(c.basePath, 0o777)
	// Open comicvine bolt
	c.DB, err = OpenBolt(filepath.Join(c.basePath, "comicvine.bolt"), DBVersion, []string{BucketIssue, BucketMeta})
	if err != nil {
		logger.Log(log.Fatal, "failed to open comicvine database: %v", err)
		return nil, err
	}
	// JSONPath := filepath.Join(c.basePath, jsonDirectory)
	// if entries, err := os.ReadDir(JSONPath); err == nil {
	// 	for _, e := range entries {
	// 		if !strings.HasSuffix(e.Name(), ".json") {
	// 			continue
	// 		}
	// 		data, err := os.ReadFile(filepath.Join(JSONPath, e.Name()))
	// 		if err != nil {
	// 			continue
	// 		}
	// 		var issue CVResult
	// 		if err := json.Unmarshal(data, &issue); err == nil {
	// 			c.DB.Update(func(tx *bolt.Tx) error {
	// 				for _, is := range issue.Results {
	// 					_ = c.DB.PutIssue(tx, is)
	// 				}
	// 				return nil
	// 			})
	// 			if issue.NumberOfTotalResults > c.totalResults {
	// 				c.totalResults = issue.NumberOfTotalResults
	// 			}
	// 		}
	// 	}
	// 	err = c.DB.CompactQuietly()
	// 	if err != nil {
	// 		logger.Log(log.Standard, "Failed to compact DB during migration: %w", err)
	// 		return c, fmt.Errorf("Failed to compact DB during migration: %w", err)
	// 	}
	// }
	return c, nil
}

func DownloadCovers(ctx context.Context, c *Downloader) {
	var err error
	c.Context = log.NewContext(ctx, logger)

	c.StartDownloadQueue = make(chan dl.Download, 1)
	c.cvIssueQueue = make(chan *CVResult)     // This is just json it shouldn't take up much more than 122 MB
	c.notFound = make(chan failedDownload, 1) // Same here
	ImagePath := filepath.Join(c.basePath, imageDirectory)
	_ = os.MkdirAll(ImagePath, 0o777)
	f, _ := os.Create(filepath.Join(ImagePath, ".keep"))
	_ = f.Close()
	if !c.KeepDownloadedImages {
		logger.Println(log.Verbose, "Cleaning directories")
		c.cleanDirs()
	}
	c.DB.CompactQuietly()

	// Open page cache bolt
	c.PageCache, err = OpenBolt(filepath.Join(c.basePath, "page_cache.bolt"), PageCacheVersion, []string{BucketPageCache, BucketMeta})
	if err != nil {
		logger.Log(log.Fatal, "failed to open page cache database: %v", err)
		return
	}
	defer c.PageCache.Close()

	// Migration from _json files
	JSONPath := filepath.Join(c.basePath, jsonDirectory)
	if entries, err := os.ReadDir(JSONPath); err == nil {
		c.PageCache.DB.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(BucketPageCache))
			for _, e := range entries {
				if !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(JSONPath, e.Name()))
				if err != nil {
					continue
				}
				var issue CVResult
				if err := json.Unmarshal(data, &issue); err == nil {
					c.DB.DB.Update(func(tx *bolt.Tx) error {
						for _, is := range issue.Results {
							_ = c.DB.PutIssue(tx, is)
						}
						return nil
					})
					if issue.NumberOfTotalResults > c.totalResults {
						c.totalResults = issue.NumberOfTotalResults
					}
				}
				off := getOffset(e.Name())
				if data, err = minlz.AppendEncoded(nil, data, minlz.LevelFastest); err != nil {
					return fmt.Errorf("failed to compress page %q: %w", e.Name(), err)
				}
				err = bucket.Put(ch.IntToBolt(off), data)
				if err != nil {
					return err
				}
				os.Remove(filepath.Join(JSONPath, e.Name()))
			}
			return nil
		})
		err = c.PageCache.CompactQuietly()
		if err != nil {
			logger.Log(log.Standard, "Failed to compact PageCache during migration: %w", err)
			return
		}
		err = c.DB.CompactQuietly()
		if err != nil {
			logger.Log(log.Standard, "Failed to compact DB during migration: %w", err)
			return
		}
	}

	c.totalResults = max(c.totalResults, c.PageCache.TotalResults())
	if c.totalResults == 0 {
		c.totalResults = 1
	}
	logger.Println(log.Verbose, "Number of pages (cached)", log.FormatInt(len(c.fileList)), "Expected Pages:", log.FormatInt(c.totalResults/100))
	logger.Println(log.Standard, "Updating ComicVine issues now")

	pwg := sync.WaitGroup{}
	dwg := sync.WaitGroup{}
	pwg.Go(c.processCVIssues)
	for i := range 5 {
		dwg.Go(func() {
			dl.Worker(c.Context, c.chdb, filepath.Dir(c.basePath), c.KeepDownloadedImages, c.StartDownloadQueue, c.FinishedDownloadQueue, i)
		})
	}

	offset, err := c.downloadIssues()
	if err != nil {
		// This function can't return an error and should be "self-contained"
		// log the error and finish cleanup
		logger.Log(log.Fatal, "Failed to download new CV Issues: %s", err)
	}
	issueCount := (c.totalResults / 100) * 100

	logger.Println(log.Standard, "Number of issues", log.FormatInt(issueCount), " expected:", log.FormatInt(c.totalResults))

	close(c.cvIssueQueue) // sends only happen in c.updateIssues which has already been called
	// We don't drain here as we want to process them. And we get here from a successful run

	logger.Println(log.Standard, "Waiting for issue processor")
	pwg.Wait()
	close(c.StartDownloadQueue) // Sends only happen in processCVIssues -> processDownloadQueue -> startCoverDownload
	close(c.notFound)           // Sends only happen in startCoverDownload

	logger.Println(log.Standard, "Waiting for cover downloaders")
	dwg.Wait()
	for dw := range c.notFound {
		log.Println(log.MoreVerbose, "Skipping not found", dw.issueID)
	}

	// We drain at the end because we need to wait for the images to download on a successful run
	// A failed run or a requested quit will exit all go-routines early without processing so we still need to drain
	for dw := range c.cvIssueQueue {
		log.Println(log.MoreVerbose, "Skipping page download", dw.Offset)
	}
	for dload := range c.StartDownloadQueue {
		log.Println(log.MoreVerbose, "Skipping cover download", dload.Request.URL)
	}

	logger.Println(log.Standard, "Completed downloading covers")
	logger.Println(log.MoreVerbose, "Last offset", offset)
}
