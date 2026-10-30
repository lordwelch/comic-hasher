// Package metron
package metron

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
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
	"github.com/go-json-experiment/json"
	bolt "go.etcd.io/bbolt"
)

var logger = log.NewLogger("metron", "downloads")

// Buckets
const (
	BUCKET_ISSUE      = "issues"
	BUCKET_PAGE_CACHE = "page cache"
	BUCKET_META       = "metadata"
)

// Keys
const (
	KEY_CURRENT_START_DATE Key = "current start date" // We may get interupted before we get a full run done so we need to keep track of the current run and the next run
	KEY_NEXT_START_DATE    Key = "next start date"    // The date that this run was originally started, that way we aren't crawling the entire site repeatedly
	KEY_MAX_ID             Key = "max issue id"       // After we have a first run: c.StartDate.IsZero() != true this is an optimization to skip processing
	// KEY_NEXT_PAGE          Key = "next page"          // Url to the next page according to the last c.StartDate
	KEY_RETRY_DATE Key = "retry date" // Date given by api to try again on
)

var BaseURL = MustParseURL("https://metron.cloud/api/")

const (
	WorkDirectory   = "metron"
	imageDirectory  = "_image"
	TimestampLayout = "2006-01-02T15:04:05.999999-07:00"

	DB_VERSION         = "1.0.1"
	PAGE_CACHE_VERSION = "1.0.0"
)

var (
	ErrRetry = errors.New("Retry")
	errExit  = errors.New("EXIT")
)

// const defaultLimit = 5000 / rate.Limit(time.Hour*24)

var JsonOpts = []json.Options{
	json.ExperimentalSupportFormatTag(true),
	json.WithMarshalers(json.JoinMarshalers(
		json.MarshalToFunc(URLEncoder),
	)),
	json.WithUnmarshalers(json.JoinUnmarshalers(
		json.UnmarshalFromFunc(URLDecoder),
	)),
}

type Auth string

func (a Auth) Apply(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+string(a))
}

func URLDecoder(dec *jsontext.Decoder, u *url.URL) error {
	if k := dec.PeekKind(); k != jsontext.KindString {
		if k == jsontext.KindNull {
			_, err := dec.ReadValue()
			return err
		}
		return &json.SemanticError{JSONKind: k}
	}
	strURL := ""
	err := json.UnmarshalDecode(dec, &strURL)
	if err != nil {
		return err
	}
	tmpURL, err := url.Parse(strURL)
	if err != nil {
		return err
	}
	*u = *tmpURL
	return nil
}

func URLEncoder(enc *jsontext.Encoder, u url.URL) error {
	return enc.WriteToken(jsontext.String(u.String()))
}

type Series struct {
	ID        int64  `json:"id"`         // 3856
	Name      string `json:"Name"`       // "The 06 Protocol"
	Volume    int    `json:"Volume"`     // 1
	YearBegan int    `json:"year_began"` // 2022
}

type Issue struct {
	Series    Series    `json:"series"`
	ID        int64     `json:"id"`                                                 // 52529
	Number    string    `json:"number"`                                             // "1"
	Issue     string    `json:"issue"`                                              // "The 06 Protocol (2022) #1"
	CoverDate time.Time `json:"cover_date,format:'2006-01-02'"`                     // "2022-09-01"
	StoreDate time.Time `json:"store_date,format:'2006-01-02'"`                     // "2022-09-14"
	Image     url.URL   `json:"image"`                                              // "https://static.metron.cloud/media/issue/2022/09/19/6-protocol-1.jpg"
	Coverhash string    `json:"cover_hash"`                                         // "e9529e3586ca6b34"
	Modified  time.Time `json:"modified,format:'2006-01-02T15:04:05.999999-07:00'"` // "2024-12-23T16:17:29.333263-05:00"
}
type ResultList struct {
	Count    int     `json:"count"`    // 123
	Next     url.URL `json:"next"`     // "http://api.example.org/accounts/?page=4",
	Previous url.URL `json:"previous"` // "http://api.example.org/accounts/?page=2",
	Results  []Issue `json:"results"`
}

// 2ced2bae14967e9a1d4f80d94f64de6bfdef2ea477ecb5a85d8dfa05c1fe92e4
type Downloader struct {
	Context context.Context

	basePath             string
	version              string
	SendExistingImages   bool
	KeepDownloadedImages bool
	onlyHashNewIDs       bool
	StartDownloadQueue   chan dl.Download
	FinishDownloadQueue  chan<- dl.Download
	Auth                 Auth

	DB        Bolt
	PageCache Bolt
	StartDate time.Time

	totalResults int
	// notFound       chan download
	chdb    ch.CHDB
	bufPool *sync.Pool
	getID   func(id ch.ID) []ch.ID
}

// Key is a key to an item in a bolt bucket
type Key string

type Bolt struct {
	ch.Bolt
}

func (m Bolt) Issue(id int64) Issue {
	var issue Issue
	err := m.DB.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte(BUCKET_ISSUE)).Get(ch.IntToBolt(id)), &issue, JsonOpts...)
	})
	if err != nil {
		return Issue{
			ID: -1,
		}
	}
	return issue
}

// The metron api is a list of `Issue` and must be parsed out,
// we will never really have access to the original bytes
// so we just need to validate that this doesn't break the format
func (m Bolt) PutIssue(issue Issue) error {
	return m.DB.Update(func(tx *bolt.Tx) error {
		if issue == (Issue{}) {
			return tx.Bucket([]byte(BUCKET_ISSUE)).Delete(ch.IntToBolt(issue.ID))
		}
		content, err := json.Marshal(issue, JsonOpts...)
		if err != nil {
			return fmt.Errorf("failed to convert issue to bytes: %w", err)
		}
		return tx.Bucket([]byte(BUCKET_ISSUE)).Put(ch.IntToBolt(issue.ID), content)
	})
}

func (m Bolt) Date(key Key) time.Time {
	var startDate time.Time
	err := m.DB.View(func(tx *bolt.Tx) error {
		return startDate.UnmarshalBinary(tx.Bucket([]byte(BUCKET_META)).Get([]byte(key)))
	})
	if err != nil {
		return time.Time{}
	}
	return startDate
}

func (m Bolt) PutDate(key Key, startDate time.Time) error {
	return m.DB.Update(func(tx *bolt.Tx) error {
		if startDate.IsZero() {
			tx.Bucket([]byte(BUCKET_META)).Delete([]byte(key))
		}
		content, err := startDate.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to save start date to database: %w", err)
		}
		return tx.Bucket([]byte(BUCKET_META)).Put([]byte(key), content)
	})
}

func (m Bolt) URL(key Key) url.URL {
	var value url.URL
	err := m.DB.View(func(tx *bolt.Tx) error {
		return value.UnmarshalBinary(tx.Bucket([]byte(BUCKET_META)).Get([]byte(key)))
	})
	if err != nil {
		return url.URL{}
	}
	return value
}

func (m Bolt) PutURL(key Key, value url.URL) error {
	return m.DB.Update(func(tx *bolt.Tx) error {
		if value == (url.URL{}) {
			return tx.Bucket([]byte(BUCKET_META)).Delete([]byte(key))
		}
		return tx.Bucket([]byte(BUCKET_META)).Put([]byte(key), []byte(value.String()))
	})
}

func (m Bolt) Get(bucket, key string) []byte {
	buf := make([]byte, 0, 16)
	err := m.DB.View(func(tx *bolt.Tx) error {
		buf = append(buf, tx.Bucket([]byte(bucket)).Get([]byte(key))...)
		return nil
	})
	if err != nil {
		return nil
	}
	return buf
}

func (m Bolt) Put(bucket, key string, value []byte) error {
	return m.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Put([]byte(key), value)
	})
}

func NewDownloader(
	version string,
	bufPool *sync.Pool,
	onlyHashNewIDs bool,
	getID func(id ch.ID) []ch.ID,
	chdb ch.CHDB,
	basePath, APIKey string,
	keepDownloadedImages, sendExistingImages bool,
	finishDownloadQueue chan<- dl.Download,
) *Downloader {
	if os.Getenv("METRON_KEEP_IMAGES") == "TRUE" {
		keepDownloadedImages = true
	}
	return &Downloader{
		basePath:             basePath,
		version:              version,
		Auth:                 Auth(APIKey),
		bufPool:              bufPool, // The buffers get sent back via finishedDownloadQueue
		FinishDownloadQueue:  finishDownloadQueue,
		SendExistingImages:   sendExistingImages,
		KeepDownloadedImages: keepDownloadedImages,
		chdb:                 chdb,
		getID:                getID,
		onlyHashNewIDs:       onlyHashNewIDs,
	}
}

func (d *Downloader) cleanDirs() {
	_ = filepath.WalkDir(filepath.Join(d.basePath, imageDirectory), func(path string, d fs.DirEntry, err error) error {
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

func MustParseURL(rawURI string) *url.URL {
	uri, err := url.Parse(rawURI)
	if err != nil {
		panic(fmt.Errorf("failed to parse url: %w", err))
	}
	return uri
}

func (d *Downloader) getPage(pageURL url.URL) ([]byte, time.Time, error) {
	content := d.PageCache.Get(BUCKET_PAGE_CACHE, pageURL.String())
	if len(content) > 0 {
		logger.Println(log.Standard, "Checking metron page", pageURL.String())
		return content, time.Time{}, nil
	}
	logger.Println(log.Standard, "Downloading metron page", pageURL.String())
	req, _ := http.NewRequest(http.MethodGet, pageURL.String(), nil)
	d.Auth.Apply(req)
	resp, respCancel, err := dl.Get(d.Context, req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to retrieve %q: %w", pageURL.String(), err)
	}
	sleepTo := GetNextRequestTime(resp)
	defer respCancel()
	content, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, sleepTo, fmt.Errorf("failed to download page: %s: %w: %w", pageURL.String(), err, ErrRetry)
	}
	err = d.PageCache.Put(BUCKET_PAGE_CACHE, pageURL.String(), content)
	if err != nil {
		return content, sleepTo, fmt.Errorf("failed to cache metron search page: %v: %w", pageURL, err)
	}
	if resp.StatusCode == http.StatusOK {
		return content, sleepTo, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return content, sleepTo, ErrRetry
	}
	return content, sleepTo, fmt.Errorf("generic http error: %d: %s", resp.StatusCode, content)
}

// https://metron.cloud/api/issue/?modified_gt
func (d *Downloader) processIssues() error {
	if d.DB.DB == nil {
		panic("DB not set")
	}
	if d.PageCache.DB == nil {
		panic("DB not set")
	}
	var resultList ResultList
	// resultList.Next = d.DB.URL(KEY_NEXT_PAGE)
	// if resultList.Next == (url.URL{}) {
	// We always start at the first page. It should already be cached so should not use any extra api requests
	resultList.Next = *BaseURL.ResolveReference(&url.URL{Path: "issue/"})
	if !d.StartDate.IsZero() {
		resultList.Next.Query().Add("modified_gt", d.StartDate.Format(TimestampLayout))
	}
	// }
	retries := 0
	// TODO: we have a count attribute. Calculate what page we should end on so that we don't have an infinite loop here
	nextAPIRequestTime := time.Time{}
	i := 0
	for resultList.Next != (url.URL{}) {
		err := d.Context.Err()
		if err != nil {
			return err
		}
		currentURL := resultList.Next
		resultList.Count = 0
		resultList.Next = url.URL{}
		resultList.Previous = url.URL{}
		resultList.Results = resultList.Results[0:0]
		logger.Println(log.Verbose2, "Checking url", resultList.Next.String())

		// So defer can be used
		err = func() error {
			var (
				content []byte
				err     error
			)
			if !nextAPIRequestTime.IsZero() {
				timeLeft := time.Until(nextAPIRequestTime)
				if timeLeft > time.Millisecond*100 {
					select {
					case <-time.After(timeLeft):
					case <-d.Context.Done():
						return d.Context.Err()
					}
				}
			}
			content, nextAPIRequestTime, err = d.getPage(currentURL)
			if errors.Is(err, ErrRetry) {
				retries += 1
				if retries >= 3 {
					return errors.New("to many retries")
				}
				resultList.Next = currentURL
				return nil
			}
			retries = 0
			if err != nil {
				return fmt.Errorf("failed to request issues from metron API: %w", err)
			}
			err = json.Unmarshal(content, &resultList, JsonOpts...)
			if err != nil {
				return fmt.Errorf("failed to decode json response from %q: %w\n%s", currentURL.String(), err, content)
			}
			var issue Issue
			// This is mainly to keep the data available for later changes to the server it's not used otherwise
			for _, issue = range resultList.Results {
				err = d.DB.PutIssue(issue)
				if err != nil {
					return fmt.Errorf("failed to save issue %d to disk: %w", issue.ID, err)
				}
			}
			var imageNextRequestTime time.Time
			for _, issue = range resultList.Results {
				err = d.Context.Err()
				if err != nil {
					return err
				}
				if issue.ID == 136787 {
					fmt.Println(issue)
				}
				issueID := ch.ID{Domain: ch.NewSource(ch.Metron), ID: strconv.Itoa(int(issue.ID))}
				logger.Println(log.Verbose2, "Checking id:", issueID)

				imageRequest, _ := http.NewRequest(http.MethodGet, issue.Image.String(), nil)
				ext := strings.ToLower(path.Ext(issue.Image.Path))
				if ext == "" || (len(ext) > 4 && !slices.Contains([]string{".avif", ".webp", ".tiff", ".heif"}, ext)) {
					ext = ".jpg"
				}
				// Construct the relative path for the file
				imagePath := filepath.Join(imageDirectory, strconv.Itoa(int(issue.Series.ID)), strconv.Itoa(int(issue.ID)), "cover"+ext)
				buf := d.bufPool.Get().(*bytes.Buffer)
				buf.Reset()

				if issue.Image == (url.URL{}) {
					logger.Println(log.Standard, "No url found for:", issueID)
					continue
				}

				if d.chdb.CheckURL(issue.Image.String()) {
					logger.Println(log.Verbose, "Skipping known bad url:", issue.Image)
					continue
				}
				if d.chdb.PathDownloaded(filepath.Join(WorkDirectory, imagePath)) {
					logger.Println(log.Verbose, "Issue is already downloaded:", issueID)
					if !d.SendExistingImages {
						fmt.Println(log.Verbose, "THIS SHOULDN'T HAPPEN")
						continue
					}
					// d.basePath is the absolute path to WorkDirectory
					if _, err = os.Stat(filepath.Join(d.basePath, imagePath)); err != nil {
						fmt.Println(log.Verbose, "THIS SHOULDN'T HAPPEN")
						continue // assume it's already been hashed and deleted
					}

					err = dl.ReadAll(filepath.Join(d.basePath, imagePath), buf)
					if err != nil {
						fmt.Println(log.Verbose, "THIS SHOULDN'T HAPPEN")
						logger.Log(log.Standard, "Failed to read existing image %q: %v", imagePath, err)
						continue
					}
					d.FinishDownloadQueue <- dl.Download{
						Request: imageRequest,
						IssueID: issueID,
						// This is relative to to comic-hasher path. eg filepath.Join(c.basePath, "../")
						Dest:  filepath.Join(WorkDirectory, imagePath),
						Image: buf,
					}
					continue
				}
				existingIDs := d.getID(issueID)
				logger.Println(log.Verbose, "Checking if ID:", issueID, "is already hashed", existingIDs)
				if d.onlyHashNewIDs && len(existingIDs) > 0 {
					logger.Println(log.Verbose, "Skipping already hashed ID:", issueID)
					continue
				}

				if sleepTime := time.Until(imageNextRequestTime); sleepTime > time.Millisecond*100 {
					select {
					case <-time.After(sleepTime):
					case <-d.Context.Done():
						return d.Context.Err()
					}
				}
				if i > 20 {
					return errExit
				}
				i += 1
				return errExit
				coverResp := dl.DownloadImage(
					dl.Download{
						Request: imageRequest,
						IssueID: issueID,
						// This is relative to to comic-hasher path. eg filepath.Join(c.basePath, "../")
						Dest:  filepath.Join(WorkDirectory, imagePath),
						Image: buf,
					},
					d.Context,
					d.chdb,
					filepath.Dir(d.basePath),
					d.KeepDownloadedImages,
					d.FinishDownloadQueue,
					0,
				)
				_ = coverResp
				// Covers are cached by cloudflare. Default is 1 second. But if x-ratelimit headers are ever added they will be parsed
				imageNextRequestTime = GetNextRequestTime(coverResp)
			}
			// persist the next url so we can resume
			// We resume via BUCKET_PAGE_CACHE in d.getPage
			// d.DB.PutURL(KEY_NEXT_PAGE, resultList.Next)
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func GetServerTime(resp *http.Response) time.Time {
	now := time.Now()
	serverTime := resp.Header.Get("Date")
	if serverTime == "" {
		return now
	}
	t, err := time.Parse(time.RFC1123, serverTime)
	if err != nil {
		return now
	}
	return t
}

// GetRatelimitTime checks these http headers
// x-ratelimit-burst-limit: 45
// x-ratelimit-burst-remaining: 41
// x-ratelimit-burst-reset: 1790207705 // 1 Minute
// x-ratelimit-sustained-limit: 5000
// x-ratelimit-sustained-remaining: 4983
// x-ratelimit-sustained-reset: 1790283530 // 24 Hours
// Retry-After: 60 // Seconds to next reset if limit is hit. Realistically this will be x-ratelimit-burst-reset or x-ratelimit-sustained-reset
func GetRatelimitTime(resp *http.Response, ratelimit string) (time.Time, error) {
	remaining := resp.Header.Get("x-ratelimit-" + ratelimit + "-remaining")
	resetTime := resp.Header.Get("x-ratelimit-" + ratelimit + "-reset")
	if remaining == "" || resetTime == "" {
		return time.Time{}, nil
	}
	limit, err := strconv.Atoi(remaining)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse %s limit remaining: %w", ratelimit, err)
	}
	if limit < 1 {
		sustainedReset, err := strconv.ParseInt(resetTime, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse %s limit reset: %w", ratelimit, err)
		}
		return time.Unix(sustainedReset, 0), nil
	}
	return time.Time{}, nil
}

func GetNextRequestTime(resp *http.Response) time.Time {
	if resp == nil {
		return time.Time{}
	}
	serverTime := GetServerTime(resp)
	if resp.Header.Get("Retry-After") != "" {
		retrySeconds, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
		if err != nil {
			logger.Log(log.Required, "Unable to parse %#v: %v", resp.Header.Get("Retry-After"), err)
			return serverTime.Add(10 * time.Second)
		}

		return serverTime.Add(time.Duration(retrySeconds) * time.Second)
	}
	serverTime = time.Now()
	t, err := GetRatelimitTime(resp, "sustained")
	if err != nil || t.IsZero() {
		t, err = GetRatelimitTime(resp, "burst")
	}

	if err != nil {
		logger.Log(log.Required, "Unable to parse ratelimit: %v", err)
		return serverTime.Add(10 * time.Second)
	}
	if t.IsZero() {
		return serverTime.Add(time.Second)
	}
	return t
}

func OpenBolt(path string, version ch.Version, buckets []string) (Bolt, error) {
	logger.Println(log.Verbose2, "Opening bolt:", path)
	b, err := ch.OpenBolt(path, version, buckets)
	if err != nil {
		return Bolt{b}, err
	}
	return Bolt{b}, nil
}

func DownloadCovers(ctx context.Context, d *Downloader) {
	var err error
	d.Context = log.NewContext(ctx, logger)
	_ = os.MkdirAll(d.basePath, 0o777)
	d.DB, err = OpenBolt(filepath.Join(d.basePath, "metron.bolt"), DB_VERSION, []string{BUCKET_ISSUE, BUCKET_META})
	if err != nil {
		logger.Log(log.Fatal, "failed to open metron database: %v", err)
		return
	}
	defer d.DB.Close()
	ImagePath := filepath.Join(d.basePath, imageDirectory)
	d.StartDate = d.DB.Date(KEY_CURRENT_START_DATE)
	nextStartDate := d.DB.Date(KEY_NEXT_START_DATE)
	if nextStartDate.IsZero() {
		nextStartDate = time.Now()
		d.DB.PutDate(KEY_NEXT_START_DATE, nextStartDate)
	}
	d.PageCache, err = OpenBolt(filepath.Join(d.basePath, "page_cache.bolt"), PAGE_CACHE_VERSION, []string{BUCKET_PAGE_CACHE, BUCKET_META})
	if err != nil {
		logger.Log(log.Fatal, "failed to open metron page cache database: %v", err)
		return
	}
	if d.StartDate != d.PageCache.Date(KEY_CURRENT_START_DATE) {
		// Page cache will cycle through a lot of data especially on the initial run
		// instead of dealing with db compacting just delete the entire file if it doesn't match the current run
		d.PageCache.Close()
		os.Remove(filepath.Join(d.basePath, "page_cache.bolt"))
		logger.Println(log.Verbose, "Re-creating page cache")
		d.PageCache, err = OpenBolt(filepath.Join(d.basePath, "page_cache.db"), PAGE_CACHE_VERSION, []string{BUCKET_PAGE_CACHE, BUCKET_META})
		if err != nil {
			logger.Log(log.Fatal, "failed to open metron page cache database: %v", err)
			return
		}
		d.DB.PutDate(KEY_CURRENT_START_DATE, d.StartDate)
	}
	defer d.PageCache.Close()

	_ = os.MkdirAll(ImagePath, 0o777)
	f, _ := os.Create(filepath.Join(ImagePath, ".keep"))
	_ = f.Close()
	if !d.KeepDownloadedImages {
		logger.Println(log.Verbose2, "Cleaning directories")
		d.cleanDirs()
	}

	logger.Log(log.Standard, "Updating metron issues now")

	err = d.processIssues()
	if err != nil {
		logger.Log(log.Fatal, "Failed to download new metron Issues: %s", err)
		return
	}
	err = d.DB.PutDate(KEY_CURRENT_START_DATE, nextStartDate)
	if err != nil {
		logger.Println(log.Fatal, "Failed to save metron modified dates")
	}
	err = d.DB.PutDate(KEY_NEXT_START_DATE, time.Time{})
	if err != nil {
		logger.Println(log.Fatal, "Failed to save metron modified dates")
	}

	logger.Println(log.Standard, "Completed downloading covers")
}
