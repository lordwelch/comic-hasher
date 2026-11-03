package metron

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	dl "gitea.narnian.us/lordwelch/comic-hasher/download"
)

const (
	testAPIKey   = "test-api-key"
	testSeriesID = 5
	testImage    = "image-bytes"
)

// testPageResults is the results array of each api page the fixture serves:
// Next, Previous are handled in testPageJSON
var testPageResults = []string{
	`[
		{
			"series": {"id": 5, "Name": "Test Series", "Volume": 1, "year_began": 2022},
			"id": 1000,
			"number": "1000",
			"issue": "Test Series (2022) #1000",
			"cover_date": "2022-09-01",
			"store_date": "2022-09-14",
			"image": "https://metron.cloud/media/issue/1000/cover.jpg",
			"cover_hash": "0123456789abcdef",
			"modified": "2024-12-23T16:17:29.333263-05:00"
		},
		{
			"series": {"id": 5, "Name": "Test Series", "Volume": 1, "year_began": 2022},
			"id": 1001,
			"number": "1001",
			"issue": "Test Series (2022) #1001",
			"cover_date": "2022-09-01",
			"store_date": "2022-09-14",
			"image": "https://metron.cloud/media/issue/1001/cover.jpg",
			"cover_hash": "0123456789abcdef",
			"modified": "2024-12-23T16:17:29.333263-05:00"
		}
	]`,
	`[
		{
			"series": {"id": 5, "Name": "Test Series", "Volume": 1, "year_began": 2022},
			"id": 1002,
			"number": "1002",
			"issue": "Test Series (2022) #1002",
			"cover_date": "2022-09-01",
			"store_date": "2022-09-14",
			"image": "https://metron.cloud/media/issue/1002/cover.jpg",
			"cover_hash": "0123456789abcdef",
			"modified": "2024-12-23T16:17:29.333263-05:00"
		},
		{
			"series": {"id": 5, "Name": "Test Series", "Volume": 1, "year_began": 2022},
			"id": 1003,
			"number": "1003",
			"issue": "Test Series (2022) #1003",
			"cover_date": "2022-09-01",
			"store_date": "2022-09-14",
			"image": "https://metron.cloud/media/issue/1003/cover.jpg",
			"cover_hash": "0123456789abcdef",
			"modified": "2024-12-23T16:17:29.333263-05:00"
		}
	]`,
	`[
		{
			"series": {"id": 5, "Name": "Test Series", "Volume": 1, "year_began": 2022},
			"id": 1004,
			"number": "1004",
			"issue": "Test Series (2022) #1004",
			"cover_date": "2022-09-01",
			"store_date": "2022-09-14",
			"image": "https://metron.cloud/media/issue/1004/cover.jpg",
			"cover_hash": "0123456789abcdef",
			"modified": "2024-12-23T16:17:29.333263-05:00"
		},
		{
			"series": {"id": 5, "Name": "Test Series", "Volume": 1, "year_began": 2022},
			"id": 1005,
			"number": "1005",
			"issue": "Test Series (2022) #1005",
			"cover_date": "2022-09-01",
			"store_date": "2022-09-14",
			"image": "https://metron.cloud/media/issue/1005/cover.jpg",
			"cover_hash": "0123456789abcdef",
			"modified": "2024-12-23T16:17:29.333263-05:00"
		}
	]`,
}

type testMetron struct {
	*httptest.Server
	hits     map[string]int
	fail     map[int]int
	cancelOn int
	cancel   context.CancelFunc
}

func newTestMetron(t *testing.T) *testMetron {
	t.Helper()
	f := &testMetron{}
	f.reset()
	f.Server = httptest.NewTestServer(t, http.HandlerFunc(f.serveHTTP))
	return f
}

// reset clears the recorded requests, any configured failures and the request
// that will cancel the run.
func (f *testMetron) reset() {
	f.hits = make(map[string]int)
	f.fail = make(map[int]int)
	f.cancelOn = 0
	f.cancel = nil
}

// testPageJSON renders a page of the api fixture. The next and previous links
// repeat the query of the request so filters like modified_gt apply to every
// page, the same way the real api does it.
func testPageJSON(page int, query url.Values) string {
	link := func(page int) string {
		q := url.Values{}
		for key, values := range query {
			if key != "page" {
				q[key] = values
			}
		}
		if page > 1 {
			q.Set("page", strconv.Itoa(page))
		}
		u := BaseURL.JoinPath("issue/")
		u.RawQuery = q.Encode()
		return u.String()
	}
	next, previous := "null", "null"
	if page < len(testPageResults) {
		next = `"` + link(page+1) + `"`
	}
	if page > 1 {
		previous = `"` + link(page-1) + `"`
	}

	return fmt.Sprintf(`{"count": %d, "next": %s, "previous": %s, "results": %s}`,
		len(testPageResults)*2, next, previous, testPageResults[page-1])
}

func (f *testMetron) serveHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("x-ratelimit-burst-remaining", "0")
	header.Set("x-ratelimit-burst-reset", strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10))
	page := 1
	if r.URL.Path == "/api/issue/" {
		if raw := r.URL.Query().Get("page"); raw != "" {
			var err error
			page, err = strconv.Atoi(raw)
			if err != nil {
				f.hits[r.URL.RequestURI()] += 1
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, "bad page: "+err.Error())
				return
			}
		}
		if f.abortPage(page) {
			return
		}
	}
	f.hits[r.URL.RequestURI()] += 1

	switch {
	case r.URL.Path == "/api/issue/":
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "unexpected authorization header: "+got)
			return
		}
		if status := f.fail[page]; status != 0 {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"detail":"rate limited"}`)
			return
		}
		if page < 1 || page > len(testPageResults) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "page not found")
			return
		}
		header.Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, testPageJSON(page, r.URL.Query()))
	case strings.HasPrefix(r.URL.Path, "/media/issue/"):
		header.Set("Content-Type", "image/jpeg")
		_, _ = io.WriteString(w, testImage)
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "unexpected path: "+r.URL.Path)
	}
}

// Simulates restarting the server.
func (f *testMetron) cancelPage(page int, cancel context.CancelFunc) {
	f.cancelOn = page
	f.cancel = cancel
}

// Simulates a network error
func (f *testMetron) abortPage(page int) bool {
	cancel := f.cancel
	abort := cancel != nil && f.cancelOn == page
	if abort {
		cancel()
		panic(http.ErrAbortHandler)
	}
	return abort
}

type testEnv struct {
	srv      *testMetron
	d        *Downloader
	finished chan dl.Download
	base     string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	srv := newTestMetron(t)
	oldClient := dl.Client
	dl.Client = srv.Client() // TODO:? pipe this through as an argument to NewDownloader
	t.Cleanup(func() {
		dl.Client = oldClient
	})

	root := t.TempDir()
	base := filepath.Join(root, WorkDirectory)
	if err := os.MkdirAll(base, 0o777); err != nil {
		t.Fatalf("failed to create metron directory: %v", err)
	}
	chdb, err := ch.OpenCHDBBolt(root, false)
	if err != nil {
		t.Fatalf("failed to open chdb: %v", err)
	}

	buffers := &sync.Pool{New: func() any { return new(bytes.Buffer) }}
	finished := make(chan dl.Download, 1024)
	d := NewDownloader(
		"test",
		buffers,
		false,
		func(ch.ID) []ch.ID { return nil }, // We don't test this we just use CHDB for cache testing
		chdb,
		base,
		testAPIKey,
		true,
		false,
		finished,
	)

	env := &testEnv{srv: srv, d: d, finished: finished, base: base}
	t.Cleanup(env.closeDBs)
	return env
}

// For inspecting state after DownloadCovers return
func (e *testEnv) openDBs() error {
	var err error
	e.d.DB, err = OpenBolt(filepath.Join(e.base, "metron.bolt"), DBVersion, []string{BucketIssue, BucketMeta})
	if err != nil {
		return fmt.Errorf("failed to open metron database: %w", err)
	}
	e.d.PageCache, err = OpenBolt(filepath.Join(e.base, "page_cache.bolt"), PageCacheVersion, []string{BucketPageCache, BucketMeta})
	if err != nil {
		return fmt.Errorf("failed to open page cache: %w", err)
	}
	return nil
}

func (e *testEnv) closeDBs() {
	if e.d.PageCache.DB != nil {
		_ = e.d.PageCache.Close()
		e.d.PageCache = Bolt{}
	}
	if e.d.DB.DB != nil {
		_ = e.d.DB.Close()
		e.d.DB = Bolt{}
	}
}

// drain collects the images DownloadCovers finished downloading.
func (e *testEnv) drain() []string {
	dests := make([]string, 0, len(e.finished))
	for len(e.finished) > 0 {
		dests = append(dests, (<-e.finished).Dest)
	}
	return dests
}
