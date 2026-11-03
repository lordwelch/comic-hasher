package metron

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestMain(m *testing.M) {
	// Force UTC timezone so we can hard-code urls.
	oldLocal := time.Local
	time.Local = time.UTC
	code := m.Run()
	time.Local = oldLocal
	os.Exit(code)
}

// Cache functions at all
func TestDownloadCoversCachesAllRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)

		DownloadCovers(context.Background(), env.d)
		if diff := cmp.Diff(map[string]int{
			"/api/issue/":                 1,
			"/api/issue/?page=2":          1,
			"/api/issue/?page=3":          1,
			"/media/issue/1000/cover.jpg": 1,
			"/media/issue/1001/cover.jpg": 1,
			"/media/issue/1002/cover.jpg": 1,
			"/media/issue/1003/cover.jpg": 1,
			"/media/issue/1004/cover.jpg": 1,
			"/media/issue/1005/cover.jpg": 1,
		}, env.srv.hits); diff != "" {
			t.Errorf("unexpected metron requests (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{
			filepath.Join(WorkDirectory, "_image", "5", "1000", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1001", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1002", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1003", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1004", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1005", "cover.jpg"),
		}, env.drain()); diff != "" {
			t.Errorf("unexpected downloads (-want +got):\n%s", diff)
		}

		if err := env.openDBs(); err != nil {
			t.Fatalf("failed to open databases: %v", err)
		}
		for _, pageURL := range []string{
			"https://metron.cloud/api/issue/",
			"https://metron.cloud/api/issue/?page=2",
			"https://metron.cloud/api/issue/?page=3",
		} {
			if content := env.d.PageCache.Get(BucketPageCache, pageURL); len(content) == 0 {
				t.Errorf("page is not cached: %q", pageURL)
			}
		}

		// Page cache is cleared at the start of DownloadCovers
		// Here we remove the KeyCurrentStartDate so it acts as a first run
		// but we have the entire run cached so nothing should happen
		if err := env.d.DB.PutDate(KeyCurrentStartDate, time.Time{}); err != nil {
			t.Fatalf("failed to reset the metron start date: %v", err)
		}
		env.closeDBs()

		env.srv.reset()
		DownloadCovers(context.Background(), env.d)
		if diff := cmp.Diff(map[string]int{}, env.srv.hits); diff != "" {
			t.Errorf("resumed run made unexpected requests (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{}, env.drain()); diff != "" {
			t.Errorf("unexpected downloads (-want +got):\n%s", diff)
		}
	})
}

// Validate that an interruption mid-run continues
func TestDownloadCoversResumeUsesPageCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)

		ctx, cancel := context.WithCancel(t.Context())
		env.srv.cancelPage(2, cancel)
		ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		DownloadCovers(ctx, env.d)
		// Disable the cancel
		env.srv.cancelOn = 0

		ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		DownloadCovers(ctx, env.d)

		// Page 1 is served from the cache, the images from page 1 are on disk.
		if diff := cmp.Diff(map[string]int{
			"/api/issue/?page=2":          1,
			"/api/issue/?page=3":          1,
			"/api/issue/":                 1,
			"/media/issue/1000/cover.jpg": 1,
			"/media/issue/1001/cover.jpg": 1,
			"/media/issue/1002/cover.jpg": 1,
			"/media/issue/1003/cover.jpg": 1,
			"/media/issue/1004/cover.jpg": 1,
			"/media/issue/1005/cover.jpg": 1,
		}, env.srv.hits); diff != "" {
			t.Errorf("resumed run made unexpected requests (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{
			filepath.Join(WorkDirectory, "_image", "5", "1000", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1001", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1002", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1003", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1004", "cover.jpg"),
			filepath.Join(WorkDirectory, "_image", "5", "1005", "cover.jpg"),
		}, env.drain()); diff != "" {
			t.Errorf("unexpected downloads (-want +got):\n%s", diff)
		}

		if err := env.openDBs(); err != nil {
			t.Fatalf("failed to open databases: %v", err)
		}
		for _, pageURL := range []string{
			"https://metron.cloud/api/issue/",
			"https://metron.cloud/api/issue/?page=2",
			"https://metron.cloud/api/issue/?page=3",
		} {
			if content := env.d.PageCache.Get(BucketPageCache, pageURL); len(content) == 0 {
				t.Errorf("page is not cached under %q", pageURL)
			}
		}
		env.closeDBs()
	})
}

// TestDownloadCoversRetriesFailedPages validates that failed pages are retried
// (and not cached as if they were a successful page).
func TestDownloadCoversRetriesFailedPages(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)
		env.srv.fail[2] = http.StatusTooManyRequests

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		DownloadCovers(ctx, env.d)

		if diff := cmp.Diff(map[string]int{
			"/api/issue/":                 1,
			"/api/issue/?page=2":          3, // the initial request plus two retries
			"/media/issue/1000/cover.jpg": 1,
			"/media/issue/1001/cover.jpg": 1,
		}, env.srv.hits); diff != "" {
			t.Errorf("unexpected metron requests (-want +got):\n%s", diff)
		}

		if err := env.openDBs(); err != nil {
			t.Fatalf("failed to open databases: %v", err)
		}
		if content := env.d.PageCache.Get(BucketPageCache, "https://metron.cloud/api/issue/"); len(content) == 0 {
			t.Error("page 1 is not cached")
		}
		if content := env.d.PageCache.Get(BucketPageCache, "https://metron.cloud/api/issue/?page=2"); len(content) != 0 {
			t.Error("a failed page was cached")
		}
		env.closeDBs()
	})
}

// Here we run it 3 times
func TestDownloadCoversCacheLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)

		// Run 1: first run, there is no start date yet every cover is downloaded.
		DownloadCovers(context.Background(), env.d)
		if diff := cmp.Diff(map[string]int{
			"/media/issue/1000/cover.jpg": 1,
			"/media/issue/1001/cover.jpg": 1,
			"/media/issue/1002/cover.jpg": 1,
			"/media/issue/1003/cover.jpg": 1,
			"/media/issue/1004/cover.jpg": 1,
			"/media/issue/1005/cover.jpg": 1,
			"/api/issue/":                 1,
			"/api/issue/?page=2":          1,
			"/api/issue/?page=3":          1,
		}, env.srv.hits); diff != "" {
			t.Errorf("first run made unexpected requests (-want +got):\n%s", diff)
		}
		time.Sleep(time.Hour)

		// Run 2: the new start date (unix epoch) replaces the page cache, so every page is requested with (unix epoch).
		// CHDB ensures that covers are not requested again
		// Note: "current time" is (unix epoch +1h)
		DownloadCovers(context.Background(), env.d)
		if diff := cmp.Diff(map[string]int{
			"/media/issue/1000/cover.jpg":                                      1,
			"/media/issue/1001/cover.jpg":                                      1,
			"/media/issue/1002/cover.jpg":                                      1,
			"/media/issue/1003/cover.jpg":                                      1,
			"/media/issue/1004/cover.jpg":                                      1,
			"/media/issue/1005/cover.jpg":                                      1,
			"/api/issue/":                                                      1,
			"/api/issue/?page=2":                                               1,
			"/api/issue/?page=3":                                               1,
			"/api/issue/?modified_gt=2000-01-01T00%3A00%3A00%2B00%3A00":        1,
			"/api/issue/?modified_gt=2000-01-01T00%3A00%3A00%2B00%3A00&page=2": 1,
			"/api/issue/?modified_gt=2000-01-01T00%3A00%3A00%2B00%3A00&page=3": 1,
		}, env.srv.hits); diff != "" {
			t.Errorf("second run made unexpected requests (-want +got):\n%s", diff)
		}
		time.Sleep(time.Hour)

		// Run 3: starting from (unix epoch +1h), the cache is replaced again and every page is requested with (unix epoch +1h).
		// Note: "current time" is (unix epoch +2h)
		DownloadCovers(context.Background(), env.d)
		if diff := cmp.Diff(map[string]int{
			"/media/issue/1000/cover.jpg":                                      1,
			"/media/issue/1001/cover.jpg":                                      1,
			"/media/issue/1002/cover.jpg":                                      1,
			"/media/issue/1003/cover.jpg":                                      1,
			"/media/issue/1004/cover.jpg":                                      1,
			"/media/issue/1005/cover.jpg":                                      1,
			"/api/issue/":                                                      1,
			"/api/issue/?page=2":                                               1,
			"/api/issue/?page=3":                                               1,
			"/api/issue/?modified_gt=2000-01-01T00%3A00%3A00%2B00%3A00":        1,
			"/api/issue/?modified_gt=2000-01-01T00%3A00%3A00%2B00%3A00&page=2": 1,
			"/api/issue/?modified_gt=2000-01-01T00%3A00%3A00%2B00%3A00&page=3": 1,
			"/api/issue/?modified_gt=2000-01-01T01%3A00%3A00%2B00%3A00":        1,
			"/api/issue/?modified_gt=2000-01-01T01%3A00%3A00%2B00%3A00&page=2": 1,
			"/api/issue/?modified_gt=2000-01-01T01%3A00%3A00%2B00%3A00&page=3": 1,
		}, env.srv.hits); diff != "" {
			t.Errorf("third run made unexpected requests (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{
			"metron/_image/5/1000/cover.jpg",
			"metron/_image/5/1001/cover.jpg",
			"metron/_image/5/1002/cover.jpg",
			"metron/_image/5/1003/cover.jpg",
			"metron/_image/5/1004/cover.jpg",
			"metron/_image/5/1005/cover.jpg",
		}, env.drain()); diff != "" {
			t.Errorf("unexpected downloads (-want +got):\n%s", diff)
		}
	})
}
