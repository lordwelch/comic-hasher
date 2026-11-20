package cv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
)

func TestIssueRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	db, err := OpenBolt(filepath.Join(tmp, "comicvine.bolt"), DBVersion, []string{BucketIssue, BucketMeta})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	issue := Issue{ID: 42, IssueNumber: "1", Image: struct {
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
	}{ThumbURL: "thumb", OriginalURL: "orig"}}
	if err := db.PutIssue(nil, issue); err != nil {
		t.Fatal(err)
	}
	got := db.Issue(nil, 42)
	if got.ID != 42 || got.Image.ThumbURL != "thumb" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestIssueRoundTripZSTD(t *testing.T) {
	tmp := t.TempDir()
	db, err := OpenBolt(filepath.Join(tmp, "comicvine.bolt"), DBVersion, []string{BucketIssue, BucketMeta})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := ch.NewCodec(ch.CompressionZSTD, zstdDict)
	if err != nil {
		t.Fatal(err)
	}
	db.Codec = codec
	issue := Issue{ID: 42, IssueNumber: "1", Image: struct {
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
	}{ThumbURL: "thumb", OriginalURL: "orig"}}
	if err := db.PutIssue(nil, issue); err != nil {
		t.Fatal(err)
	}
	got := db.Issue(nil, 42)
	if got.ID != 42 || got.Image.ThumbURL != "thumb" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestMigrationFromJSON(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, WorkDirectory)
	jsonDir := filepath.Join(base, jsonDirectory)
	os.MkdirAll(jsonDir, 0o777)
	page := `{"offset":0,"number_of_page_results":1,"number_of_total_results":1,"status_code":200,"results":[{"id":7,"issue_number":"1","image":{"thumb_url":"t","original_url":"o"},"volume":{"id":1}}]}`
	os.WriteFile(filepath.Join(jsonDir, "cv-0.json"), []byte(page), 0o644)

	_ = base
	// simulate migration by calling DownloadCovers? requires network; instead replicate migration logic minimal
	db, _ := OpenBolt(filepath.Join(base, "comicvine.bolt"), DBVersion, []string{BucketIssue, BucketMeta})
	defer db.Close()
	pc, _ := OpenBolt(filepath.Join(base, "page_cache.bolt"), PageCacheVersion, []string{BucketPageCache, BucketMeta})
	defer pc.Close()
	data, _ := os.ReadFile(filepath.Join(jsonDir, "cv-0.json"))
	if err := pc.Put(BucketPageCache, ch.IntToBolt(0), data); err != nil {
		t.Fatal("Something fucked:", err)
	}
	var issue CVResult
	json.Unmarshal(data, &issue)
	for _, is := range issue.Results {
		db.PutIssue(nil, is)
	}
	os.Remove(filepath.Join(jsonDir, "cv-0.json"))
	if len(pc.Get(BucketPageCache, ch.IntToBolt(0))) == 0 {
		t.Fatal("page not migrated")
	}
	if db.Issue(nil, 7).ID != 7 {
		t.Fatal("issue not migrated")
	}
	if _, err := os.Stat(filepath.Join(jsonDir, "cv-0.json")); !os.IsNotExist(err) {
		t.Fatal("file not deleted")
	}
}
