package main_test

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gcmp "cmp"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
	"gitea.narnian.us/lordwelch/comic-hasher/storage"
	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var cmpOpts = []cmp.Option{
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(func(a ch.Result, b ch.Result) int {
		return gcmp.Or(
			gcmp.Compare(a.Hash.Kind, b.Hash.Kind),
			gcmp.Compare(a.Hash.Hash, b.Hash.Hash),
			a.ID.Compare(b.ID),
		)
	}),
}

var (
	sample1SavedHashes = []ch.SavedHash{
		{ID: ch.ID{ID: "sample1.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.AHash, Hash: 0x7eff3f030703c1fc}},
		{ID: ch.ID{ID: "sample1.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.DHash, Hash: 0xe89f6f63af4f8b69}},
		{ID: ch.ID{ID: "sample1.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.PHash, Hash: 0xaf95d2205c7b1f82}},
	}

	sample2SavedHashes = []ch.SavedHash{
		{ID: ch.ID{ID: "sample2.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.AHash, Hash: 0x003c7e7e7e7e3c18}},
		{ID: ch.ID{ID: "sample2.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.DHash, Hash: 0x71f0f4d2f0b8f071}},
		{ID: ch.ID{ID: "sample2.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.PHash, Hash: 0x95274a996be4349e}},
	}

	sample3SavedHashes = []ch.SavedHash{
		{ID: ch.ID{ID: "sample3.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.AHash, Hash: 0x7eff3f030703c1fc}},
		{ID: ch.ID{ID: "sample3.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.DHash, Hash: 0xe89f6f63af4f8bc9}},
		{ID: ch.ID{ID: "sample3.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.PHash, Hash: 0xaf95d2205c7b1f82}},
	}

	sample4SavedHashes = []ch.SavedHash{
		{ID: ch.ID{ID: "sample4.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.AHash, Hash: 0x183c3e3e7e2e3c18}},
		{ID: ch.ID{ID: "sample4.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.DHash, Hash: 0x716cd4e8dccc78b1}},
		{ID: ch.ID{ID: "sample4.jpg", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.PHash, Hash: 0x979c5a9369cd6518}},
	}

	exampleSavedHashes = []ch.SavedHash{
		{ID: ch.ID{ID: "example.png", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.AHash, Hash: 0x246e7e3c1c181800}},
		{ID: ch.ID{ID: "example.png", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.DHash, Hash: 0xccccccf139b0b210}},
		{ID: ch.ID{ID: "example.png", Domain: ch.NewSource("example.org")}, Hash: ch.Hash{Kind: goimagehash.PHash, Hash: 0xd2f2361e2f496368}},
	}
)

func SeedHashes(hs ch.HashStorage) {
	hashes := []ch.SavedHash{}
	hashes = append(hashes, sample1SavedHashes...)
	hashes = append(hashes, sample2SavedHashes...)
	hashes = append(hashes, sample3SavedHashes...)
	hashes = append(hashes, sample4SavedHashes...)
	hashes = append(hashes, exampleSavedHashes...)
	hs.DecodeHashes(&ch.SavedHashes{
		Version: 2,
		Hashes:  hashes,
	})
}

//	type HashStorage interface {
//		GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error)
//		MapHashes(ImageHash) Metrics
//		DecodeHashes(hashes *SavedHashes) (Metrics, error)
//		EncodeHashes() (*SavedHashes, error)
//		AssociateIDs(newIDs []NewIDs) error
//		GetIDs(id ID) IDList
//		RLock()
//		RUnlock()
//	}

func GetMatchesBasic(t *testing.T, hs ch.HashStorage) {
	results, err := hs.GetMatches([]ch.Hash{{Hash: 0x183c3e3e7e2e3c18, Kind: goimagehash.AHash}}, 8, true)
	if err != nil {
		t.Fatal("Failed to search hashes:", err)
	}
	expected := []ch.Result{
		{
			Hash:          ch.Hash{Hash: 0x183c3e3e7e2e3c18, Kind: 1},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample4.jpg"},
			Distance:      0,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample4.jpg"}},
		},
	}
	if diff := cmp.Diff(expected, results, cmpOpts...); diff != "" {
		t.Errorf("GetMatches() mismatch (-want +got):\n%s", diff)
	}
}

//////////// Generated

func GetMatchesNoMatchExact(t *testing.T, hs ch.HashStorage) {
	results, err := hs.GetMatches([]ch.Hash{{Hash: 0xffffffffffffffff, Kind: goimagehash.AHash}}, 8, true)
	if err != nil {
		t.Fatal("Failed to search hashes:", err)
	}
	expected := []ch.Result{}
	if diff := cmp.Diff(expected, results, cmpOpts...); diff != "" {
		t.Errorf("GetMatches() mismatch (-want +got):\n%s", diff)
	}
}

func GetMatchesSharedAHash(t *testing.T, hs ch.HashStorage) {
	// sample1 and sample3 share the same AHash
	results, err := hs.GetMatches([]ch.Hash{{Hash: 0x7eff3f030703c1fc, Kind: goimagehash.AHash}}, 8, true)
	if err != nil {
		t.Fatal("Failed to search hashes:", err)
	}
	expected := []ch.Result{
		{
			Hash:          ch.Hash{Hash: 0x7eff3f030703c1fc, Kind: goimagehash.AHash},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample1.jpg"},
			Distance:      0,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample1.jpg"}},
		},
		{
			Hash:          ch.Hash{Hash: 0x7eff3f030703c1fc, Kind: goimagehash.AHash},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample3.jpg"},
			Distance:      0,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample3.jpg"}},
		},
	}
	if diff := cmp.Diff(expected, results, cmpOpts...); diff != "" {
		t.Errorf("GetMatches() mismatch (-want +got):\n%s", diff)
	}
}

func GetMatchesNearDHash(t *testing.T, hs ch.HashStorage) {
	results, err := hs.GetMatches([]ch.Hash{{Hash: 0xe89f6f63af4f8b59, Kind: goimagehash.DHash}}, 8, true)
	if err != nil {
		t.Fatal("Failed to search hashes:", err)
	}
	expected := []ch.Result{
		{
			Hash:          ch.Hash{Hash: 0xe89f6f63af4f8b69, Kind: goimagehash.DHash},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample1.jpg"},
			Distance:      2,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample1.jpg"}},
		},
		{
			Hash:          ch.Hash{Hash: 0xe89f6f63af4f8bc9, Kind: goimagehash.DHash},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample3.jpg"},
			Distance:      2,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample3.jpg"}},
		},
	}
	if diff := cmp.Diff(expected, results, cmpOpts...); diff != "" {
		t.Errorf("GetMatches() mismatch (-want +got):\n%s", diff)
	}
}

func GetMatchesMultipleHashes(t *testing.T, hs ch.HashStorage) {
	results, err := hs.GetMatches([]ch.Hash{
		{Hash: 0x003c7e7e7e7e3c18, Kind: goimagehash.AHash},
		{Hash: 0x71f0f4d2f0b8f071, Kind: goimagehash.DHash},
		{Hash: 0x95274a996be4349e, Kind: goimagehash.PHash},
	}, 8, true)
	if err != nil {
		t.Fatal("Failed to search hashes:", err)
	}
	expected := []ch.Result{
		{
			Hash:          ch.Hash{Hash: 0x003c7e7e7e7e3c18, Kind: goimagehash.AHash},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample2.jpg"},
			Distance:      0,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample2.jpg"}},
		},
		{
			Hash:          ch.Hash{Hash: 0x71f0f4d2f0b8f071, Kind: goimagehash.DHash},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample2.jpg"},
			Distance:      0,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample2.jpg"}},
		},
		{
			Hash:          ch.Hash{Hash: 0x95274a996be4349e, Kind: goimagehash.PHash},
			ID:            ch.ID{Domain: ch.NewSource("example.org"), ID: "sample2.jpg"},
			Distance:      0,
			EquivalentIDs: []ch.ID{{Domain: ch.NewSource("example.org"), ID: "sample2.jpg"}},
		},
	}
	if diff := cmp.Diff(expected, results, cmpOpts...); diff != "" {
		t.Errorf("GetMatches() mismatch (-want +got):\n%s", diff)
	}
}

func GetIDs(t *testing.T, hs ch.HashStorage) {
	results := hs.GetIDs(ch.ID{Domain: ch.NewSource("example.org"), ID: "sample4.jpg"})
	expected := ch.IDList{
		ch.Source("example.org"): []string{"sample4.jpg"},
	}
	if diff := cmp.Diff(expected, results, cmpOpts...); diff != "" {
		t.Errorf("GetIDs() mismatch (-want +got):\n%s", diff)
	}
}

func TestBasicStorage(t *testing.T) {
	hs, err := storage.NewBasicMapStorage()
	if err != nil {
		t.Fatal("Failed to create basic storage:", err)
	}
	SeedHashes(hs)

	t.Run("GetMatchesBasic", func(t *testing.T) { GetMatchesBasic(t, hs) })
	t.Run("GetMatchesNoMatchExact", func(t *testing.T) { GetMatchesNoMatchExact(t, hs) })
	t.Run("GetMatchesSharedAHash", func(t *testing.T) { GetMatchesSharedAHash(t, hs) })
	t.Run("GetMatchesNearDHash", func(t *testing.T) { GetMatchesNearDHash(t, hs) })
	t.Run("GetMatchesMultipleHashes", func(t *testing.T) { GetMatchesMultipleHashes(t, hs) })
	t.Run("GetIDs", func(t *testing.T) { GetIDs(t, hs) })
}

func TestMapStorage(t *testing.T) {
	hs, err := storage.NewMapStorage()
	if err != nil {
		t.Fatal("Failed to create map storage:", err)
	}
	SeedHashes(hs)

	t.Run("GetMatchesBasic", func(t *testing.T) { GetMatchesBasic(t, hs) })
	t.Run("GetMatchesNoMatchExact", func(t *testing.T) { GetMatchesNoMatchExact(t, hs) })
	t.Run("GetMatchesSharedAHash", func(t *testing.T) { GetMatchesSharedAHash(t, hs) })
	t.Run("GetMatchesNearDHash", func(t *testing.T) { GetMatchesNearDHash(t, hs) })
	t.Run("GetMatchesMultipleHashes", func(t *testing.T) { GetMatchesMultipleHashes(t, hs) })
	t.Run("GetIDs", func(t *testing.T) { GetIDs(t, hs) })
}

func TestVPSStorage(t *testing.T) {
	hs, err := storage.NewVPStorage()
	if err != nil {
		t.Fatal("Failed to create basic storage:", err)
	}
	SeedHashes(hs)

	t.Run("GetMatchesBasic", func(t *testing.T) { GetMatchesBasic(t, hs) })
	t.Run("GetMatchesNoMatchExact", func(t *testing.T) { GetMatchesNoMatchExact(t, hs) })
	t.Run("GetMatchesSharedAHash", func(t *testing.T) { GetMatchesSharedAHash(t, hs) })
	t.Run("GetMatchesNearDHash", func(t *testing.T) { GetMatchesNearDHash(t, hs) })
	t.Run("GetMatchesMultipleHashes", func(t *testing.T) { GetMatchesMultipleHashes(t, hs) })
	t.Run("GetIDs", func(t *testing.T) { GetIDs(t, hs) })
}

func TestSqliteStorage(t *testing.T) {
	hs, err := storage.NewSqliteStorage("sqlite", filepath.Join(t.TempDir(), "sqlite.db"))
	if err != nil {
		t.Fatal("Failed to create sqlite storage:", err)
	}
	SeedHashes(hs)

	t.Run("GetMatchesBasic", func(t *testing.T) { GetMatchesBasic(t, hs) })
	t.Run("GetMatchesNoMatchExact", func(t *testing.T) { GetMatchesNoMatchExact(t, hs) })
	t.Run("GetMatchesSharedAHash", func(t *testing.T) { GetMatchesSharedAHash(t, hs) })
	t.Run("GetMatchesNearDHash", func(t *testing.T) { GetMatchesNearDHash(t, hs) })
	t.Run("GetMatchesMultipleHashes", func(t *testing.T) { GetMatchesMultipleHashes(t, hs) })
	t.Run("GetIDs", func(t *testing.T) { GetIDs(t, hs) })
}

func TestHashServer(t *testing.T) {
	hs, err := storage.NewBasicMapStorage()
	if err != nil {
		t.Fatal("Failed to create basic storage:", err)
	}
	SeedHashes(hs)

	HashServer := ch.NewHashServer(filepath.Join(t.TempDir(), "hashes.gz"), ch.Msgpack)
	req := httptest.NewRequest("GET", "/", nil)
	err = HashServer.WriteHashes(hs)
	if err != nil {
		t.Fatal("failed to write hashes:", err)
	}
	recorder := httptest.NewRecorder()
	HashServer.DownloadHashes(recorder, req)
	gz, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatal("HashServer did not send a gzipped response:", err)
	}
	decompressedHashes, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal("Failed to read response:", err)
	}
	_, err = ch.DecodeHashes(ch.Msgpack, decompressedHashes)
	if err != nil {
		t.Fatal("failed to validate hashes:", err)
	}
	var md5 []byte
	for _, digest := range strings.Split(recorder.Header().Get("Repr-Digest"), ",") {
		kind, b64 := log.Partition(digest, "=:")
		b64 = b64[:len(b64)-1]
		if kind != "MD5" {
			continue
		}
		md5 = crypto.MD5.New().Sum(recorder.Body.Bytes())

	}
	expected := "d41d8cd98f00b204e9800998ecf8427e"
	if diff := cmp.Diff(expected, fmt.Sprintf("%x", md5), cmpOpts...); diff != "" {
		t.Errorf("GetMatches() mismatch (-want +got):\n%s", diff)
	}
}

func SeedEmbeddedHashes(hs ch.HashStorage) {
	var err error
	hashes := ch.Hashes
	if gr, err := gzip.NewReader(bytes.NewReader(ch.Hashes)); err == nil {
		hashes, err = io.ReadAll(gr)
		if err != nil {
			log.Println(log.Fatal, "Failed to read embedded hashes:", err)
		}
		gr.Close()
	}

	var (
		format       ch.Format
		loadedHashes *ch.SavedHashes
	)

	for _, format = range []ch.Format{ch.Msgpack, ch.JSON} {
		if loadedHashes, err = ch.DecodeHashes(format, hashes); errors.Is(err, ch.ErrDecodeFail) {
			continue
		}
		break
	}
	hs.DecodeHashes(loadedHashes)
}

func BenchmarkStorageSmall(fuck *testing.B) {
	Match := []ch.Hash{
		{Hash: 0xfc788d1d89c1c9cf, Kind: goimagehash.AHash},
		{Hash: 0x61d91b79330f939a, Kind: goimagehash.DHash},
		{Hash: 0xf95ac0669da8b4a9, Kind: goimagehash.PHash},
	}

	hs, err := storage.NewBasicMapStorage()
	if err != nil {
		fuck.Fatal("Failed to create Basic storage:", err)
	}
	SeedEmbeddedHashes(hs)
	runtime.GC()
	runtime.GC()
	m := runtime.MemStats{}
	runtime.ReadMemStats(&m)

	fuck.Run("Basic Storage", func(b *testing.B) {
		for b.Loop() {
			b.ReportMetric(float64(m.HeapAlloc), "bytes")
			hs.GetMatches(Match, 8, true)
		}
	})

	hs, err = storage.NewMapStorage()
	if err != nil {
		fuck.Fatal("Failed to create Map storage:", err)
	}
	SeedEmbeddedHashes(hs)
	runtime.GC()
	runtime.GC()
	m = runtime.MemStats{}
	runtime.ReadMemStats(&m)

	fuck.Run("Map Storage", func(b *testing.B) {
		for b.Loop() {
			b.ReportMetric(float64(m.HeapAlloc), "bytes")
			hs.GetMatches(Match, 8, true)
		}
	})

	hs, err = storage.NewVPStorage()
	if err != nil {
		fuck.Fatal("Failed to create VPS storage:", err)
	}
	SeedEmbeddedHashes(hs)
	runtime.GC()
	runtime.GC()
	m = runtime.MemStats{}
	runtime.ReadMemStats(&m)

	fuck.Run("VPS Storage", func(b *testing.B) {
		for b.Loop() {
			b.ReportMetric(float64(m.HeapAlloc), "bytes")
			hs.GetMatches(Match, 8, true)
		}
	})
}

func BenchmarkStorageLarge(b *testing.B) {
	Match := []ch.Hash{
		{Hash: 0x003c7e7e7e7e3c18, Kind: goimagehash.AHash},
		{Hash: 0x71f0f4d2f0b8f071, Kind: goimagehash.DHash},
		{Hash: 0x95274a996be4349e, Kind: goimagehash.PHash},
	}

	hs, err := storage.NewBasicMapStorage()
	if err != nil {
		b.Fatal("Failed to create Basic storage:", err)
	}
	SeedEmbeddedHashes(hs)
	runtime.GC()
	runtime.GC()
	m := runtime.MemStats{}
	runtime.ReadMemStats(&m)

	b.Run("Basic Storage", func(b *testing.B) {
		for b.Loop() {
			b.ReportMetric(float64(m.HeapAlloc), "bytes")
			hs.GetMatches(Match, 8, true)
		}
	})

	hs, err = storage.NewMapStorage()
	if err != nil {
		b.Fatal("Failed to create Map storage:", err)
	}
	SeedEmbeddedHashes(hs)
	runtime.GC()
	runtime.GC()
	m = runtime.MemStats{}
	runtime.ReadMemStats(&m)

	b.Run("Map Storage", func(b *testing.B) {
		for b.Loop() {
			b.ReportMetric(float64(m.HeapAlloc), "bytes")
			hs.GetMatches(Match, 8, true)
		}
	})

	hs, err = storage.NewVPStorage()
	if err != nil {
		b.Fatal("Failed to create VPS storage:", err)
	}
	SeedEmbeddedHashes(hs)
	runtime.GC()
	runtime.GC()
	m = runtime.MemStats{}
	runtime.ReadMemStats(&m)

	b.Run("VPS Storage", func(b *testing.B) {
		for b.Loop() {
			b.ReportMetric(float64(m.HeapAlloc), "bytes")
			hs.GetMatches(Match, 8, true)
		}
	})
}
