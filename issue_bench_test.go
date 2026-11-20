package main_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	minlz "github.com/minio/minlz"
	bolt "go.etcd.io/bbolt"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/comic-hasher/cv"
	"gitea.narnian.us/lordwelch/comic-hasher/metron"
)

// sampleIssueIDs returns up to n issue ids spread across the bucket.
func sampleIssueIDs(db *bolt.DB, bucket string, n int) []int64 {
	var ids []int64
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if v != nil {
				ids = append(ids, int64(ch.BoltToInt(k)))
			}
			return nil
		})
	})

	if len(ids) > n {
		step := len(ids) / n
		sampled := make([]int64, 0, n)
		for i := range n {
			sampled = append(sampled, ids[i*step])
		}
		return sampled
	}
	return ids
}

// writeCompressedDB writes a new bolt database at outPath with every value of
// bucket from srcPath compressed at level.
func writeCompressedDB(tb testing.TB, srcPath, outPath, bucket string, level int) error {
	tb.Helper()
	src, err := bolt.Open(srcPath, 0o644, &bolt.Options{ReadOnly: true, Timeout: time.Second * 10})
	if err != nil {
		return err
	}
	defer src.Close()
	os.Remove(outPath)
	out, err := bolt.Open(outPath, 0o644, nil)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := out.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		return err
	}); err != nil {
		return err
	}
	writeTx, err := out.Begin(true)
	if err != nil {
		return err
	}
	wb := writeTx.Bucket([]byte(bucket))
	if wb == nil {
		writeTx.Rollback()
		return errors.New("missing bucket in the new db")
	}
	if err := src.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil
			}
			compressed, err := minlz.AppendEncoded(nil, v, level)
			if err != nil {
				return err
			}
			return wb.Put(k, compressed)
		})
	}); err != nil {
		writeTx.Rollback()
		return err
	}
	return writeTx.Commit()
}

func setupBenchmark(b *testing.B, dbPath, bucket string, level int) (*bolt.DB, []int64) {
	b.Helper()
	compressedDBPath := filepath.Join(b.TempDir(), filepath.Base(dbPath))
	if err := writeCompressedDB(b, dbPath, compressedDBPath, bucket, level); err != nil {
		b.Fatalf("failed to write compressed database: %v", err)
	}
	db, err := bolt.Open(compressedDBPath, 0o644, &bolt.Options{ReadOnly: true, Timeout: time.Second * 10})
	if err != nil {
		b.Fatalf("failed to open compressed database: %v", err)
	}
	ids := sampleIssueIDs(db, bucket, 15)
	if len(ids) == 0 {
		b.Skip("no issues found in the issues database")
	}
	b.ReportAllocs()
	b.ResetTimer()
	return db, ids
}

type issueDB[T cv.Issue | metron.Issue] interface {
	Issue(int64) T
	View(func(tx *bolt.Tx) error) error
	Close() error
}

type issueDBTX[T cv.Issue | metron.Issue] interface {
	Issue(*bolt.Tx, int64) T
	View(func(tx *bolt.Tx) error) error
	Close() error
}

func benchmarkIssueRetrieval[T cv.Issue | metron.Issue](b *testing.B, boltDB issueDB[T], bucket string, level int, ids []int64) {
	for range b.N {
		if err := boltDB.View(func(tx *bolt.Tx) error {
			for _, id := range ids {
				issue := boltDB.Issue(id)
				fmt.Println(issue)
				var got int64
				switch v := any(issue).(type) {
				case cv.Issue:
					got = v.ID
				case metron.Issue:
					got = v.ID
				}
				if got != id {
					b.Errorf("issue retrieval mismatch: want id %d, got %d", id, got)
					return nil
				}
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

var levels = map[string]int{
	"SuperFast":     minlz.LevelSuperFast,
	"Uncompressed":  minlz.LevelUncompressed,
	"Fastest":       minlz.LevelFastest,
	"Balanced":      minlz.LevelBalanced,
	"Smallest":      minlz.LevelSmallest,
	"SuperFastSIMD": minlz.LevelSuperFastSIMD,
	"FastestSIMD":   minlz.LevelFastestSIMD,
	"BalancedSIMD":  minlz.LevelBalancedSIMD,
	"SmallestSIMD":  minlz.LevelSmallestSIMD,
	// "SIMDDelta":     minlz.LevelSIMDDelta,
}

func benchmarkIssueRetrievalOneTX[T cv.Issue | metron.Issue](b *testing.B, boltDB issueDBTX[T], bucket string, level int, ids []int64) {
	defer boltDB.Close()
	for range b.N {
		if err := boltDB.View(func(tx *bolt.Tx) error {
			for _, id := range ids {
				issue := boltDB.Issue(tx, id)
				fmt.Println(issue)
				var got int64
				switch v := any(issue).(type) {
				case cv.Issue:
					got = v.ID
				case metron.Issue:
					got = v.ID
				}
				if got != id {
					b.Errorf("issue retrieval mismatch: want id %d, got %d", id, got)
					return nil
				}
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMetronIssueRetrieval(b *testing.B) {
	for name, level := range levels {
		db, ids := setupBenchmark(b, "./metron-hashes/metron/metron.bolt", metron.BucketIssue, level)
		boltDB := metron.Bolt{Bolt: ch.Bolt{DB: db, Path: db.Path()}}
		b.Run(name, func(b *testing.B) {
			benchmarkIssueRetrieval(b, boltDB, metron.BucketIssue, level, ids)
		})
	}
}

func BenchmarkComicVineIssueRetrieval(b *testing.B) {
	for name, level := range levels {
		db, ids := setupBenchmark(b, "./comic-hasher/comicvine/comicvine.bolt", cv.BucketIssue, level)
		boltDB := cv.Bolt{Bolt: ch.Bolt{DB: db, Path: db.Path()}}
		b.Run(name, func(b *testing.B) {
			benchmarkIssueRetrieval(b, boltDB, cv.BucketIssue, level, ids)
		})
	}
}
