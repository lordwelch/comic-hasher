package main_test

import (
	"errors"
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
// bucket from srcPath compressed with write.
func writeCompressedDB(tb testing.TB, srcPath, outPath, bucket string, write func([]byte) ([]byte, error)) error {
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
			compressed, err := write(v)
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

func setupBenchmark(b *testing.B, dbPath, bucket string, write func([]byte) ([]byte, error)) (*bolt.DB, []int64) {
	b.Helper()
	compressedDBPath := filepath.Join(b.TempDir(), filepath.Base(dbPath))
	if err := writeCompressedDB(b, dbPath, compressedDBPath, bucket, write); err != nil {
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

type issueDBTX[T cv.Issue | metron.Issue] interface {
	Issue(*bolt.Tx, int64) T
	View(func(tx *bolt.Tx) error) error
}

func benchmarkIssueRetrieval[T cv.Issue | metron.Issue](b *testing.B, boltDB issueDBTX[T], bucket string, ids []int64) {
	for range b.N {
		for _, id := range ids {
			issue := boltDB.Issue(nil, id)
			var got int64
			switch v := any(issue).(type) {
			case cv.Issue:
				got = v.ID
			case metron.Issue:
				got = v.ID
			}
			if got != id {
				b.Errorf("issue retrieval mismatch: want id %d, got %d", id, got)
				b.FailNow()
			}
		}
	}
}

func benchmarkIssueRetrievalOneTX[T cv.Issue | metron.Issue](b *testing.B, boltDB issueDBTX[T], bucket string, ids []int64) {
	for range b.N {
		if err := boltDB.View(func(tx *bolt.Tx) error {
			for _, id := range ids {
				issue := boltDB.Issue(tx, id)
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

// zstdCodec returns the zstd Codec and dictionary used for the given source.
func zstdCodec(b testing.TB, source string) ch.Codec {
	var path string
	switch source {
	case "metron":
		path = "metron/zstd.dict"
	case "comicvine":
		path = "cv/zstd.dict"
	default:
		b.Fatalf("unknown source %q", source)
	}
	dict, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("failed to read %s: %v", path, err)
	}
	codec, err := ch.NewCodec(ch.CompressionZSTD, dict)
	if err != nil {
		b.Fatalf("failed to create zstd codec: %v", err)
	}
	return codec
}

// benchmarkBoth runs the issue retrieval benchmark for both sources. write is
// used to compress the source databases, and codecFor returns the Codec used
// to retrieve the issues.
func benchmarkBoth(b *testing.B, write func(source string, v []byte) ([]byte, error), codecFor func(source string) ch.Codec) {
	metronDB, metronIDs := setupBenchmark(b, "./metron-hashes/metron/metron.bolt", metron.BucketIssue, func(v []byte) ([]byte, error) {
		return write("metron", v)
	})
	cvDB, cvIDs := setupBenchmark(b, "./comic-hasher/comicvine/comicvine.bolt", cv.BucketIssue, func(v []byte) ([]byte, error) {
		return write("comicvine", v)
	})
	defer metronDB.Close()
	defer cvDB.Close()

	b.Run("source=Metron", func(b *testing.B) {
		st, _ := os.Stat(metronDB.Path())
		b.ReportMetric(float64(st.Size()), "bytes")
		benchmarkIssueRetrievalOneTX(b, metron.Bolt{Bolt: ch.Bolt{DB: metronDB, Path: metronDB.Path()}, Codec: codecFor("metron")}, metron.BucketIssue, metronIDs)
	})
	b.Run("source=ComicVine", func(b *testing.B) {
		st, _ := os.Stat(cvDB.Path())
		b.ReportMetric(float64(st.Size()), "bytes")
		benchmarkIssueRetrievalOneTX(b, cv.Bolt{Bolt: ch.Bolt{DB: cvDB, Path: cvDB.Path()}, Codec: codecFor("comicvine")}, cv.BucketIssue, cvIDs)
	})
}

func BenchmarkIssueRetrieval(b *testing.B) {
	for name, level := range levels {
		b.Run("compression="+name, func(b *testing.B) {
			benchmarkBoth(b, func(source string, v []byte) ([]byte, error) {
				return minlz.AppendEncoded(nil, v, level)
			}, func(string) ch.Codec { return ch.Codec{Compression: ch.CompressionMinLZ} })
		})
	}
	b.Run("compression=ZSTD", func(b *testing.B) {
		metronCodec := zstdCodec(b, "metron")
		cvCodec := zstdCodec(b, "comicvine")
		benchmarkBoth(b, func(source string, v []byte) ([]byte, error) {
			if source == "metron" {
				return metronCodec.Compress(v)
			}
			return cvCodec.Compress(v)
		}, func(source string) ch.Codec {
			if source == "metron" {
				return metronCodec
			}
			return cvCodec
		})
	})
}
