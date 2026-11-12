package bbolt_test

import (
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestCompact(t *testing.T) {
	// Open a data file.
	db := MustOpenDB()
	defer db.MustClose()

	// Insert until we get above the minimum 4MB size.
	if err := db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("data"))
		for i := range 10000 {
			if err := b.Put(fmt.Appendf(nil, "%04d", i), make([]byte, 1000)); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(db.Path())
	if err != nil {
		t.Fatal(err)
	}

	compactDB := MustOpenDB()

	err = bolt.Compact(compactDB.DB, db.DB, math.MaxUint16)
	if err != nil {
		t.Fatal(err)
	}

	// Compact2 then check that it is all still there.
	err = db.Compact2(math.MaxUint16, testing.Verbose())
	if err != nil {
		t.Fatal(err)
	}

	fi2, err := os.Stat(db.Path())
	if err != nil {
		t.Fatal(err)
	}

	fi3, err := os.Stat(compactDB.Path())
	if err != nil {
		t.Fatal(err)
	}

	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("data"))
		for i := range 10000 {
			if v := b.Get(fmt.Appendf(nil, "%04d", i)); v == nil || len(v) != 1000 {
				t.Fatalf("expected non-nil value of len 1000")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// check that we shrunk in size also
	startSz := fi.Size()
	endSz := fi2.Size()
	bestSz := fi3.Size()
	if endSz < startSz {
		// good, typically seeing  37490688 -> 25444352 bytes (gain=1.47x)
	} else {
		// bad
		t.Fatalf("after Compress, endSz = %v was not less than startSz %v", endSz, startSz)
	}
	if endSz != bestSz {
		t.Fatalf("after Compress, endSz = %v was not equal to bestSz %v", endSz, bestSz)
	}

	if err := db.DB.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAutoCompact(t *testing.T) {
	// Open a data file.
	db := MustOpenDB()
	// defer db.MustClose()

	// setup automatic compaction after one commit.
	db.CompactAfterCommitCount = 1

	// Insert until we get above the minimum 4MB size.
	if err := db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("data"))
		for i := range 10000 {
			if err := b.Put(fmt.Appendf(nil, "%04d", i), make([]byte, 1000)); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// auto-compaction should have happened
	count := db.SuccessfulCompactionCount()
	if count != 1 {
		t.Fatalf("expected 1 auto-compaction, saw %v", count)
	}

	fi, err := os.Stat(db.Path())
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		fmt.Printf("Size after auto-compaction: %v bytes.\n", fi.Size())
	}

	// do 20 more after setting
	db.CompactAfterCommitCount = 100
	// so we should not see any auto-compaction.

	for range 20 {
		log.Print("Stuff")
		if err := db.Update(func(tx *bolt.Tx) error {
			log.Print("tx start")
			b, _ := tx.CreateBucketIfNotExists([]byte("data"))
			if err := b.Put(fmt.Appendf(nil, "%04d", 0), make([]byte, 1000)); err != nil {
				t.Error(err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// should have seen no additional compaction.
	count = db.SuccessfulCompactionCount()
	if count != 1 {
		t.Fatalf("expected 1 auto-compaction, saw %v", count)
	}

	// after having done 20 commits above, if we set
	db.CompactAfterCommitCount = 20
	// then one more commit should result in a compaction.

	if err := db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("data"))
		if err := b.Put(fmt.Appendf(nil, "%04d", 0), make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	count = db.SuccessfulCompactionCount()
	if count != 2 {
		t.Fatalf("expected 2 auto-compaction, saw %v", count)
	}

	if err := db.DB.Close(); err != nil {
		t.Fatal(err)
	}
}

// DB is a test wrapper for bolt.DB.
type DB struct {
	*bolt.DB
}

// MustOpenDB returns a new, open DB at a temporary location.
func MustOpenDB() *DB {
	l := &bolt.DefaultLogger{Logger: log.Default()}
	l.EnableDebug()
	db, err := bolt.Open(tempfile(), 0o666, &bolt.Options{Logger: l})
	if err != nil {
		panic(err)
	}
	return &DB{db}
}

// Close closes the database and deletes the underlying file.
func (db *DB) Close() error {
	// Log statistics.

	// Check database consistency after every test.
	db.MustCheck()

	// Close database and remove file.
	defer os.Remove(db.Path())
	return db.DB.Close()
}

// MustClose closes the database and deletes the underlying file. Panic on error.
func (db *DB) MustClose() {
	if err := db.Close(); err != nil {
		panic(err)
	}
}

// PrintStats prints the database stats
func (db *DB) PrintStats() {
	stats := db.Stats()
	fmt.Printf("[db] %-20s %-20s %-20s\n",
		fmt.Sprintf("pg(%d/%d)", stats.TxStats.PageCount, stats.TxStats.PageAlloc),
		fmt.Sprintf("cur(%d)", stats.TxStats.CursorCount),
		fmt.Sprintf("node(%d/%d)", stats.TxStats.NodeCount, stats.TxStats.NodeDeref),
	)
	fmt.Printf("     %-20s %-20s %-20s\n",
		fmt.Sprintf("rebal(%d/%v)", stats.TxStats.Rebalance, truncDuration(stats.TxStats.RebalanceTime)),
		fmt.Sprintf("spill(%d/%v)", stats.TxStats.Spill, truncDuration(stats.TxStats.SpillTime)),
		fmt.Sprintf("w(%d/%v)", stats.TxStats.Write, truncDuration(stats.TxStats.WriteTime)),
	)
}

func truncDuration(d time.Duration) string {
	return regexp.MustCompile(`^(\d+)(\.\d+)`).ReplaceAllString(d.String(), "$1")
}

// MustCheck runs a consistency check on the database and panics if any errors are found.
func (db *DB) MustCheck() {
	if err := db.Update(func(tx *bolt.Tx) error {
		// Collect all the errors.
		var errors []error
		for err := range tx.Check() {
			errors = append(errors, err)
			if len(errors) > 10 {
				break
			}
		}

		// If errors occurred, copy the DB and print the errors.
		if len(errors) > 0 {
			path := tempfile()
			if err := tx.CopyFile(path, 0o600); err != nil {
				panic(err)
			}

			// Print errors.
			fmt.Print("\n\n")
			fmt.Printf("consistency check failed (%d errors)\n", len(errors))
			for _, err := range errors {
				fmt.Println(err)
			}
			fmt.Println("")
			fmt.Println("db saved to:")
			fmt.Println(path)
			fmt.Print("\n\n")
			os.Exit(-1)
		}

		return nil
	}); err != nil && err != bolt.ErrDatabaseNotOpen {
		panic(err)
	}
}

// CopyTempFile copies a database to a temporary file.
func (db *DB) CopyTempFile() {
	path := tempfile()
	if err := db.View(func(tx *bolt.Tx) error {
		return tx.CopyFile(path, 0o600)
	}); err != nil {
		panic(err)
	}
	fmt.Println("db copied to: ", path)
}

// tempfile returns a temporary file path.
func tempfile() string {
	f, err := os.CreateTemp("", "bolt-")
	if err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}
	if err := os.Remove(f.Name()); err != nil {
		panic(err)
	}
	return f.Name()
}
