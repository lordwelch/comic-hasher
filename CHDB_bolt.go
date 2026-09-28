package ch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"gitea.narnian.us/lordwelch/comic-hasher/log"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/constraints"
)

type Version string

type Bolt struct {
	Path string
	DB   *bolt.DB
}

func (b Bolt) Close() error {
	return b.DB.Close()
}

type CHDBBolt struct {
	Bolt
	BasePath       string
	deleteExisting bool
	validPaths     map[string]bool
}

const CHDBVERSION = "1.0.0"

func OpenCHDBBolt(path string, deleteExisting bool) (CHDBBolt, error) {
	path, _ = filepath.Abs(path)
	chDBPath := filepath.Join(path, "chdb.bolt")
	bolt, err := OpenBolt(chDBPath, CHDBVERSION, []string{"paths", "bad_urls", "source"})
	if err != nil {
		return CHDBBolt{Bolt: bolt, BasePath: path, deleteExisting: deleteExisting, validPaths: make(map[string]bool)}, fmt.Errorf("failed to open database: %w", err)
	}
	return CHDBBolt{Bolt: bolt, BasePath: path, deleteExisting: deleteExisting, validPaths: make(map[string]bool)}, nil
}

func OpenBolt(path string, version Version, buckets []string) (Bolt, error) {
	path, _ = filepath.Abs(path)
	db, err := bolt.Open(path, 0o644, &bolt.Options{FreelistType: bolt.FreelistArrayType, Timeout: time.Millisecond * 100})
	if err != nil {
		return Bolt{path, db}, fmt.Errorf("failed to open database: %w", err)
	}
	db, err = BoltTruncate(db, version)
	if err != nil {
		return Bolt{}, fmt.Errorf("failed to truncate database")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range buckets {
			_, err = tx.CreateBucketIfNotExists([]byte(bucket))
			if err != nil {
				return fmt.Errorf("failed to create bucket %v: %w", bucket, err)
			}
		}

		var versionBucket *bolt.Bucket
		versionBucket, err = tx.CreateBucketIfNotExists([]byte("version"))
		if err != nil {
			return fmt.Errorf("failed to create bucket %v: %w", "paths", err)
		}
		err = versionBucket.Put([]byte("version"), []byte(version))
		if err != nil {
			return fmt.Errorf("failed to set Metron Bolt version: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return Bolt{path, db}, fmt.Errorf("failed to init database: %w", err)
	}

	return Bolt{path, db}, nil
}

func BoltTruncate(db *bolt.DB, version Version) (*bolt.DB, error) {
	doTruncate := false
	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("version"))
		if bucket == nil {
			doTruncate = true
			return nil
		}
		if !bytes.Equal(bucket.Get([]byte("version")), []byte(version)) {
			doTruncate = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !doTruncate {
		return db, nil
	}

	path := db.Path()
	db.Close()
	CHDBLogger.Println(log.Verbose, "Creating new Bolt database")
	err = os.Truncate(path, 0)
	if err != nil {
		return nil, err
	}
	return bolt.Open(path, 0o644, nil)
}

func (c CHDBBolt) Import(paths []string, badURLs []string) {
	slices.Sort(paths)
	slices.Sort(badURLs)
	c.DB.Update(func(tx *bolt.Tx) error {
		p := tx.Bucket([]byte("paths"))
		b := tx.Bucket([]byte("bad_urls"))

		for _, path := range paths {
			p.Put([]byte(path), []byte{})
		}
		for _, url := range badURLs {
			b.Put([]byte(url), []byte{})
		}
		return nil
	})
}

func (c CHDBBolt) ValidatePath(path string) bool {
	firstDir, _ := log.Partition(path, "/")
	if c.validPaths[firstDir] {
		return true
	}
	_, err := os.Stat(filepath.Join(c.BasePath, firstDir))
	c.validPaths[firstDir] = err == nil
	return c.validPaths[firstDir]
}

func (c CHDBBolt) Dump() (paths []string, badURLs []string) {
	c.DB.View(func(tx *bolt.Tx) error {
		p := tx.Bucket([]byte("paths"))
		b := tx.Bucket([]byte("bad_urls"))
		paths = make([]string, 0, p.Inspect().KeyN)
		badURLs = make([]string, 0, b.Inspect().KeyN)
		b.ForEach(func(k, v []byte) error {
			badURLs = append(badURLs, string(k)+"")
			return nil
		})
		p.ForEach(func(k, v []byte) error {
			paths = append(paths, string(k)+"")
			return nil
		})
		return nil
	})
	return paths, badURLs
}

func (c CHDBBolt) PathHashed(path string) bool {
	if filepath.IsAbs(path) {
		panic(fmt.Sprintln("Absolute path given to chdb:", path))
	}
	if !c.ValidatePath(path) {
		panic(fmt.Sprintln("Invalid path", path))
	}

	tx, err := c.DB.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))
	dbRes := b.Get([]byte(path))
	if dbRes != nil {
		if c.deleteExisting {
			err = os.Remove(filepath.Join(c.BasePath, path))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				CHDBLogger.Println(log.Required, "Failed to delete hashed image:", err)
			}
		}
		return true
	}

	return false
}

func IntToBolt[T constraints.Integer](v T) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

func (c CHDBBolt) PathDownloaded(path string) bool {
	if filepath.IsAbs(path) {
		panic(fmt.Sprintln("Absolute path given to chdb:", path))
	}
	if !c.ValidatePath(path) {
		panic(fmt.Sprintln("Invalid path", path))
	}

	tx, err := c.DB.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))
	dbRes := b.Get([]byte(path))
	if dbRes == nil {
		_, err := os.Stat(filepath.Join(c.BasePath, path))
		// We only care if the error is not ErrNotExist
		// If it's something else we should get an error on the next operation
		// If it is nil then it still is not ErrNotExist which means we return true
		return !errors.Is(err, fs.ErrNotExist)
	}
	return true
}

func (c CHDBBolt) AddPath(path string) {
	if filepath.IsAbs(path) {
		panic(fmt.Sprintln("Absolute path given to chdb:", path))
	}
	if !c.ValidatePath(path) {
		panic(fmt.Sprintln("Invalid path", path))
	}

	tx, err := c.DB.Begin(true)
	if err != nil {
		CHDBLogger.Log(log.Fatal, "failed to open transaction: %v", err)
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))

	err = b.Put([]byte(path), []byte{})
	if err != nil {
		CHDBLogger.Log(log.Fatal, "failed to insert %v (%v) into paths: %v", path, path, err)
	}
	tx.Commit()
	if c.deleteExisting {
		err = os.Remove(filepath.Join(c.BasePath, path))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			CHDBLogger.Println(log.Required, "Failed to delete hashed image:", err)
		}
		_ = RmdirP(filepath.Dir(path))
	}
}

func (c CHDBBolt) CheckURL(url string) bool {
	tx, err := c.DB.Begin(true)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("bad_urls"))
	return b.Get([]byte(url)) != nil
}

func (c CHDBBolt) AddURL(url string) {
	tx, err := c.DB.Begin(true)
	if err != nil {
		CHDBLogger.Log(log.Fatal, "Failed to open transaction: %v", err)
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("bad_urls"))

	err = b.Put([]byte(url), []byte{})
	if err != nil {
		CHDBLogger.Log(log.Fatal, "failed to insert %v into bad_urls: %v", url, err) // TODO: this should probably be fatal
	}
	tx.Commit()
}

func (c CHDBBolt) Close() error {
	return c.DB.Close()
}

func (c CHDBBolt) GetSourceID(name string) byte {
	var sourceID byte
	c.DB.View(func(tx *bolt.Tx) error {
		tx.Bucket([]byte("source")).ForEach(func(k, v []byte) error {
			if len(k) != 1 || k[0] == 0 {
				return nil
			}
			if bytes.EqualFold(v, []byte(name)) {
				sourceID = k[0]
			}
			return nil
		})
		return nil
	})
	return sourceID
}

func (c CHDBBolt) GetSourceName(sourceID byte) string {
	var sourceName string
	c.DB.View(func(tx *bolt.Tx) error {
		name := tx.Bucket([]byte("source")).Get([]byte{sourceID})
		if len(name) > 0 {
			sourceName = string(bytes.Clone(name))
		}
		return nil
	})
	return sourceName
}
