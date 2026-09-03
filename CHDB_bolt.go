package ch

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"

	bolt "go.etcd.io/bbolt"
)

type CHDBBolt struct {
	path           string
	db             *bolt.DB
	deleteExisting bool
}

const CHDBVERSION = "1.0.0"

func OpenCHDBBolt(path string, deleteExisting bool) (CHDBBolt, error) {
	path, _ = filepath.Abs(path)
	db, err := bolt.Open(filepath.Join(path, "chdb.bolt"), 0o644, nil)
	if err != nil {
		return CHDBBolt{path, db, deleteExisting}, fmt.Errorf("failed to open database: %w", err)
	}
	db, err = truncate(db)
	if err != nil {
		return CHDBBolt{}, fmt.Errorf("failed to truncate database")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists([]byte("paths"))
		if err != nil {
			return fmt.Errorf("failed to create bucket %v: %w", "paths", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("bad_urls"))
		if err != nil {
			return fmt.Errorf("failed to create bucket %v: %w", "paths", err)
		}
		var versionBucket *bolt.Bucket
		versionBucket, err = tx.CreateBucketIfNotExists([]byte("version"))
		if err != nil {
			return fmt.Errorf("failed to create bucket %v: %w", "paths", err)
		}
		err = versionBucket.Put([]byte("version"), []byte(CHDBVERSION))
		if err != nil {
			return fmt.Errorf("failed to set CHDB version: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return CHDBBolt{path, db, deleteExisting}, fmt.Errorf("failed to init database: %w", err)
	}

	return CHDBBolt{path, db, deleteExisting}, nil
}

func truncate(db *bolt.DB) (*bolt.DB, error) {
	doTruncate := false
	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("version"))
		if bucket == nil {
			doTruncate = true
			return nil
		}
		if !bytes.Equal(bucket.Get([]byte("version")), []byte(CHDBVERSION)) {
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
	err = os.Truncate(path, 0)
	if err != nil {
		return nil, err
	}
	return bolt.Open(path, 0o644, nil)
}

func (c CHDBBolt) Import(paths []string, badURLs []string) {
	slices.Sort(paths)
	slices.Sort(badURLs)
	c.db.Update(func(tx *bolt.Tx) error {
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

func (c CHDBBolt) Dump() (paths []string, badURLs []string) {
	c.db.View(func(tx *bolt.Tx) error {
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
		log.Panic("Absolute path given to chdb:", path)
	}

	tx, err := c.db.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))
	dbRes := b.Get([]byte(path))
	if dbRes != nil {
		if c.deleteExisting {
			err = os.Remove(filepath.Join(c.path, path))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Println("Failed to delete hashed image:", err)
			}
		}
		return true
	}

	return false
}

func (c CHDBBolt) PathDownloaded(path string) bool {
	if filepath.IsAbs(path) {
		log.Panic("Absolute path given to chdb:", path)
	}

	tx, err := c.db.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))
	dbRes := b.Get([]byte(path))
	if dbRes == nil {

		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
		}
		return !os.IsNotExist(err)
	}
	return true
}

func (c CHDBBolt) AddPath(path string) {
	if filepath.IsAbs(path) {
		log.Panic("Absolute path given to chdb:", path)
	}

	tx, err := c.db.Begin(true)
	if err != nil {
		c.db.Logger().Errorf("failed to open transaction: %v", err)
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))

	err = b.Put([]byte(path), []byte{})
	if err != nil {
		log.Println(fmt.Errorf("failed to insert %v (%v) into paths: %w", path, path, err))
	}
	tx.Commit()
	if c.deleteExisting {
		err = os.Remove(filepath.Join(c.path, path))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Println("Failed to delete hashed image:", err)
		}
		_ = RmdirP(filepath.Dir(path))
	}
}

func (c CHDBBolt) CheckURL(url string) bool {
	tx, err := c.db.Begin(true)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("bad_urls"))
	return b.Get([]byte(url)) != nil
}

func (c CHDBBolt) AddURL(url string) {
	tx, err := c.db.Begin(true)
	if err != nil {
		c.db.Logger().Errorf("Failed to open transaction: %v", err)
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("bad_urls"))

	err = b.Put([]byte(url), []byte{})
	if err != nil {
		log.Println(fmt.Errorf("failed to insert %v into bad_urls: %w", url, err))
	}
	tx.Commit()
}

func (c CHDBBolt) Close() error {
	return c.db.Close()
}
