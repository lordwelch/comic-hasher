package ch

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"

	bolt "go.etcd.io/bbolt"
)

type CHDBBolt struct {
	comicvinePath  string
	db             *bolt.DB
	deleteExisting bool
}

func OpenCHDBBolt(path string, comicvinePath string, deleteExisting bool) (CHDBBolt, error) {
	path, _ = filepath.Abs(path)
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		panic("Unable to create directory " + filepath.Dir(path))
	}
	db, err := bolt.Open(path, 0o644, nil)
	if err != nil {
		return CHDBBolt{comicvinePath, db, deleteExisting}, fmt.Errorf("failed to open database: %w", err)
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
		return nil
	})
	if err != nil {
		db.Close()
		return CHDBBolt{comicvinePath, db, deleteExisting}, fmt.Errorf("failed to init database: %w", err)
	}

	return CHDBBolt{comicvinePath, db, deleteExisting}, nil
}

func (c CHDBBolt) Import(paths []string, bad_urls []string) {
	slices.Sort(paths)
	slices.Sort(bad_urls)
	c.db.Update(func(tx *bolt.Tx) error {
		p := tx.Bucket([]byte("paths"))
		b := tx.Bucket([]byte("bad_urls"))

		for _, path := range paths {
			p.Put([]byte(path), []byte{})
		}
		for _, url := range bad_urls {
			b.Put([]byte(url), []byte{})
		}
		return nil
	})
}

func (c CHDBBolt) Dump() (paths []string, bad_urls []string) {

	c.db.View(func(tx *bolt.Tx) error {
		p := tx.Bucket([]byte("paths"))
		b := tx.Bucket([]byte("bad_urls"))
		paths = make([]string, 0, p.Inspect().KeyN)
		bad_urls = make([]string, 0, b.Inspect().KeyN)
		b.ForEach(func(k, v []byte) error {
			bad_urls = append(bad_urls, string(k)+"")
			return nil
		})
		p.ForEach(func(k, v []byte) error {
			paths = append(paths, string(k)+"")
			return nil
		})
		return nil
	})
	return paths, bad_urls
}

func (c CHDBBolt) PathHashed(path string) bool {
	path, _ = filepath.Rel(c.comicvinePath, path)

	tx, err := c.db.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))
	dbRes := b.Get([]byte(path))
	if dbRes != nil {
		if c.deleteExisting {
			os.Remove(filepath.Join(c.comicvinePath, path))
		}
		return true
	}

	return false
}

func (c CHDBBolt) PathDownloaded(path string) bool {
	relPath, _ := filepath.Rel(c.comicvinePath, path)

	tx, err := c.db.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))
	dbRes := b.Get([]byte(relPath))
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
	relPath, _ := filepath.Rel(c.comicvinePath, path)

	tx, err := c.db.Begin(true)
	if err != nil {
		c.db.Logger().Errorf("Failed to open transaction: %v", err)
	}
	defer tx.Rollback()
	b := tx.Bucket([]byte("paths"))

	err = b.Put([]byte(relPath), []byte{})
	if err != nil {
		log.Println(fmt.Errorf("Failed to insert %v (%v) into paths: %w", path, relPath, err))
	}
	tx.Commit()
	if c.deleteExisting {
		_ = os.Remove(path)
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
		log.Println(fmt.Errorf("Failed to insert %v into bad_urls: %w", url, err))
	}
	tx.Commit()
}

func (c CHDBBolt) Close() error {
	return c.db.Close()
}
