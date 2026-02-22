package ch

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type CHDBSqlite struct {
	path           string
	sql            *sql.DB
	deleteExisting bool
}

func OpenCHDBSqlite(path string, deleteExisting bool) (CHDBSqlite, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return CHDBSqlite{path, nil, deleteExisting}, fmt.Errorf("find path to database: %w", err)
	}
	dbPath := filepath.Join(path, "chdb.db")
	dbURL := fmt.Sprintf("file://%s?&_pragma=busy_timeout(500)&_pragma=journal_mode(wal)", dbPath)
	log.Println("Opening sqlite chdb", dbURL)
	sql, err := sql.Open("sqlite", dbURL)
	if err != nil {
		return CHDBSqlite{path, sql, deleteExisting}, fmt.Errorf("failed to open database: %w", err)
	}
	err = sql.Ping()
	if err != nil {
		return CHDBSqlite{path, sql, deleteExisting}, fmt.Errorf("failed to open database: %w", err)
	}
	_, err = sql.Exec(`
CREATE TABLE IF NOT EXISTS paths(
    path        STRING  PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS bad_urls(
    url         STRING  PRIMARY KEY
);
`)
	if err != nil {
		err = fmt.Errorf("failed to create table: %w", err)
	}
	return CHDBSqlite{path, sql, deleteExisting}, err
}

func (s CHDBSqlite) Dump() (paths []string, badURLs []string) {
	rows, err := s.sql.Query("SELECT path from paths")
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		var value string
		err = rows.Scan(&value)
		if err != nil {
			panic(err)
		}
		paths = append(paths, value)
	}
	rows.Close()

	rows, err = s.sql.Query("SELECT url from bad_urls")
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		var value string
		err = rows.Scan(&value)
		if err != nil {
			panic(err)
		}
		badURLs = append(badURLs, value)
	}
	rows.Close()
	return paths, badURLs
}

func (s CHDBSqlite) PathHashed(path string) bool {
	if filepath.IsAbs(path) {
		log.Panic("Absolute path given to chdb:", path)
	}
	var dbPath string
	if s.deleteExisting {
		_ = s.sql.QueryRow("SELECT path FROM paths where path=?", path).Scan(&dbPath)

		if dbPath == path {
			err := os.Remove(filepath.Join(s.path, path))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Println("Failed to delete hashed image:", err)
			}
		}
		return dbPath == path
	}
	count := 0
	_ = s.sql.QueryRow("SELECT count(path) FROM paths where path=?", path).Scan(&count)
	return count > 0
}

func (s CHDBSqlite) PathDownloaded(path string) bool {
	if filepath.IsAbs(path) {
		log.Panic("Absolute path given to chdb:", path)
	}
	count := 0
	_ = s.sql.QueryRow("SELECT count(path) FROM paths where path=?", path).Scan(&count)
	if count != 1 {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
		}
		return !os.IsNotExist(err)
	}
	return true
}

func (s CHDBSqlite) AddPath(path string) {
	if filepath.IsAbs(path) {
		log.Panic("Absolute path given to chdb:", path)
	}
	_, err := s.sql.Exec("INSERT INTO paths VALUES(?) ON CONFLICT DO NOTHING", path)
	if err != nil {
		log.Println(fmt.Errorf("failed to insert %v into paths: %w", path, err))
	}

	if s.deleteExisting {
		err = os.Remove(filepath.Join(s.path, path))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Println("Failed to delete hashed image:", err)
		}
		_ = RmdirP(filepath.Dir(path))
	}
}

func (s CHDBSqlite) CheckURL(url string) bool {
	count := 0
	_ = s.sql.QueryRow("SELECT count(url) FROM bad_urls where url=?", url).Scan(&count)
	return count > 0
}

func (s CHDBSqlite) AddURL(url string) {
	_, err := s.sql.Exec("INSERT INTO bad_urls VALUES(?) ON CONFLICT DO NOTHING", url)
	if err != nil {
		log.Println(fmt.Errorf("failed to insert %v into bad_urls: %w", url, err))
	}
}

func (s CHDBSqlite) Close() error {
	return s.sql.Close()
}
