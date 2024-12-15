package ch

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type CHDB struct {
	comicvinePath  string
	sql            *sql.DB
	deleteExisting bool
}

func OpenCHDB(path string, comicvinePath string, deleteExisting bool) (CHDB, error) {
	path, _ = filepath.Abs(path)
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		panic("Unable to create directory " + filepath.Dir(path))
	}
	println(fmt.Sprintf("file://%s?&_pragma=busy_timeout(500)&_pragma=journal_mode(wal)", path))
	sql, err := sql.Open("sqlite", fmt.Sprintf("file://%s?&_pragma=busy_timeout(500)&_pragma=journal_mode(wal)", path))
	if err != nil {
		return CHDB{comicvinePath, sql, deleteExisting}, fmt.Errorf("Failed to open database: %w", err)
	}
	err = sql.Ping()
	if err != nil {
		return CHDB{comicvinePath, sql, deleteExisting}, fmt.Errorf("Failed to open database: %w", err)
	}
	_, err = sql.Exec(`
CREATE TABLE IF NOT EXISTS paths(
    path         STRING  PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS bad_urls(
    url         STRING  PRIMARY KEY
);
`)
	if err != nil {
		err = fmt.Errorf("Failed to create table: %w", err)
	}
	return CHDB{comicvinePath, sql, deleteExisting}, err
}

func (s CHDB) PathHashed(path string) bool {
	path, _ = filepath.Rel(s.comicvinePath, path)
	dbPath := ""
	_ = s.sql.QueryRow("SELECT path FROM paths where path=?", path).Scan(&dbPath)

	if dbPath == path && s.deleteExisting {
		os.Remove(filepath.Join(s.comicvinePath, path))
	}
	return dbPath == path
}

func (s CHDB) PathDownloaded(path string) bool {
	path, _ = filepath.Rel(s.comicvinePath, path)
	dbPath := ""
	_ = s.sql.QueryRow("SELECT path FROM paths where path=?", path).Scan(&dbPath)
	if dbPath != path {
		f, err := os.Open(filepath.Join(s.comicvinePath, path))
		if err == nil {
			defer f.Close()
		}
		return !os.IsNotExist(err)
	}
	return true
}

func (s CHDB) AddPath(path string) {
	path, _ = filepath.Rel(s.comicvinePath, path)
	_, err := s.sql.Exec("INSERT INTO paths VALUES(?) ON CONFLICT DO NOTHING", path)
	if err != nil {
		log.Println(fmt.Errorf("Failed to insert %v into paths: %w", path, err))
	}

	if s.deleteExisting {
		os.Remove(path)
	}
}

func (s CHDB) CheckURL(url string) bool {
	dbURL := ""
	_ = s.sql.QueryRow("SELECT url FROM bad_urls where url=?", url).Scan(&dbURL)
	return dbURL == url
}

func (s CHDB) AddURL(url string) {
	_, err := s.sql.Exec("INSERT INTO bad_urls VALUES(?) ON CONFLICT DO NOTHING", url)
	if err != nil {
		log.Println(fmt.Errorf("Failed to insert %v into bad_urls: %w", url, err))
	}
}

func (s CHDB) Close() error {
	return s.sql.Close()
}
