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

	if s.deleteExisting {
		_ = s.sql.QueryRow("SELECT path FROM paths where path=?", path).Scan(&dbPath)

		if dbPath == path {
			os.Remove(filepath.Join(s.comicvinePath, path))
		}
		return dbPath == path
	}
	count := 0
	_ = s.sql.QueryRow("SELECT count(path) FROM paths where path=?", path).Scan(&count)
	return count > 0
}

func (s CHDB) PathDownloaded(path string) bool {
	relPath, _ := filepath.Rel(s.comicvinePath, path)

	count := 0
	_ = s.sql.QueryRow("SELECT count(path) FROM paths where path=?", relPath).Scan(&count)
	if count != 1 {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
		}
		return !os.IsNotExist(err)
	}
	return true
}

func (s CHDB) AddPath(path string) {
	relPath, _ := filepath.Rel(s.comicvinePath, path)
	_, err := s.sql.Exec("INSERT INTO paths VALUES(?) ON CONFLICT DO NOTHING", relPath)
	if err != nil {
		log.Println(fmt.Errorf("Failed to insert %v into paths: %w", relPath, err))
	}

	if s.deleteExisting {
		_ = os.Remove(path)
		_ = RmdirP(filepath.Dir(path))
	}
}

func (s CHDB) CheckURL(url string) bool {
	count := 0
	_ = s.sql.QueryRow("SELECT count(url) FROM bad_urls where url=?", url).Scan(&count)
	return count > 0
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
