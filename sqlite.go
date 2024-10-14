package ch

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"strings"
	"time"

	"gitea.narnian.us/lordwelch/goimagehash"
	_ "modernc.org/sqlite"
)

type sqliteStorage struct {
	db *sql.DB
}
type sqliteHash struct {
	hashid int
	Result
}

func (s *sqliteStorage) findExactHashes(statement *sql.Stmt, items ...interface{}) ([]sqliteHash, error) { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
	hashes := []sqliteHash{}
	rows, err := statement.Query(items...)
	if err != nil {
		return hashes, err
	}

	for rows.Next() {
		var (
			r = sqliteHash{Result: Result{IDs: make(IDList)}}
			h int64
		)
		err = rows.Scan(&r.hashid, &h, &r.Hash.Kind)
		if err != nil {
			rows.Close()
			return hashes, err
		}
		r.Hash.Hash = uint64(h)
		hashes = append(hashes, r)
	}
	rows.Close()
	statement, err = s.db.PrepareContext(context.Background(), `SELECT IDS.domain, IDs.id FROM IDs JOIN id_hash ON IDs.rowid = id_hash.idid WHERE (id_hash.hashid=?) ORDER BY IDs.domain, IDs.ID;`)
	if err != nil {
		return hashes, err
	}
	for _, hash := range hashes {
		rows, err := statement.Query(hash.hashid)
		if err != nil {
			return hashes, err
		}
		for rows.Next() {
			var source Source
			var id string
			err := rows.Scan(&source, &id)
			if err != nil {
				return hashes, err
			}
			hash.IDs[source] = append(hash.IDs[source], id)
		}
		rows.Close()
	}
	return hashes, nil
}

func (s *sqliteStorage) findPartialHashes(max int, search_hash int64, kind goimagehash.Kind) ([]sqliteHash, error) { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
	hashes := []sqliteHash{}
	statement, err := s.db.PrepareContext(context.Background(), `SELECT rowid,hash,kind FROM Hashes WHERE (kind=?) AND (((hash >> (0 * 8) & 0xFF)=(?2 >> (0 * 8) & 0xFF)) OR ((hash >> (1 * 8) & 0xFF)=(?2 >> (1 * 8) & 0xFF)) OR ((hash >> (2 * 8) & 0xFF)=(?2 >> (2 * 8) & 0xFF)) OR ((hash >> (3 * 8) & 0xFF)=(?2 >> (3 * 8) & 0xFF)) OR ((hash >> (4 * 8) & 0xFF)=(?2 >> (4 * 8) & 0xFF)) OR ((hash >> (5 * 8) & 0xFF)=(?2 >> (5 * 8) & 0xFF)) OR ((hash >> (6 * 8) & 0xFF)=(?2 >> (6 * 8) & 0xFF)) OR ((hash >> (7 * 8) & 0xFF)=(?2 >> (7 * 8) & 0xFF)));`)
	if err != nil {
		return hashes, err
	}
	rows, err := statement.Query(kind, int64(search_hash))
	if err != nil {
		return hashes, err
	}

	for rows.Next() {
		var (
			r = sqliteHash{Result: Result{IDs: make(IDList)}}
			h int64
		)
		err = rows.Scan(&r.hashid, &h, &r.Hash.Kind)
		if err != nil {
			rows.Close()
			return hashes, err
		}
		r.Hash.Hash = uint64(h)
		r.Distance = bits.OnesCount64(uint64(search_hash) ^ r.Hash.Hash)
		if r.Distance <= max {
			hashes = append(hashes, r)
		}
	}
	rows.Close()
	logTime("Filter partial " + kind.String())

	statement, err = s.db.PrepareContext(context.Background(), `SELECT DISTINCT IDS.domain, IDs.id, id_hash.hashid FROM IDs JOIN id_hash ON IDs.rowid = id_hash.idid WHERE (id_hash.hashid in (`+strings.TrimRight(strings.Repeat("?,", len(hashes)), ",")+`)) ORDER BY IDs.domain, IDs.ID;`)
	if err != nil {
		return hashes, err
	}

	var ids []any
	for _, hash := range hashes {
		ids = append(ids, hash.hashid)
	}
	rows, err = statement.Query(ids...)
	if err != nil {
		return hashes, err
	}
	for rows.Next() {
		var source Source
		var id string
		var hashid int
		err := rows.Scan(&source, &id, &hashid)
		if err != nil {
			return hashes, err
		}
		for _, hash := range hashes {
			if hash.hashid == hashid {
				hash.IDs[source] = append(hash.IDs[source], id)
			}
		}
	}
	rows.Close()
	return hashes, nil
}

func (s *sqliteStorage) dropIndexes() error {
	_, err := s.db.Exec(`

	DROP INDEX IF EXISTS hash_index;
	DROP INDEX IF EXISTS hash_1_index;
	DROP INDEX IF EXISTS hash_2_index;
	DROP INDEX IF EXISTS hash_3_index;
	DROP INDEX IF EXISTS hash_4_index;
	DROP INDEX IF EXISTS hash_5_index;
	DROP INDEX IF EXISTS hash_6_index;
	DROP INDEX IF EXISTS hash_7_index;
	DROP INDEX IF EXISTS hash_8_index;

	DROP INDEX IF EXISTS id_domain;
	`)
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStorage) createIndexes() error {
	_, err := s.db.Exec(`

CREATE INDEX IF NOT EXISTS hash_index   ON Hashes (kind, hash);
CREATE INDEX IF NOT EXISTS hash_1_index ON Hashes ((hash >> (0 * 8) & 0xFF));
CREATE INDEX IF NOT EXISTS hash_2_index ON Hashes ((hash >> (1 * 8) & 0xFF));
CREATE INDEX IF NOT EXISTS hash_3_index ON Hashes ((hash >> (2 * 8) & 0xFF));
CREATE INDEX IF NOT EXISTS hash_4_index ON Hashes ((hash >> (3 * 8) & 0xFF));
CREATE INDEX IF NOT EXISTS hash_5_index ON Hashes ((hash >> (4 * 8) & 0xFF));
CREATE INDEX IF NOT EXISTS hash_6_index ON Hashes ((hash >> (5 * 8) & 0xFF));
CREATE INDEX IF NOT EXISTS hash_7_index ON Hashes ((hash >> (6 * 8) & 0xFF));
CREATE INDEX IF NOT EXISTS hash_8_index ON Hashes ((hash >> (7 * 8) & 0xFF));

CREATE INDEX IF NOT EXISTS id_domain ON IDs (domain, id);
PRAGMA shrink_memory;
ANALYZE;
`)
	if err != nil {
		return err
	}
	return nil
}

var (
	total time.Duration
	t     = time.Now()
)

func resetTime() {
	total = 0
	t = time.Now()
}

func logTime(log string) {
	n := time.Now()
	s := n.Sub(t)
	t = n
	total += s
	fmt.Printf("total: %v, %s: %v\n", total, log, s)
}

func (s *sqliteStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var (
		foundMatches []Result
	)
	resetTime()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate

		statement, err := s.db.Prepare(`SELECT rowid,hash,kind FROM Hashes WHERE ` + strings.TrimSuffix(strings.Repeat("(hash=? AND kind=?) OR", len(hashes)), "OR") + `ORDER BY kind,hash;`)
		if err != nil {
			logTime("Fail exact")
			return foundMatches, err
		}

		args := make([]interface{}, 0, len(hashes)*2)
		for _, hash := range hashes {
			if hash.Hash != 0 {
				args = append(args, int64(hash.Hash), hash.Kind)
			}
		}
		hashes, err := s.findExactHashes(statement, args...)
		if err != nil {
			return foundMatches, err
		}
		for _, hash := range hashes {
			foundMatches = append(foundMatches, hash.Result)
		}

		// If we have exact matches don't bother with other matches
		if len(foundMatches) > 0 && exactOnly {
			return foundMatches, nil
		}
		logTime("Search Exact")
	}

	foundHashes := make(map[uint64]struct{})

	for _, hash := range hashes {
		hashes, err := s.findPartialHashes(max, int64(hash.Hash), hash.Kind)
		if err != nil {
			return foundMatches, err
		}
		logTime("Search partial " + hash.Kind.String())

		for _, hash := range hashes {
			if _, alreadyMatched := foundHashes[hash.Hash.Hash]; !alreadyMatched {
				foundHashes[hash.Hash.Hash] = struct{}{}
				foundMatches = append(foundMatches, hash.Result)
			} else {
				log.Println("Hash already found", hash)
			}
		}
	}

	return foundMatches, nil
}

func (s *sqliteStorage) MapHashes(hash ImageHash) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	insertHashes, err := tx.Prepare(`
INSERT INTO Hashes (hash,kind) VALUES (?,?) ON CONFLICT DO UPDATE SET hash=?1 RETURNING hashid
`)
	if err != nil {
		panic(err)
	}
	rows, err := tx.Query(`
INSERT INTO IDs (domain,id) VALUES (?,?) ON CONFLICT DO UPDATE SET domain=?1 RETURNING idid
`, hash.ID.Domain, hash.ID.ID)
	if err != nil {
		panic(err)
	}
	if !rows.Next() {
		panic("Unable to insert IDs")
	}
	var id_id int64
	err = rows.Scan(&id_id)
	if err != nil {
		panic(err)
	}
	rows.Close()
	hash_ids := []int64{}
	for _, hash := range hash.Hashes {
		rows, err := insertHashes.Query(int64(hash.Hash), hash.Kind)
		if err != nil {
			panic(err)
		}

		if !rows.Next() {
			panic("Unable to insert IDs")
		}
		var id int64
		err = rows.Scan(&id)
		rows.Close()
		if err != nil {
			panic(err)
		}
		hash_ids = append(hash_ids, id)
	}
	var ids []any
	for _, hash_id := range hash_ids {
		ids = append(ids, hash_id, id_id)
	}
	_, err = tx.Exec(`INSERT INTO id_hash (hashid,idid) VALUES `+strings.TrimSuffix(strings.Repeat("(?, ?),", len(hash_ids)), ",")+` ON CONFLICT DO NOTHING;`, ids...)
	if err != nil {
		panic(fmt.Errorf("Failed inserting: %v,%v: %w", hash.ID.Domain, hash.ID.ID, err))
	}
	err = tx.Commit()
	if err != nil {
		panic(err)
	}
	insertHashes.Close()
}

func (s *sqliteStorage) DecodeHashes(hashes SavedHashes) error {
	err := s.dropIndexes()
	if err != nil {
		return err
	}

	for hashType, sourceHashes := range hashes.Hashes {
		hashKind := goimagehash.Kind(hashType + 1)
		for hash, idsLocations := range sourceHashes {
			for _, id := range hashes.IDs[idsLocations] {
				s.MapHashes(ImageHash{
					Hashes: []Hash{{hash, hashKind}},
					ID:     id,
				})
			}
		}
	}
	err = s.createIndexes()
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStorage) EncodeHashes() (SavedHashes, error) {
	hashes := SavedHashes{}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return hashes, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(context.Background(), "SELECT IDs.domain,IDs.id,Hashes.hash,Hashes.kind FROM Hashes JOIN id_hash ON id_hash.hashid = hashes.rowid JOIN IDs ON IDs.rowid = id_hash.idid ORDER BY IDs.ID,Hashes.kind,Hashes.hash;")
	if err != nil {
		rows.Close()
		return hashes, err
	}
	var (
		id   ID
		hash Hash
	)
	err = rows.Scan(&id.Domain, &id.ID, &hash.Hash, &hash.Kind)
	if err != nil {
		return hashes, err
	}
	hashes.InsertHash(hash, id)

	return hashes, nil
}

func (s *sqliteStorage) AssociateIDs(newIDs []NewIDs) error {
	for _, ids := range newIDs {
		var oldIDID, newIDID int
		_, err := s.db.Exec(`INSERT INTO IDs domain,id VALUES (?,?)`, ids.NewID.Domain, ids.NewID.ID)
		if err != nil {
			return err
		}
		rows, err := s.db.Query(`SELECT idid FROM IDs WHERE domain=? AND id=?`, ids.NewID.Domain, ids.NewID.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if rows.Next() {
			rows.Scan(&newIDID)
		} else {
			return errors.New("Unable to insert New ID into database")
		}
		rows.Close()
		rows, err = s.db.Query(`SELECT idid FROM IDs WHERE domain=? AND id=?`, ids.OldID.Domain, ids.OldID.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if rows.Next() {
			rows.Scan(&oldIDID)
		} else {
			continue
		}
		_, err = s.db.Exec(`INSERT INTO id_hash (hashid, id_id) SELECT hashid,? FROM id_hash where id_id=?`, newIDID, oldIDID)
		if err != nil {
			return fmt.Errorf("Unable to associate IDs: %w", err)
		}
	}
	return nil
}

func (s *sqliteStorage) GetIDs(id ID) IDList {
	var idid int
	rows, err := s.db.Query(`SELECT idid FROM IDs WHERE domain=? AND id=?`, id.Domain, id.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if rows.Next() {
		rows.Scan(&idid)
	} else {
		return nil
	}
	rows, err = s.db.Query(`SELECT id_hash FROM id_hash WHERE id_id=?`, idid)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		panic(err)
	}
	var hashIDs []interface{}
	for rows.Next() {
		var hashID int
		rows.Scan(&hashID)
		hashIDs = append(hashIDs, hashID)
	}
	rows.Close()

	IDs := make(IDList)
	rows, err = s.db.Query(`SELECT IDs.domain,IDs.id FROM id_hash JOIN IDs ON id_hash.idid==IDs.idid WHERE hash_id in (`+strings.TrimRight(strings.Repeat("?,", len(hashIDs)), ",")+`)`, hashIDs...)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		panic(err)
	}
	for rows.Next() {
		var id ID
		rows.Scan(&id.Domain, id.ID)
		IDs[id.Domain] = append(IDs[id.Domain], id.ID)
	}
	return IDs
}

func NewSqliteStorage(db, path string) (HashStorage, error) {
	sqlite := &sqliteStorage{}
	sqlDB, err := sql.Open(db, fmt.Sprintf("file://%s?_pragma=cache_size(-200000)&_pragma=busy_timeout(500)&_pragma=hard_heap_limit(1073741824)&_pragma=journal_mode(wal)&_pragma=soft_heap_limit(314572800)", path))
	if err != nil {
		panic(err)
	}
	sqlite.db = sqlDB
	_, err = sqlite.db.Exec(`
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS Hashes(
    hashid         INTEGER  PRIMARY KEY,
    hash          INT  NOT NULL,
    kind          int NOT NULL,
    UNIQUE(kind, hash)
);

CREATE TABLE IF NOT EXISTS IDs(
    id          TEXT NOT NULL,
    domain      TEXT NOT NULL,
    idid       INTEGER  PRIMARY KEY,
    UNIQUE (domain, id)
);
CREATE INDEX IF NOT EXISTS id_domain ON IDs (domain, id);

CREATE TABLE IF NOT EXISTS id_hash(
  hashid     INTEGER,
  idid       INTEGER,
  FOREIGN KEY(hashid) REFERENCES Hashes(hashid),
  FOREIGN KEY(idid) REFERENCES IDs(idid)
  UNIQUE (hashid, idid)
);

`)
	if err != nil {
		panic(err)
	}
	sqlite.createIndexes()
	sqlite.db.SetMaxOpenConns(1)
	return sqlite, nil
}
