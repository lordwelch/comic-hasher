package ch

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/bits"

	_ "modernc.org/sqlite"
)

type sqliteStorage struct {
	db *sql.DB

	hashExactMatchStatement   *sql.Stmt
	hashPartialMatchStatement *sql.Stmt

	idMatchStatement *sql.Stmt

	insertHash *sql.Stmt
	insertID   *sql.Stmt
	insertEID  *sql.Stmt
	insertIEID *sql.Stmt
	idExists   *sql.Stmt
}

func (s *sqliteStorage) findExactHashes(statement *sql.Stmt, hash Hash) ([]ID, error) {
	if statement == nil {
		statement = s.hashExactMatchStatement
	}
	hashes := []ID{}
	rows, err := statement.Query(hash.Kind, int64(hash.Hash))
	if err != nil {
		return hashes, err
	}

	for rows.Next() {
		var (
			r = ID{}
		)
		err = rows.Scan(&r.Domain, &r.ID)
		if err != nil {
			rows.Close()
			return hashes, err
		}
		hashes = append(hashes, r)
	}
	rows.Close()
	return hashes, nil
}

func (s *sqliteStorage) findPartialHashes(tl timeLog, statement *sql.Stmt, max int, hash Hash) ([]Result, error) {
	if statement == nil {
		statement = s.hashPartialMatchStatement
	}
	hashResults := []Result{}
	rows, err := statement.Query(hash.Kind, int64(hash.Hash))
	if err != nil {
		return hashResults, err
	}

	results := map[Hash][]ID{}
	for rows.Next() {
		var (
			tmpHash int64
			sqlHash = Hash{Kind: hash.Kind}
			id      ID
		)
		err = rows.Scan(&tmpHash, &id.Domain, &id.ID)
		if err != nil {
			rows.Close()
			return hashResults, err
		}
		sqlHash.Hash = uint64(tmpHash)
		results[sqlHash] = append(results[sqlHash], id)
	}
	for sqlHash, ids := range results {
		res := Result{
			Hash:     sqlHash,
			Distance: bits.OnesCount64(hash.Hash ^ sqlHash.Hash),
		}
		if res.Distance <= max {
			res.IDs = ToIDList(ids)
			hashResults = append(hashResults, res)
		}
	}
	return hashResults, nil
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

        CREATE INDEX IF NOT EXISTS id_domain ON IDs (domain, stringid);
        PRAGMA shrink_memory;
        ANALYZE;
    `)
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var (
		foundMatches []Result
		tl           timeLog
	)
	tl.resetTime()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		for _, hash := range hashes {
			idlist, err := s.findExactHashes(nil, hash)
			if err != nil {
				return foundMatches, err
			}
			foundMatches = append(foundMatches, Result{
				IDs:  ToIDList(idlist),
				Hash: hash,
			})
		}

		tl.logTime("Search Exact")
		if len(foundMatches) > 0 {
			return foundMatches, nil
		}
	}

	foundHashes := make(map[uint64]struct{})

	for _, hash := range hashes {
		results, err := s.findPartialHashes(tl, nil, max, hash)
		if err != nil {
			return foundMatches, err
		}
		tl.logTime(fmt.Sprintf("Search partial %v", hash.Kind))

		for _, hash := range results {
			if _, alreadyMatched := foundHashes[hash.Hash.Hash]; !alreadyMatched {
				foundHashes[hash.Hash.Hash] = struct{}{}
				foundMatches = append(foundMatches, hash)
			} else {
				log.Println("Hash already found", hash)
			}
		}
	}

	return foundMatches, nil
}

func (s *sqliteStorage) mapHashes(tx *sql.Tx, hash ImageHash) {
	var err error
	insertHash := tx.Stmt(s.insertHash)
	insertID := tx.Stmt(s.insertID)
	idExists := tx.Stmt(s.idExists)
	insertEID := tx.Stmt(s.insertEID)
	insertIEID := tx.Stmt(s.insertIEID)

	rows, err := insertID.Query(hash.ID.Domain, hash.ID.ID)
	if err != nil {
		panic(err)
	}
	if !rows.Next() {
		panic("Unable to insert ID")
	}

	var id_id int64
	err = rows.Scan(&id_id)
	if err != nil {
		panic(err)
	}
	rows.Close()

	for _, hash := range hash.Hashes {
		_, err := insertHash.Exec(hash.Kind, int64(hash.Hash), id_id)
		if err != nil {
			panic(err)
		}
	}
	rows.Close()
	row := idExists.QueryRow(id_id)
	var count int64
	err = row.Scan(&count)
	if err != nil {
		panic(fmt.Errorf("failed to query id: %w", err))
	}
	if count < 1 {
		row := insertEID.QueryRow()
		var eid int64
		err = row.Scan(&eid)
		if err != nil {
			panic(fmt.Errorf("failed to insert equivalent id: %w", err))
		}
		_, err := insertIEID.Exec(id_id, eid)
		if err != nil {
			panic(fmt.Errorf("failed to associate equivalent IDs: %w", err))
		}
	}
}
func (s *sqliteStorage) MapHashes(hash ImageHash) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	s.mapHashes(tx, hash)
	err = tx.Commit()
	if err != nil {
		panic(err)
	}
}

func (s *sqliteStorage) DecodeHashes(hashes SavedHashes) error {
	return nil
	err := s.dropIndexes()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	insertID := tx.Stmt(s.insertID)
	insertEID := tx.Stmt(s.insertEID)
	insertIEID := tx.Stmt(s.insertIEID)
	for _, idlist := range hashes.IDs {
		var eid int64
		id_ids := make([]int64, 0, len(idlist))
		for _, id := range idlist {
			var id_id int64
			row := insertID.QueryRow(id.Domain, id.ID)
			err = row.Scan(&id_id)
			if err != nil {
				return fmt.Errorf("failed to insert id: %w", err)
			}
			id_ids = append(id_ids, id_id)
		}
		row := insertEID.QueryRow()
		err = row.Scan(&eid)
		if err != nil {
			return fmt.Errorf("failed to insert equivalent id: %w", err)
		}
		for _, id_id := range id_ids {
			_, err = insertIEID.Exec(id_id, eid)
			if err != nil {
				return err
			}
		}
	}

	for _, savedHash := range hashes.Hashes {
		s.mapHashes(tx, ImageHash{
			Hashes: []Hash{savedHash.Hash},
			ID:     savedHash.ID,
		})
	}

	err = tx.Commit()
	if err != nil {
		panic(err)
	}
	err = s.createIndexes()
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStorage) EncodeHashes() (SavedHashes, error) {
	hashes := SavedHashes{}
	tx, err := s.db.Begin()
	if err != nil {
		return hashes, err
	}

	rows, err := tx.Query("SELECT Hashes.kind, Hashes.hash, IDs.domain, IDs.stringid FROM Hashes JOIN IDs ON Hashes.id=IDs.id ORDER BY Hashes.kind, Hashes.hash;")
	if err != nil {
		return hashes, err
	}
	for rows.Next() {
		var (
			hash    SavedHash
			tmpHash int64
		)
		err = rows.Scan(&hash.Hash.Kind, &tmpHash, &hash.ID.Domain, &hash.ID.ID)
		if err != nil {
			return hashes, err
		}
		hash.Hash.Hash = uint64(tmpHash)
		hashes.InsertHash(hash)
	}
	rows, err = tx.Query("SELECT IEIDs.equivalentid, IDs.domain, IDs.stringid FROM IDs JOIN IDsToEquivalantIDs AS IEIDs ON IDs.id=IEIDs.idid ORDER BY IEIDs.equivalentid, IDs.domain, IDs.stringid;")
	if err != nil {
		return hashes, err
	}
	var (
		previousEid int64 = -1
		ids         []ID
	)
	for rows.Next() {
		var (
			id     ID
			newEid int64
		)
		err = rows.Scan(&newEid, &id.Domain, &id.Domain)
		if err != nil {
			return hashes, err
		}
		if newEid != previousEid {
			previousEid = newEid
			// Only keep groups len>1 as they are mapped in SavedHashes.Hashes
			if len(ids) > 1 {
				hashes.IDs = append(hashes.IDs, ids)
			}
			ids = make([]ID, 0)
		}
		ids = append(ids, id)
	}
	return hashes, nil
}

func (s *sqliteStorage) AssociateIDs(newIDs []NewIDs) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	insertID := tx.Stmt(s.insertID)
	insertIEID := tx.Stmt(s.insertIEID)
	for _, ids := range newIDs {
		var (
			newRowid int64
			oldRowid int64
			eid      int64
		)
		rows := tx.QueryRow(`SELECT ITEI.idid, ITEI.equivalentid from IDs JOIN IDsToEquivalantIDs AS ITEI ON IDs.id=ITEI.idid WHERE domain=? AND stringid=?`, ids.OldID.Domain, ids.OldID.ID)

		err := rows.Scan(&oldRowid, &eid)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrIDNotFound
			}
			return err
		}

		rows = insertID.QueryRow(ids.NewID.Domain, ids.NewID.ID)

		err = rows.Scan(&newRowid)
		if err != nil {
			return err
		}
		_, err = insertIEID.Exec(newRowid, eid)
		if err != nil {
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		panic(err)
	}
	return nil
}

func (s *sqliteStorage) GetIDs(id ID) IDList {
	var ids []ID
	rows, err := s.idMatchStatement.Query(id.Domain, id.ID)
	if err != nil {
		return nil
	}
	for rows.Next() {
		var id ID
		err = rows.Scan(&id.Domain, &id.ID)
		if err != nil {
			return nil
		}
		ids = append(ids, id)
	}
	return ToIDList(ids)
}

func (s *sqliteStorage) PrepareStatements() error {
	var err error
	s.insertHash, err = s.db.Prepare(`INSERT INTO Hashes (kind, hash, id) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET kind=?1`)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	s.insertID, err = s.db.Prepare(`INSERT INTO IDs (domain, stringid) VALUES (?,?) ON CONFLICT DO UPDATE SET domain=?1 RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	s.insertEID, err = s.db.Prepare(`INSERT INTO EquivalentIDs DEFAULT VALUES RETURNING id;`)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	s.insertIEID, err = s.db.Prepare(`INSERT INTO IDsToEquivalantIDs (idid, equivalentid) VALUES (?, ?);`)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	s.idExists, err = s.db.Prepare(`SELECT COUNT(*) from IDsToEquivalantIDs WHERE idid=?`)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	s.hashExactMatchStatement, err = s.db.Prepare(`
        select IDs.domain, IDs.stringid from IDs
        join IDsToEquivalantIDs as IEIDs on IDs.id=IEIDs.idid
        join (
            select QEIDs.id as id from EquivalentIDs as QEIDs
            join IDsToEquivalantIDs as QIEIDs on QEIDs.id=QIEIDs.equivalentid
            join IDs as QIDs on QIDs.id=QIEIDs.idid
            join Hashes on Hashes.id=QIDs.id
            where (Hashes.kind=? AND Hashes.hash=?)
        ) as EIDs on EIDs.id=IEIDs.equivalentid;
    `)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	s.hashPartialMatchStatement, err = s.db.Prepare(`
        select EIDs.hash, IDs.domain, IDs.stringid from IDs
        join IDsToEquivalantIDs as IEIDs on IDs.id=IEIDs.idid
        join (
            select Hashes.hash as hash, QEIDs.id as id from EquivalentIDs as QEIDs
            join IDsToEquivalantIDs as QIEIDs on QEIDs.id=QIEIDs.equivalentid
            join IDs as QIDs on QIDs.id=QIEIDs.idid
            join Hashes on Hashes.id=QIDs.id
            where (Hashes.kind=? AND (((Hashes.hash >> (0 * 8) & 0xFF)=(?2 >> (0 * 8) & 0xFF)) OR ((Hashes.hash >> (1 * 8) & 0xFF)=(?2 >> (1 * 8) & 0xFF)) OR ((Hashes.hash >> (2 * 8) & 0xFF)=(?2 >> (2 * 8) & 0xFF)) OR ((Hashes.hash >> (3 * 8) & 0xFF)=(?2 >> (3 * 8) & 0xFF)) OR ((Hashes.hash >> (4 * 8) & 0xFF)=(?2 >> (4 * 8) & 0xFF)) OR ((Hashes.hash >> (5 * 8) & 0xFF)=(?2 >> (5 * 8) & 0xFF)) OR ((Hashes.hash >> (6 * 8) & 0xFF)=(?2 >> (6 * 8) & 0xFF)) OR ((Hashes.hash >> (7 * 8) & 0xFF)=(?2 >> (7 * 8) & 0xFF))))
        ) as EIDs on EIDs.id=IEIDs.equivalentid;
    `)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	s.idMatchStatement, err = s.db.Prepare(`
        select IDs.domain, IDs.stringid from IDs
        join IDsToEquivalantIDs as IEIDs on IDs.id=IEIDs.idid
        join (
            select EIDs.* from EquivalentIDs as EIDs
            join IDsToEquivalantIDs as QIEIDs on EIDs.id=QIEIDs.equivalentid
            join IDs as QIDs on QIDs.id=QIEIDs.idid
            where (QIDs.domain=? AND QIDs.stringid=?)
        ) as EIDs on EIDs.id=IEIDs.equivalentid;
    `)
	if err != nil {
		return fmt.Errorf("failed to prepare database statements: %w", err)
	}
	return nil
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
        CREATE TABLE IF NOT EXISTS IDs(
            id INTEGER PRIMARY KEY,
            stringid TEXT NOT NULL,
            domain TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS Hashes(
            hash INTEGER NOT NULL,
            kind INTEGER NOT NULL,
            id INTEGER NOT NULL,

            FOREIGN KEY(id) REFERENCES IDs(id)
        );

        CREATE TABLE IF NOT EXISTS EquivalentIDs(
            id integer primary key
        );

        CREATE TABLE IF NOT EXISTS IDsToEquivalantIDs(
            idid INTEGER NOT NULL,
            equivalentid INTEGER NOT NULL,
            PRIMARY KEY (idid, equivalentid),

            FOREIGN KEY(idid) REFERENCES IDs(id),
            FOREIGN KEY(equivalentid) REFERENCES EquivalentIDs(id)
        );
    `)
	if err != nil {
		panic(err)
	}
	sqlite.createIndexes()
	sqlite.db.SetMaxOpenConns(1)
	err = sqlite.PrepareStatements()
	if err != nil {
		return nil, err
	}
	return sqlite, nil
}
