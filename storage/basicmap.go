package storage

import (
	"cmp"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"simd"
	"simd/archsimd"
	"slices"
	"sort"
	"sync"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type RuntimeHash struct {
	Hash uint64
	ID   *ch.ID
}
type basicMapStorage struct {
	hashMutex *sync.RWMutex

	ids     IDMap
	aHashes Table
	dHashes Table
	pHashes Table
}

type Table struct {
	IDs    []ch.ID
	Hashes []uint64
}

func (t *Table) Len() int {
	if len(t.IDs) != len(t.Hashes) {
		panic(fmt.Sprintf("Hashes and Indexes got out of sync: hashes: %d, indexes: %d", len(t.IDs), len(t.Hashes)))
	}
	return len(t.IDs)
}

func (t *Table) Less(i, j int) bool {
	return cmp.Or(
		cmp.Compare(t.Hashes[i], t.Hashes[j]),
		t.IDs[i].Compare(t.IDs[j]),
	) < 0
}

func (t *Table) Swap(i, j int) {
	t.IDs[j], t.IDs[i] = t.IDs[i], t.IDs[j]
	t.Hashes[j], t.Hashes[i] = t.Hashes[i], t.Hashes[j]
}

type IDs struct {
	id     ch.ID
	idList *[]*ch.ID
}
type IDMap struct {
	ids []IDs
}

func (m *IDMap) InsertID(id ch.ID) *ch.ID {
	index, found := m.FindID(&id)
	if !found {
		m.ids = slices.Insert(m.ids, index, IDs{
			id,
			&[]*ch.ID{},
		})
	}
	return &m.ids[index].id
}

func (m *IDMap) insertID(id ch.ID, idList *[]*ch.ID) *ch.ID {
	index, found := m.FindID(&id)
	if !found {
		m.ids = slices.Insert(m.ids, index, IDs{
			id,
			idList,
		})
	}
	return &m.ids[index].id
}

func (m *IDMap) sort() {
	slices.SortFunc(m.ids, func(a, b IDs) int {
		return a.id.Compare(b.id)
	})
}

func (m *IDMap) FindID(id *ch.ID) (int, bool) {
	return slices.BinarySearchFunc(m.ids, id, func(id IDs, target *ch.ID) int {
		return id.id.Compare(*target)
	})
}

func (m *IDMap) GetIDs(id *ch.ID) []ch.ID {
	index, found := m.FindID(id)

	if !found {
		return nil
	}
	ids := make([]ch.ID, 0, len(*m.ids[index].idList))
	ids = append(ids, m.ids[index].id)
	for _, id := range *m.ids[index].idList {
		ids = append(ids, *id)
	}
	return ids
}

func (m *IDMap) GetIDsAt(index int) []ch.ID {
	ids := make([]ch.ID, 0, len(*m.ids[index].idList))
	for _, id := range *m.ids[index].idList {
		ids = append(ids, *id)
	}
	return ids
}

func (m *IDMap) AssociateIDs(newids []ch.NewIDs) error {
	for _, newid := range newids {
		index, found := m.FindID(&newid.OldID)
		if !found {
			return ErrIDNotFound
		}
		*m.ids[index].idList = ch.InsertIDp(*m.ids[index].idList, &newid.NewID)
		m.insertID(newid.NewID, m.ids[index].idList)
	}
	return nil
}

var ErrIDNotFound = errors.New("ID not found on this server")

func (b *basicMapStorage) RLock() {
	b.hashMutex.RLock()
}

func (b *basicMapStorage) RUnlock() {
	b.hashMutex.RUnlock()
}

var distShared []byte

const chunkSize = 64

var work = make([]bool, chunkSize)

// atleast must have a read lock before using
func (b *basicMapStorage) atleast(kind goimagehash.Kind, maxDistance int, searchHash uint64) []ch.Result {
	currentTable := b.getCurrentTable(kind)
	foundHashes := make([]struct{i , d int;h uint64}, 0, 30)
	i := 0
	var values archsimd.Uint64x2
	r := make([]uint64, simd.VectorBitSize()/64)
	hashLen := currentTable.Len()
	if len(distShared) < hashLen {
		// this reuse is only for testing this would cause issues if two requests happened at the same time
		distShared = make([]byte, hashLen)
	}
	dist := distShared[:hashLen]

	distance := 9
	searchSimd := archsimd.BroadcastUint64x2(searchHash)
	vectorSize := simd.VectorBitSize() / 64
	if vectorSize >= 8 {
		var zz int
		for ; i+vectorSize < hashLen; i += vectorSize {
			values = archsimd.LoadUint64x2(currentTable.Hashes[i : i+vectorSize])
			values.Xor(searchSimd).Store(r)
			for zz = range r {
				dist[i+zz] = byte(bits.OnesCount64(r[zz])) // Max Ones Count is 64
			}
		}
	}
	// x := 0
	// for ; i+chunkSize < hashLen; i += chunkSize {
	// 	for x = range chunkSize { // currentTable.Hashes[i:i+chunkSize] {
	// 		// Max Ones Count is 64
	// 		distance = bits.OnesCount64(searchHash^currentTable.Hashes[i+x])
	// 		if distance <= maxDistance {
	// 			foundHashes = append(foundHashes, struct{i , d int;h uint64}{i:i+x, d:distance, h: currentTable.Hashes[i+x]})
	// 		}
	// 	}
	// }
	for ; i < hashLen; i++ {
		distance = bits.OnesCount64(searchHash ^ currentTable.Hashes[i])
		if distance <= maxDistance {
			foundHashes = append(foundHashes, struct{i , d int;h uint64}{i:i, d:distance, h: currentTable.Hashes[i]})
		}
	}

	matchingHashes := make([]ch.Result, 0, len(foundHashes))
	var f struct{i , d int;h uint64}
	for _, f = range foundHashes {
		matchingHashes = append(matchingHashes, ch.Result{
			Hash:          ch.Hash{Hash: f.h, Kind: kind},
			ID:            currentTable.IDs[f.i],
			Distance:      f.d,
			EquivalentIDs: b.ids.GetIDs(&currentTable.IDs[f.i]),
		})
	}

	return matchingHashes
}

func (b *basicMapStorage) exactMatches(hashes []ch.Hash) []ch.Result {
	var foundMatches []ch.Result
	for _, hash := range hashes {
		mappedIds := map[int]bool{}

		index, count := b.findHash(hash)
		if count < 1 {
			continue
		}
		var (
			storedHash   uint64
			storedID     ch.ID
			i            int
			currentTable = b.getCurrentTable(hash.Kind)
		)
		for i, storedHash = range currentTable.Hashes[index : index+count] {
			storedID = currentTable.IDs[index+i]
			index, _ := b.ids.FindID(&storedID)
			if mappedIds[index] {
				continue
			}
			mappedIds[index] = true

			foundMatches = append(foundMatches, ch.Result{
				Hash:          ch.Hash{Hash: storedHash, Kind: hash.Kind},
				ID:            storedID,
				Distance:      0,
				EquivalentIDs: b.ids.GetIDsAt(index),
			})
		}
	}
	return foundMatches
}

var tl *ch.TimeLog = ch.NewTimeLog()

func (b *basicMapStorage) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		foundMatches []ch.Result
	)
	tl.ResetTime()
	defer tl.ResetTime()
	defer tl.LogTime(fmt.Sprintf("Search Complete: max: %v ExactOnly: %v", max, exactOnly))
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		foundMatches = b.exactMatches(hashes)

		tl.LogTime("Search Exact")
		if len(foundMatches) > 0 {
			return foundMatches, nil
		}
	}
	if max == 0 {
		return foundMatches, nil
	}

	totalPartialHashes := 0

	for _, hash := range hashes {
		totalPartialHashes += b.getCurrentTable(hash.Kind).Len()
		foundMatches = append(foundMatches, b.atleast(hash.Kind, max, hash.Hash)...)
	}
	return foundMatches, nil
}

// getCurrentHashes must have a read lock before using
func (b *basicMapStorage) getCurrentTable(kind goimagehash.Kind) *Table {
	if kind == goimagehash.AHash {
		return &b.aHashes
	}
	if kind == goimagehash.DHash {
		return &b.dHashes
	}
	if kind == goimagehash.PHash {
		return &b.pHashes
	}
	panic("Unknown hash type: " + kind.String())
}

// findHash looks for exact matches
// must have a read lock before using
// return value is index, count
// if count < 1 then no results were found
func (b *basicMapStorage) findHash(hash ch.Hash) (int, int) {
	currentTable := *b.getCurrentTable(hash.Kind)
	index, found := slices.BinarySearchFunc(currentTable.Hashes, hash, func(existing uint64, target ch.Hash) int {
		return cmp.Compare(existing, target.Hash)
	})
	if !found {
		return index, 0
	}
	count := 1 // Skip the index we already found because we know it's equal
	for i := index + 1; i < len(currentTable.Hashes) && currentTable.Hashes[i] == hash.Hash; i++ {
		count++
	}
	return index, count
}

// insertHash must already have a lock
func (b *basicMapStorage) insertHash(hash ch.Hash, id ch.ID) bool {
	currentTable := b.getCurrentTable(hash.Kind)
	start, count := b.findHash(hash)
	max := start + count
	index := start
	for ; index < max; index++ {
		if currentTable.IDs[index] == id {
			return true
		}
	}

	rh := RuntimeHash{
		Hash: hash.Hash,
		ID:   b.ids.InsertID(id),
	}
	currentTable.Hashes = slices.Insert(currentTable.Hashes, index, sh.Hash.Hash)
	currentTable.IDs = slices.Insert(currentTable.IDs, index, sh.ID)
	b.ids.InsertID(sh.ID)
	// This slice only contains items that have the same hash so they must be unique and can be sorted
	slices.SortFunc(currentTable.IDs[start:max+1], idCmp)
	return false
}

func (b *basicMapStorage) MapHashes(hash ch.ImageHash) ch.Metrics {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()

	count := ch.Metrics{
		Hashes: make(map[ch.Metric]int, 3),
	}
	for _, ih := range hash.Hashes {
		if b.insertHash(ih, hash.ID) {
			count.Hashes[ch.Metric{Source: hash.ID.Domain, Kind: ih.Kind}] += 1
		}
	}
	return count
}

// DecodeHashes must already have a lock
func (b *basicMapStorage) DecodeHashes(hashes *ch.SavedHashes) (ch.Metrics, error) {
	if hashes == nil {
		return ch.Metrics{}, nil
	}
	b.ids.ids = make([]IDs, 0, len(hashes.Hashes))

	// Initialize all the known equal IDs
	for _, ids := range hashes.IDs {
		newIDs := make([]*ch.ID, 0, len(ids))
		for _, id := range ids {
			newIDs = append(newIDs, &id)
		}
		for _, id := range newIDs {
			b.ids.ids = append(b.ids.ids, IDs{
				*id, // should this be a pointer?????
				// I would have duplicate ID pointers hanging around if there was anything to load in this loop
				&newIDs,
			})
		}
	}
	b.ids.sort()

	// Remove duplicates
	slices.SortFunc(hashes.Hashes, hashCmp)
	hashCompact := func(existing ch.SavedHash, target ch.SavedHash) bool {
		return hashCmp(existing, target) == 0
	}
	hashes.Hashes = slices.CompactFunc(hashes.Hashes, hashCompact)

	// Sort for ID insertion
	// There are definitely duplicate IDs and re-searching every ID isn't efficient
	slices.SortFunc(hashes.Hashes, func(existing, target ch.SavedHash) int { return existing.ID.Compare(target.ID) })

	// this is now sorted and compacted in the correct order we just need to separate out by hash type
	aHashCount := 0
	dHashCount := 0
	pHashCount := 0
	// Use space efficiently
	for _, savedHash := range hashes.Hashes {

		if savedHash.Hash.Kind == goimagehash.AHash {
			aHashCount += 1
		}
		if savedHash.Hash.Kind == goimagehash.DHash {
			dHashCount += 1
		}
		if savedHash.Hash.Kind == goimagehash.PHash {
			pHashCount += 1
		}
	}

	b.aHashes.IDs = make([]ch.ID, 0, aHashCount)
	b.aHashes.Hashes = make([]uint64, 0, aHashCount)
	b.dHashes.IDs = make([]ch.ID, 0, dHashCount)
	b.dHashes.Hashes = make([]uint64, 0, dHashCount)
	b.pHashes.IDs = make([]ch.ID, 0, pHashCount)
	b.pHashes.Hashes = make([]uint64, 0, pHashCount)
	var hash ch.SavedHash
	b.ids.ids = make([]IDs, 0, len(hashes.Hashes)/3)
	for _, hash = range hashes.Hashes {
		// TODO: Investigate better options to load in the ID
		if hash.Hash.Kind == goimagehash.AHash {
			b.aHashes.IDs = append(b.aHashes.IDs, hash.ID)
			b.aHashes.Hashes = append(b.aHashes.Hashes, hash.Hash.Hash)
		}
		if hash.Hash.Kind == goimagehash.DHash {
			b.dHashes.IDs = append(b.dHashes.IDs, hash.ID)
			b.dHashes.Hashes = append(b.dHashes.Hashes, hash.Hash.Hash)
		}
		if hash.Hash.Kind == goimagehash.PHash {
			b.pHashes.IDs = append(b.pHashes.IDs, hash.ID)
			b.pHashes.Hashes = append(b.pHashes.Hashes, hash.Hash.Hash)
		}

		if hash.ID == (ch.ID{}) {
			log.Panic("Empty ID detected", hash)
		}
		if len(b.ids.ids) > 0 && b.ids.ids[len(b.ids.ids)-1].id.Compare(hash.ID) == 0 {
			continue
		}
		// This still does a binary search but should always be a negative match
		// Probably won't waste too much time as it should always be equal to an append and we should already have the space available
		b.ids.InsertID(hash.ID)
	}

	// Should already be sorted but shouldn't hurt
	b.ids.sort()

	// Hashes are currently in the wrong order they must be sorted
	sort.Sort(&b.aHashes)
	sort.Sort(&b.dHashes)
	sort.Sort(&b.pHashes)

	var count = ch.Metrics{
		Hashes: make(map[ch.Metric]int, 6),
	}

	var id ch.ID
	for _, id = range b.aHashes.IDs {
		count.Hashes[ch.Metric{Source: id.Domain, Kind: goimagehash.AHash}] += 1
	}
	for _, id = range b.dHashes.IDs {
		count.Hashes[ch.Metric{Source: id.Domain, Kind: goimagehash.DHash}] += 1
	}
	for _, id = range b.pHashes.IDs {
		count.Hashes[ch.Metric{Source: id.Domain, Kind: goimagehash.PHash}] += 1
	}

	return count, nil
}

func hashCmp(existing, target RuntimeHash) int {
	return cmp.Or(
		cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
		cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
		existing.ID.Compare(target.ID),
	)
}
func appendHashes(kind goimagehash.Kind,rhashes []RuntimeHash, savedHashes *ch.SavedHashes) {
	var rhash RuntimeHash
	for _, rhash = range rhashes {
		savedHashes.Hashes = append(savedHashes.Hashes, ch.SavedHash{
			Hash: ch.Hash{
				Hash: rhash.Hash,
				Kind: kind,
			},
			ID: *rhash.ID,
		})
	}

func idCmp(existing, target ch.ID) int {
	return existing.Compare(target)
}

// EncodeHashes should already have a lock
func (b *basicMapStorage) EncodeHashes() (*ch.SavedHashes, error) {
	savedHashes := ch.SavedHashes{
		Hashes: make([]ch.SavedHash, 0, b.aHashes.Len()+b.dHashes.Len()+b.pHashes.Len()),
	}
	for i := 0; i < b.aHashes.Len(); i++ {
		savedHashes.Hashes = append(savedHashes.Hashes, ch.SavedHash{
			Hash: ch.Hash{
				Hash: b.aHashes.Hashes[i],
				Kind: goimagehash.AHash,
			},
			ID: b.aHashes.IDs[i],
		})
	}
	for i := 0; i < b.dHashes.Len(); i++ {
		savedHashes.Hashes = append(savedHashes.Hashes, ch.SavedHash{
			Hash: ch.Hash{
				Hash: b.dHashes.Hashes[i],
				Kind: goimagehash.DHash,
			},
			ID: b.dHashes.IDs[i],
		})
	}
	for i := 0; i < b.pHashes.Len(); i++ {
		savedHashes.Hashes = append(savedHashes.Hashes, ch.SavedHash{
			Hash: ch.Hash{
				Hash: b.pHashes.Hashes[i],
				Kind: goimagehash.PHash,
			},
			ID: b.pHashes.IDs[i],
		})
	}

	// Only keep groups len>1 as they are mapped in SavedHashes.Hashes
	for _, ids := range b.ids.ids {
		if len(*ids.idList) > 1 {
			idl := make([]ch.ID, 0, len(*ids.idList))
			for _, id := range *ids.idList {
				idl = append(idl, *id)
			}

			savedHashes.IDs = append(savedHashes.IDs, idl)
		}
	}

	return &savedHashes, nil
}

func (b *basicMapStorage) AssociateIDs(newids []ch.NewIDs) error {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	return b.ids.AssociateIDs(newids)
}

func (b *basicMapStorage) GetIDs(id ch.ID) ch.IDList {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	ids := b.ids.GetIDs(&id)
	return ch.ToIDList(ids)
}

func NewBasicMapStorage() (ch.HashStorage, error) {
	storage := &basicMapStorage{
		hashMutex: &sync.RWMutex{},
		ids: IDMap{
			ids: []IDs{},
		},
		aHashes: Table{
			IDs:    []ch.ID{},
			Hashes: []uint64{},
		},
		dHashes: Table{
			IDs:    []ch.ID{},
			Hashes: []uint64{},
		},
		pHashes: Table{
			IDs:    []ch.ID{},
			Hashes: []uint64{},
		},
	}
	return storage, nil
}
