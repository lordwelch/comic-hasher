package storage

import (
	"cmp"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"slices"
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
	aHashes []RuntimeHash
	dHashes []RuntimeHash
	pHashes []RuntimeHash
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

// atleast must have a read lock before using
func (b *basicMapStorage) atleast(kind goimagehash.Kind, maxDistance int, searchHash uint64) []ch.Result {
	otherHashes := make([]ch.Result, 0, 20) // hope that we don't need more

	storedHash := RuntimeHash{}
	for _, storedHash = range *b.getCurrentHashes(kind) {
		distance := bits.OnesCount64(searchHash ^ storedHash.Hash)
		if distance <= maxDistance {
			otherHashes = append(otherHashes, ch.Result{
				Hash: ch.Hash{
					Hash: storedHash.Hash,
					Kind: kind,
				},
				ID: *storedHash.ID,
				Distance: distance,
				EquivalentIDs: nil})
		}
	}

	matchingHashes := make([]ch.Result, 0, len(otherHashes)) // For some reason copying to this slice is faster than not........
	for i := range otherHashes {
		otherHashes[i].EquivalentIDs = b.ids.GetIDs(&otherHashes[i].ID)
		matchingHashes = append(matchingHashes, ch.Result{
			Hash:          otherHashes[i].Hash,
			ID:            otherHashes[i].ID,
			Distance:      otherHashes[i].Distance,
			EquivalentIDs: otherHashes[i].EquivalentIDs,
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
		var storedHash RuntimeHash
		for _, storedHash = range (*b.getCurrentHashes(hash.Kind))[index : index+count] {
			index, _ := b.ids.FindID(storedHash.ID)
			if mappedIds[index] {
				continue
			}
			mappedIds[index] = true

			foundMatches = append(foundMatches, ch.Result{
				Hash:     ch.Hash{Hash:storedHash.Hash, Kind: hash.Kind},
				ID:       *storedHash.ID,
				Distance: 0,
			})
		}
		for i := range foundMatches {
			foundMatches[i].EquivalentIDs = b.ids.GetIDs(storedHash.ID)
		}

	}
	return foundMatches
}

func (b *basicMapStorage) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		foundMatches []ch.Result
		tl           ch.TimeLog
	)
	tl.ResetTime()
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

	totalPartialHashes := 0

	for _, hash := range hashes {
		totalPartialHashes += len(*b.getCurrentHashes(hash.Kind))
		foundMatches = append(foundMatches, b.atleast(hash.Kind, max, hash.Hash)...)
	}
	return foundMatches, nil
}

// getCurrentHashes must have a read lock before using
func (b *basicMapStorage) getCurrentHashes(kind goimagehash.Kind) *[]RuntimeHash {
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
	currentHashes := *b.getCurrentHashes(hash.Kind)
	index, found := slices.BinarySearchFunc(currentHashes, hash, func(existing RuntimeHash, target ch.Hash) int {
		return cmp.Compare(existing.Hash, target.Hash)
	})
	if !found {
		return index, 0
	}
	count := 1 // Skip the index we already found because we know it's equal
	for i := index + 1; i < len(currentHashes) && currentHashes[i].Hash == hash.Hash; i++ {
		count++
	}
	return index, count
}

// insertHash must already have a lock
func (b *basicMapStorage) insertHash(hash ch.Hash, id ch.ID) bool {
	currentHashes := b.getCurrentHashes(hash.Kind)
	start, count := b.findHash(hash)
	max := start + count
	index := start
	for ; index < max; index++ {
		if (*currentHashes)[index].ID.Compare(id) == 0 {
			return true
		}
	}

	rh := RuntimeHash{
		Hash: hash.Hash,
		ID:   b.ids.InsertID(id),
	}
	*currentHashes = slices.Insert(*currentHashes, index, rh)

	slices.SortFunc((*currentHashes)[start:max+1], hashCmp)
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

	slices.SortFunc(hashes.Hashes, func(existing, target ch.SavedHash) int {
		return cmp.Or(
			cmp.Compare(*existing.ID.Domain, *target.ID.Domain), // Sorted for id insertion efficiency
			cmp.Compare(existing.ID.ID, target.ID.ID),           // Sorted for id insertion efficiency
			cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash), // This should never realisticaly happen
		)
	})
	aHashCount := 0
	dHashCount := 0
	pHashCount := 0
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

	b.aHashes = make([]RuntimeHash, 0, aHashCount)
	b.dHashes = make([]RuntimeHash, 0, dHashCount)
	b.pHashes = make([]RuntimeHash, 0, pHashCount)
	var hash ch.SavedHash
	for _, hash = range hashes.Hashes {
		// TODO: Investigate better options to load in the ID
		if hash.Hash.Kind == goimagehash.AHash {
			b.aHashes = append(b.aHashes, RuntimeHash{
				Hash: hash.Hash.Hash,
				ID:   b.ids.InsertID(hash.ID),
			})
		} else if hash.Hash.Kind == goimagehash.DHash {
			b.dHashes = append(b.dHashes, RuntimeHash{
				Hash: hash.Hash.Hash,
				ID:   b.ids.InsertID(hash.ID),
			})
		} else if hash.Hash.Kind == goimagehash.PHash {
			b.pHashes = append(b.pHashes, RuntimeHash{
				Hash: hash.Hash.Hash,
				ID:   b.ids.InsertID(hash.ID),
			})
		}

		if hash.ID == (ch.ID{}) {
			log.Panic("Empty ID detected", hash)
		}
	}

	hashCompact := func(existing, target RuntimeHash) bool {
		return hashCmp(existing, target) == 0
	}
	// sort for lookup
	slices.SortFunc(b.aHashes, hashCmp)
	slices.SortFunc(b.dHashes, hashCmp)
	slices.SortFunc(b.pHashes, hashCmp)
	// remove duplicates
	b.aHashes = slices.CompactFunc(b.aHashes, hashCompact)
	b.dHashes = slices.CompactFunc(b.dHashes, hashCompact)
	b.pHashes = slices.CompactFunc(b.pHashes, hashCompact)
	b.ids.sort()

	count := ch.Metrics{
		Hashes: make(map[ch.Metric]int, 6),
	}
	var rhash RuntimeHash
	for _, rhash = range b.aHashes {
		count.Hashes[ch.Metric{Source: rhash.ID.Domain, Kind: goimagehash.AHash}] += 1
	}
	for _, rhash = range b.dHashes {
		count.Hashes[ch.Metric{Source: rhash.ID.Domain, Kind: goimagehash.DHash}] += 1
	}
	for _, rhash = range b.pHashes {
		count.Hashes[ch.Metric{Source: rhash.ID.Domain, Kind: goimagehash.PHash}] += 1
	}

	return count, nil
}

func hashCmp(existing, target RuntimeHash) int {
	return cmp.Or(
		cmp.Compare(existing.Hash, target.Hash),
		cmp.Compare(*existing.ID.Domain, *target.ID.Domain),
		cmp.Compare(existing.ID.ID, target.ID.ID),
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

}
// EncodeHashes should already have a lock
func (b *basicMapStorage) EncodeHashes() (*ch.SavedHashes, error) {
	savedHashes := ch.SavedHashes{
		Hashes: make([]ch.SavedHash, 0, len(b.aHashes)+len(b.dHashes)+len(b.pHashes)),
	}
	appendHashes(goimagehash.AHash, b.aHashes,&savedHashes)
	appendHashes(goimagehash.DHash, b.dHashes,&savedHashes)
	appendHashes(goimagehash.PHash, b.pHashes,&savedHashes)

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
		aHashes: []RuntimeHash{},
		dHashes: []RuntimeHash{},
		pHashes: []RuntimeHash{},
	}
	return storage, nil
}
