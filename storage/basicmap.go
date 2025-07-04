package storage

import (
	"cmp"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"sync"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type basicMapStorage struct {
	hashMutex *sync.RWMutex

	ids     IDMap
	aHashes []ch.SavedHash
	dHashes []ch.SavedHash
	pHashes []ch.SavedHash
}
type IDs struct {
	id     *ch.ID
	idList *[]*ch.ID
}
type IDMap struct {
	ids []IDs
}

func (m *IDMap) InsertID(id *ch.ID) *ch.ID {
	return m.insertID(id, &[]*ch.ID{id})
}

func (m *IDMap) insertID(id *ch.ID, idList *[]*ch.ID) *ch.ID {
	index, found := slices.BinarySearchFunc(m.ids, id, func(id IDs, target *ch.ID) int {
		return id.id.Compare(*target)
	})
	if !found {
		m.ids = slices.Insert(m.ids, index, IDs{
			id,
			idList,
		})
	}
	return m.ids[index].id
}

func (m *IDMap) sort() {
	slices.SortFunc(m.ids, func(a, b IDs) int {
		return a.id.Compare(*b.id)
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
		*(m.ids[index].idList) = ch.InsertIDp(*(m.ids[index].idList), &newid.NewID)
		m.insertID(&newid.NewID, m.ids[index].idList)
	}
	return nil
}

// func (m *IDMap) NewID(domain Source, id string) *ch.ID {
// 	newID := ch.ID{domain, id}
// 	index, found := slices.BinarySearchFunc(m.idList, newID, func(id *ch.ID, target ch.ID) int {
// 		return id.Compare(*target)
// 	})
// 	if !found {
// 		m.idList = slices.Insert(m.idList, index, &newID)
// 	}
// 	return m.idList[index]
// }

var ErrIDNotFound = errors.New("ID not found on this server")

// atleast must have a read lock before using
func (b *basicMapStorage) atleast(kind goimagehash.Kind, maxDistance int, searchHash uint64) []ch.Result {
	matchingHashes := make([]ch.Result, 0, 20) // hope that we don't need more

	mappedIds := map[int]bool{}
	storedHash := ch.SavedHash{} // reduces allocations and ensures queries are <1s
	for _, storedHash = range *b.getCurrentHashes(kind) {
		distance := bits.OnesCount64(searchHash ^ storedHash.Hash.Hash)
		if distance <= maxDistance {
			index, _ := b.ids.FindID(&storedHash.ID)
			if mappedIds[index] {
				continue
			}
			mappedIds[index] = true
			matchingHashes = append(matchingHashes, ch.Result{
				Hash:          storedHash.Hash,
				ID:            storedHash.ID,
				Distance:      distance,
				EquivalentIDs: b.ids.GetIDs(&storedHash.ID),
			})
		}
	}
	return matchingHashes
}

func (b *basicMapStorage) exactMatches(hashes []ch.Hash, max int) []ch.Result {
	var foundMatches []ch.Result
	for _, hash := range hashes {
		mappedIds := map[int]bool{}

		index, count := b.findHash(hash)
		if count > 0 {
			for _, storedHash := range (*b.getCurrentHashes(hash.Kind))[index : index+count] {
				index, _ := b.ids.FindID(&storedHash.ID)
				if mappedIds[index] {
					continue
				}
				mappedIds[index] = true

				foundMatches = append(foundMatches, ch.Result{
					Hash:          storedHash.Hash,
					ID:            storedHash.ID,
					Distance:      0,
					EquivalentIDs: b.ids.GetIDs(&storedHash.ID),
				})
			}
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
		foundMatches = b.exactMatches(hashes, max)

		tl.LogTime("Search Exact")
		if len(foundMatches) > 0 {
			return foundMatches, nil
		}
	}

	foundHashes := make(map[uint64]struct{})
	totalPartialHashes := 0

	for _, hash := range hashes {
		foundMatches = append(foundMatches, b.atleast(hash.Kind, max, hash.Hash)...)

	}
	fmt.Println("Total partial hashes tested:", totalPartialHashes, len(foundHashes))
	return foundMatches, nil
}

// getCurrentHashes must have a read lock before using
func (b *basicMapStorage) getCurrentHashes(kind goimagehash.Kind) *[]ch.SavedHash {
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

// findHash must have a read lock before using
// return value is index, count
// if count < 1 then no results were found
func (b *basicMapStorage) findHash(hash ch.Hash) (int, int) {
	currentHashes := *b.getCurrentHashes(hash.Kind)
	index, found := slices.BinarySearchFunc(currentHashes, hash, func(existing ch.SavedHash, target ch.Hash) int {
		return cmp.Compare(existing.Hash.Hash, target.Hash)
	})
	if !found {
		return index, 0
	}
	count := 0
	for i := index + 1; i < len(currentHashes) && currentHashes[i].Hash.Hash == hash.Hash; i++ {
		count++
	}
	return index, count
}

// insertHash must already have a lock
func (b *basicMapStorage) insertHash(hash ch.Hash, id ch.ID) {
	currentHashes := b.getCurrentHashes(hash.Kind)
	index, count := b.findHash(hash)
	max := index + count
	for ; index < max; index++ {
		if (*currentHashes)[index].ID == id {
			return
		}
	}

	sh := ch.SavedHash{
		Hash: hash,
		ID:   id,
	}
	*currentHashes = slices.Insert(*currentHashes, index, sh)
	b.ids.InsertID(&sh.ID)
}

func (b *basicMapStorage) MapHashes(hash ch.ImageHash) {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()
	for _, ih := range hash.Hashes {
		b.insertHash(ih, hash.ID)
	}
}

// DecodeHashes must already have a lock
func (b *basicMapStorage) DecodeHashes(hashes *ch.SavedHashes) error {
	if hashes == nil {
		return nil
	}
	b.ids.ids = make([]IDs, 0, len(hashes.Hashes))

	// Initialize all the known equal IDs
	for _, ids := range hashes.IDs {
		new_ids := make([]*ch.ID, 0, len(ids))
		for _, id := range ids {
			new_ids = append(new_ids, &id)
		}
		for _, id := range new_ids {
			b.ids.ids = append(b.ids.ids, IDs{
				id,
				&new_ids,
			})
		}
	}
	b.ids.sort()

	slices.SortFunc(hashes.Hashes, func(existing, target ch.SavedHash) int {
		return cmp.Or(
			cmp.Compare(*existing.ID.Domain, *target.ID.Domain), // Sorted for id insertion efficiency
			cmp.Compare(existing.ID.ID, target.ID.ID),           // Sorted for id insertion efficiency
			cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
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

	// Assume they are probably fairly equally split between hash types
	b.aHashes = make([]ch.SavedHash, 0, aHashCount)
	b.dHashes = make([]ch.SavedHash, 0, dHashCount)
	b.pHashes = make([]ch.SavedHash, 0, pHashCount)
	for i := range hashes.Hashes {
		hash := hashes.Hashes[i].Clone() // Not cloning this will keep strings/slices loaded from json wasting memory
		if hashes.Hashes[i].Hash.Kind == goimagehash.AHash {
			b.aHashes = append(b.aHashes, hash)
		}
		if hashes.Hashes[i].Hash.Kind == goimagehash.DHash {
			b.dHashes = append(b.dHashes, hash)
		}
		if hashes.Hashes[i].Hash.Kind == goimagehash.PHash {
			b.pHashes = append(b.pHashes, hash)
		}

		if hashes.Hashes[i].ID == (ch.ID{}) {
			fmt.Println("Empty ID detected")
			panic(hashes.Hashes[i])
		}
		// TODO: Make loading this more efficient
		// All known equal IDs are already mapped we can add any missing ones from hashes
		b.ids.InsertID(&hash.ID)
	}

	hashCmp := func(existing, target ch.SavedHash) int {
		return cmp.Or(
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
			cmp.Compare(*existing.ID.Domain, *target.ID.Domain),
			cmp.Compare(existing.ID.ID, target.ID.ID),
		)
	}
	slices.SortFunc(b.aHashes, hashCmp)
	slices.SortFunc(b.dHashes, hashCmp)
	slices.SortFunc(b.pHashes, hashCmp)

	return nil
}

// EncodeHashes should already have a lock
func (b *basicMapStorage) EncodeHashes() (*ch.SavedHashes, error) {
	savedHashes := ch.SavedHashes{
		Hashes: make([]ch.SavedHash, 0, len(b.aHashes)+len(b.dHashes)+len(b.pHashes)),
	}
	// savedHashes.Hashes = append(savedHashes.Hashes, b.aHashes...)
	// savedHashes.Hashes = append(savedHashes.Hashes, b.dHashes...)
	// savedHashes.Hashes = append(savedHashes.Hashes, b.pHashes...)

	// // Only keep groups len>1 as they are mapped in SavedHashes.Hashes
	// for _, ids := range b.ids.ids {
	// 	if len(*ids.idList) > 1 {
	// 		idl := make([]ID, 0, len(*ids.idList))
	// 		for _, id := range *ids.idList {
	// 			idl = append(idl, *id)
	// 		}

	// 		savedHashes.IDs = append(savedHashes.IDs, idl)
	// 	}
	// }

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
		aHashes: []ch.SavedHash{},
		dHashes: []ch.SavedHash{},
		pHashes: []ch.SavedHash{},
	}
	return storage, nil
}
