package ch

import (
	"cmp"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"sync"

	"gitea.narnian.us/lordwelch/goimagehash"
)

type basicMapStorage struct {
	hashMutex *sync.RWMutex

	ids     map[ID]*[]ID
	aHashes []SavedHash
	dHashes []SavedHash
	pHashes []SavedHash
}

var ErrIDNotFound = errors.New("ID not found on this server")

// atleast must have a read lock before using
func (b *basicMapStorage) atleast(kind goimagehash.Kind, maxDistance int, searchHash uint64) []Result {
	matchingHashes := make([]Result, 0, 20) // hope that we don't need more

	mappedIds := map[*[]ID]bool{}
	for _, storedHash := range *b.getCurrentHashes(kind) {
		distance := bits.OnesCount64(searchHash ^ storedHash.Hash.Hash)
		if distance <= maxDistance {
			ids := b.ids[storedHash.ID]
			if mappedIds[ids] {
				continue
			}
			mappedIds[ids] = true
			matchingHashes = append(matchingHashes, Result{ToIDList(*b.ids[storedHash.ID]), distance, storedHash.Hash})
		}
	}
	return matchingHashes
}

func (b *basicMapStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var (
		foundMatches []Result
		tl           timeLog
	)
	tl.resetTime()
	defer tl.logTime(fmt.Sprintf("Search Complete: max: %v ExactOnly: %v", max, exactOnly))
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		for _, hash := range hashes {
			mappedIds := map[*[]ID]bool{}

			index, count := b.findHash(hash)
			if count > 0 {
				for _, storedHash := range (*b.getCurrentHashes(hash.Kind))[index : index+count] {
					ids := b.ids[storedHash.ID]
					if mappedIds[ids] {
						continue
					}
					mappedIds[ids] = true

					foundMatches = append(foundMatches, Result{
						Distance: 0,
						Hash:     storedHash.Hash,
						IDs:      ToIDList(*b.ids[storedHash.ID]),
					})
				}
			}

		}

		tl.logTime("Search Exact")

		return foundMatches, nil
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
func (b *basicMapStorage) getCurrentHashes(kind goimagehash.Kind) *[]SavedHash {
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
func (b *basicMapStorage) findHash(hash Hash) (int, int) {
	currentHashes := *b.getCurrentHashes(hash.Kind)
	index, found := slices.BinarySearchFunc(currentHashes, hash, func(existing SavedHash, target Hash) int {
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
func (b *basicMapStorage) insertHash(hash Hash, id ID) {
	currentHashes := b.getCurrentHashes(hash.Kind)
	index, count := b.findHash(hash)
	max := index + count
	for ; index < max; index++ {
		if (*currentHashes)[index].ID == id {
			return
		}
	}

	*currentHashes = slices.Insert(*currentHashes, index, SavedHash{hash, id})
	if _, mapped := b.ids[id]; !mapped {
		b.ids[id] = &[]ID{id}
	}
}

func (b *basicMapStorage) MapHashes(hash ImageHash) {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()
	for _, ih := range hash.Hashes {
		b.insertHash(ih, hash.ID)
	}
}

// DecodeHashes must already have a lock
func (b *basicMapStorage) DecodeHashes(hashes SavedHashes) error {
	b.ids = make(map[ID]*[]ID, len(hashes.Hashes))

	// Initialize all the known equal IDs
	for _, ids := range hashes.IDs {
		for _, id := range ids {
			b.ids[id] = &ids
		}
	}

	slices.SortFunc(hashes.Hashes, func(existing, target SavedHash) int {
		return cmp.Or(
			cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
			cmp.Compare(existing.ID.Domain, target.ID.Domain),
			cmp.Compare(existing.ID.ID, target.ID.ID),
		)
	})

	// Assume they are probably fairly equally split between hash types
	b.aHashes = make([]SavedHash, 0, len(hashes.Hashes)/3)
	b.dHashes = make([]SavedHash, 0, len(hashes.Hashes)/3)
	b.pHashes = make([]SavedHash, 0, len(hashes.Hashes)/3)
	for _, savedHash := range hashes.Hashes {

		if savedHash.Hash.Kind == goimagehash.AHash {
			b.aHashes = append(b.aHashes, savedHash)
		}
		if savedHash.Hash.Kind == goimagehash.DHash {
			b.dHashes = append(b.dHashes, savedHash)
		}
		if savedHash.Hash.Kind == goimagehash.PHash {
			b.pHashes = append(b.pHashes, savedHash)
		}

		if savedHash.ID == (ID{}) {
			fmt.Println("Empty ID detected")
			panic(savedHash)
		}
		// All known equal IDs are already mapped we can add any missing ones from hashes
		if _, ok := b.ids[savedHash.ID]; !ok {
			b.ids[savedHash.ID] = &[]ID{savedHash.ID}
		}
	}

	hashCmp := func(existing, target SavedHash) int {
		return cmp.Or(
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
			cmp.Compare(existing.ID.Domain, target.ID.Domain),
			cmp.Compare(existing.ID.ID, target.ID.ID),
		)
	}
	slices.SortFunc(b.aHashes, hashCmp)
	slices.SortFunc(b.dHashes, hashCmp)
	slices.SortFunc(b.pHashes, hashCmp)

	return nil
}

// EncodeHashes should already have a lock
func (b *basicMapStorage) EncodeHashes() (SavedHashes, error) {
	savedHashes := SavedHashes{
		Hashes: make([]SavedHash, 0, len(b.aHashes)+len(b.dHashes)+len(b.pHashes)),
	}
	savedHashes.Hashes = append(savedHashes.Hashes, b.aHashes...)
	savedHashes.Hashes = append(savedHashes.Hashes, b.dHashes...)
	savedHashes.Hashes = append(savedHashes.Hashes, b.pHashes...)

	// Only keep groups len>1 as they are mapped in SavedHashes.Hashes
	for _, ids := range b.ids {
		if len(*ids) > 1 {
			savedHashes.IDs = append(savedHashes.IDs, *ids)
		}
	}

	return savedHashes, nil
}

func (b *basicMapStorage) AssociateIDs(newids []NewIDs) error {
	for _, newid := range newids {
		b.hashMutex.RLock()
		ids, found := b.ids[newid.OldID]
		b.hashMutex.RUnlock()
		if !found {
			return ErrIDNotFound
		}
		b.hashMutex.Lock()
		*ids = InsertID(*ids, newid.NewID)
		b.hashMutex.Unlock()
	}
	return nil
}

func (b *basicMapStorage) GetIDs(id ID) IDList {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	ids, found := b.ids[id]
	if !found {
		return nil
	}
	return ToIDList(*ids)
}

func NewBasicMapStorage() (HashStorage, error) {
	storage := &basicMapStorage{
		hashMutex: &sync.RWMutex{},
		ids:       make(map[ID]*[]ID),
		aHashes:   []SavedHash{},
		dHashes:   []SavedHash{},
		pHashes:   []SavedHash{},
	}
	return storage, nil
}
