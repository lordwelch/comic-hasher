package storage

import (
	"cmp"
	"fmt"
	"math/bits"
	"slices"
	"sync"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type BasicStorage struct {
	hashMutex *sync.RWMutex
	hashes    *ch.SavedHashesV3
}

func (b *BasicStorage) RLock() {
	b.hashMutex.RLock()
}

func (b *BasicStorage) RUnlock() {
	b.hashMutex.RUnlock()
}

// atleast must have a read lock before using
func (b *BasicStorage) atleast(kind goimagehash.Kind, maxDistance int, searchHash uint64) []ch.Result {
	otherHashes := make([]ch.Result, 0, 20) // hope that we don't need more

	for _, storedHash := range *b.hashes.HashesForKind(kind) {
		distance := bits.OnesCount64(searchHash ^ storedHash.Hash)
		if distance <= maxDistance {
			otherHashes = append(otherHashes, ch.Result{
				Hash: ch.Hash{
					Hash: storedHash.Hash,
					Kind: kind,
				},
				ID:            b.hashes.IDAt(storedHash.ID),
				Distance:      distance,
				EquivalentIDs: b.hashes.GetAllIDs(storedHash.ID),
			})
		}
	}

	matchingHashes := make([]ch.Result, len(otherHashes)) // For some reason copying to this slice is faster than not........
	copy(matchingHashes, otherHashes)
	return matchingHashes
}

func (b *BasicStorage) exactMatches(hashes []ch.Hash) []ch.Result {
	var foundMatches []ch.Result
	for _, hash := range hashes {
		mappedIds := map[uint32]bool{}

		index, count := b.findHash(hash)
		if count < 1 {
			continue
		}
		currentHashes := *b.hashes.HashesForKind(hash.Kind)
		for _, storedHash := range currentHashes[index : index+count] {
			if mappedIds[storedHash.ID] {
				continue
			}
			mappedIds[storedHash.ID] = true

			foundMatches = append(foundMatches, ch.Result{
				Hash:          ch.Hash{Hash: storedHash.Hash, Kind: hash.Kind},
				ID:            b.hashes.IDAt(storedHash.ID),
				Distance:      0,
				EquivalentIDs: b.hashes.GetAllIDs(storedHash.ID),
			})
		}
	}
	return foundMatches
}

func (b *BasicStorage) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
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

	for _, hash := range hashes {
		foundMatches = append(foundMatches, b.atleast(hash.Kind, max, hash.Hash)...)
	}
	return foundMatches, nil
}

// findHash looks for exact matches
// must have a read lock before using
// return value is index, count
// if count < 1 then no results were found
func (b *BasicStorage) findHash(hash ch.Hash) (int, int) {
	currentHashes := *b.hashes.HashesForKind(hash.Kind)
	index, found := slices.BinarySearchFunc(currentHashes, hash.Hash, func(existing ch.SavedHashV3, target uint64) int {
		return cmp.Compare(existing.Hash, target)
	})
	if !found {
		return index, 0
	}
	start := index
	for start > 0 && currentHashes[start-1].Hash == hash.Hash {
		start--
	}
	end := index + 1
	for end < len(currentHashes) && currentHashes[end].Hash == hash.Hash {
		end++
	}
	return start, end - start
}

func (b *BasicStorage) MapHashes(hash ch.ImageHash) ch.Metrics {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()

	count := ch.Metrics{
		Hashes: make(map[ch.Metric]int, 3),
	}
	for _, ih := range hash.Hashes {
		if b.hashes.InsertHash(ih, hash.ID) {
			count.Hashes[ch.Metric{Source: hash.ID.Domain, Kind: ih.Kind}] += 1
		}
	}
	return count
}

// DecodeHashes must already have a lock. SavedHashesV3 is already in the
// runtime representation so all that is needed is to keep the pointer.
func (b *BasicStorage) DecodeHashes(hashes *ch.SavedHashesV3) (ch.Metrics, error) {
	if hashes == nil {
		return ch.Metrics{}, nil
	}
	b.hashes = hashes
	return hashes.Metrics(), nil
}

// EncodeHashes should already have a lock
func (b *BasicStorage) EncodeHashes() (*ch.SavedHashesV3, error) {
	return b.hashes, nil
}

func (b *BasicStorage) AssociateIDs(newids []ch.NewIDs) error {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()
	var err error
	for _, newid := range newids {
		err = b.hashes.AssociateIDs(newid)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *BasicStorage) GetIDs(id ch.ID) ch.IDList {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	rid, ok := b.hashes.FindID(id)
	if !ok {
		return ch.IDList{}
	}
	return ch.ToIDList(b.hashes.GetAllIDs(rid))
}

func NewBasicStorage() (ch.HashStorage, error) {
	storage := &BasicStorage{
		hashMutex: &sync.RWMutex{},
		hashes:    &ch.SavedHashesV3{},
	}
	return storage, nil
}
