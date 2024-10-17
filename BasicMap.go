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

	ids    map[ID]*[]ID
	hashes [3][]structHash
}

type structHash struct {
	hash uint64
	ids  *[]ID
}

func (b *basicMapStorage) Atleast(hashKind goimagehash.Kind, maxDistance int, searchHash uint64) []Result {
	hashType := int(hashKind) - 1
	matchingHashes := make([]Result, 0, 100) // hope that we don't need all of them
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	for _, storedHash := range b.hashes[hashType] {
		distance := bits.OnesCount64(searchHash ^ storedHash.hash)
		if distance <= maxDistance {
			matchingHashes = append(matchingHashes, Result{ToIDList(*storedHash.ids), distance, Hash{storedHash.hash, hashKind}})
		}
	}
	return matchingHashes
}
func (b *basicMapStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var foundMatches []Result
	resetTime()
	defer logTime(fmt.Sprintf("Search Complete: max: %v ExactOnly: %v", max, exactOnly))

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		for _, hash := range hashes {
			hashType := int(hash.Kind) - 1
			b.hashMutex.RLock()
			index, hashFound := b.findHash(hashType, hash.Hash)
			if hashFound {
				foundMatches = append(foundMatches, Result{
					Distance: 0,
					Hash:     hash,
					IDs:      ToIDList(*b.hashes[hashType][index].ids),
				})
			}
			b.hashMutex.RUnlock()
		}

		logTime("Search Exact")
		// If we have exact matches don't bother with other matches
		if len(foundMatches) > 0 && exactOnly {
			return foundMatches, nil
		}
	}

	foundHashes := make(map[uint64]struct{})
	totalPartialHashes := 0
	for _, hash := range hashes {
		for _, match := range b.Atleast(hash.Kind, max, hash.Hash) {
			_, alreadyMatched := foundHashes[match.Hash.Hash]
			if alreadyMatched {
				continue
			}
			foundHashes[match.Hash.Hash] = struct{}{}
			foundMatches = append(foundMatches, match)
		}

	}
	fmt.Println("Total partial hashes tested:", totalPartialHashes, len(foundHashes))
	return foundMatches, nil
}

// findHash must have a read lock before using
func (b *basicMapStorage) findHash(hashType int, hash uint64) (int, bool) {
	return slices.BinarySearchFunc(b.hashes[hashType], hash, func(e structHash, t uint64) int {
		return cmp.Compare(e.hash, t)
	})
}

// insertHash will take a write lock if the hash is not found
func (b *basicMapStorage) insertHash(hashType int, hash uint64, ids *[]ID) {
	b.hashMutex.RLock()
	index, hashFound := b.findHash(hashType, hash)
	b.hashMutex.RUnlock()
	if hashFound {
		return
	}
	b.hashMutex.Lock()
	b.hashes[hashType] = slices.Insert(b.hashes[hashType], index, structHash{hash, ids})
	b.hashMutex.Unlock()
}

func (b *basicMapStorage) MapHashes(hash ImageHash) {
	for _, ih := range hash.Hashes {
		var (
			hashType = int(ih.Kind) - 1
		)
		b.hashMutex.RLock()
		ids, ok := b.ids[hash.ID]
		b.hashMutex.RUnlock()
		if !ok {
			b.hashMutex.Lock()
			ids = &[]ID{hash.ID}
			b.ids[hash.ID] = ids
			b.hashMutex.Unlock()
		}

		b.insertHash(hashType, ih.Hash, ids)
	}
}

// DecodeHashes should already have a lock
func (b *basicMapStorage) DecodeHashes(hashes SavedHashes) error {
	for hashType, sourceHashes := range hashes.Hashes {
		b.hashes[hashType] = make([]structHash, len(sourceHashes))
		for savedHash, idlistLocation := range sourceHashes {
			b.hashes[hashType] = append(b.hashes[hashType], structHash{savedHash, &hashes.IDs[idlistLocation]})
			for _, id := range hashes.IDs[idlistLocation] {
				b.ids[id] = &hashes.IDs[idlistLocation]
			}
		}
	}
	for hashType := range b.hashes {
		slices.SortFunc(b.hashes[hashType], func(a, b structHash) int {
			return cmp.Compare(a.hash, b.hash)
		})
	}
	return nil
}

// EncodeHashes should already have a lock
func (b *basicMapStorage) EncodeHashes() (SavedHashes, error) {
	hashes := SavedHashes{
		Hashes: [3]map[uint64]int{
			make(map[uint64]int),
			make(map[uint64]int),
			make(map[uint64]int),
		},
	}
	idmap := map[*[]ID]int{}

	for _, ids := range b.ids {
		if _, ok := idmap[ids]; ok {
			continue
		}
		idmap[ids] = len(hashes.IDs)
		hashes.IDs = append(hashes.IDs, *ids)
	}

	for hashType, hashToID := range b.hashes {
		for _, hash := range hashToID {
			hashes.Hashes[hashType][hash.hash] = idmap[hash.ids]
		}
	}
	return hashes, nil
}

func (b *basicMapStorage) AssociateIDs(newids []NewIDs) error {
	for _, newid := range newids {
		b.hashMutex.RLock()
		ids, found := b.ids[newid.OldID]
		b.hashMutex.RUnlock()
		if !found {
			msg := "No IDs belonging to " + string(newid.OldID.Domain) + " exist on this server"
			return errors.New(msg)
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
		hashes:    [3][]structHash{},
	}
	return storage, nil
}
