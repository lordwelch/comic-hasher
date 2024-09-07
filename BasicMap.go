package ch

import (
	"fmt"
	"math/bits"
	"sync"

	"gitea.narnian.us/lordwelch/goimagehash"
)

type basicMapStorage struct {
	hashMutex sync.RWMutex

	ids    map[ID]*[]ID
	hashes [3]map[uint64]*[]ID
}

func (b *basicMapStorage) Atleast(hashKind goimagehash.Kind, maxDistance int, searchHash uint64) []Result {
	hashType := int(hashKind) - 1
	matchingHashes := make([]Result, 0, 100) // hope that we don't need all of them
	for storedHash, ids := range b.hashes[hashType] {
		distance := bits.OnesCount64(searchHash ^ storedHash)
		if distance <= maxDistance {
			matchingHashes = append(matchingHashes, Result{ToIDList(*ids), distance, Hash{storedHash, hashKind}})
		}
	}
	return matchingHashes
}
func (b *basicMapStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var foundMatches []Result
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	resetTime()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		for _, hash := range hashes {
			hashType := int(hash.Kind) - 1
			ids := b.hashes[hashType][hash.Hash]
			if ids != nil && len(*ids) > 0 {
				foundMatches = append(foundMatches, Result{
					Distance: 0,
					Hash:     hash,
					IDs:      ToIDList(*ids),
				})
			}
		}

		// If we have exact matches don't bother with other matches
		if len(foundMatches) > 0 && exactOnly {
			return foundMatches, nil
		}
		logTime("Search Exact")
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
	logTime("Search Complete")
	go b.printSizes()
	return foundMatches, nil
}

func (b *basicMapStorage) MapHashes(hash ImageHash) {
	for _, ih := range hash.Hashes {
		var (
			hashType = int(ih.Kind) - 1
		)

		*b.hashes[hashType][ih.Hash] = InsertID((*b.hashes[hashType][ih.Hash]), hash.ID)
	}
}

func (b *basicMapStorage) DecodeHashes(hashes SavedHashes) error {
	for hashType, sourceHashes := range hashes.Hashes {
		b.hashes[hashType] = make(map[uint64]*[]ID, len(sourceHashes))
		for savedHash, idlistLocation := range sourceHashes {
			b.hashes[hashType][savedHash] = &hashes.IDs[idlistLocation]
		}
	}
	b.printSizes()
	return nil
}

func (b *basicMapStorage) printSizes() {
	// fmt.Println("Size of", "hashes:", size.Of(b.hashes)/1024/1024, "MB")
	// fmt.Println("Size of", "ids:", size.Of(b.ids)/1024/1024, "MB")
	// fmt.Println("Size of", "basicMapStorage:", size.Of(b)/1024/1024, "MB")

}

func (b *basicMapStorage) EncodeHashes() (SavedHashes, error) {
	hashes := SavedHashes{}
	idmap := map[*[]ID]int{}
	for _, ids := range b.ids {
		if _, ok := idmap[ids]; ok {
			continue
		}
		hashes.IDs = append(hashes.IDs, *ids)
		idmap[ids] = len(hashes.IDs)
	}
	for hashType, hashToID := range b.hashes {
		for hash, ids := range hashToID {
			hashes.Hashes[hashType][hash] = idmap[ids]
		}
	}
	return hashes, nil
}

func (b *basicMapStorage) AssociateIDs(newids []NewIDs) {
	for _, newid := range newids {
		ids, found := b.ids[newid.OldID]
		if !found {
			msg := "No IDs belonging to " + newid.OldID.Domain + "exist on this server"
			panic(msg)
		}
		*ids = InsertID(*ids, newid.NewID)
	}
}

func (b *basicMapStorage) GetIDs(id ID) IDList {
	ids, found := b.ids[id]
	if !found {
		msg := "No IDs belonging to " + id.Domain + "exist on this server"
		panic(msg)
	}
	return ToIDList(*ids)
}

func NewBasicMapStorage() (HashStorage, error) {
	storage := &basicMapStorage{
		hashMutex: sync.RWMutex{},

		hashes: [3]map[uint64]*[]ID{
			make(map[uint64]*[]ID),
			make(map[uint64]*[]ID),
			make(map[uint64]*[]ID),
		},
	}
	return storage, nil
}
