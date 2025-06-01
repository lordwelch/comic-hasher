package ch

import (
	"fmt"
	"slices"
	"sync"

	"gitea.narnian.us/lordwelch/goimagehash"
)

type MapStorage struct {
	basicMapStorage
	partialAHash [8]map[uint8][]uint64
	partialDHash [8]map[uint8][]uint64
	partialPHash [8]map[uint8][]uint64
}

func (m *MapStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var (
		foundMatches []Result
		tl           timeLog
	)
	m.hashMutex.RLock()
	defer m.hashMutex.RUnlock()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		foundMatches = m.exactMatches(hashes, max)

		tl.logTime("Search Exact")
		if len(foundMatches) > 0 {
			return foundMatches, nil
		}
	}
	tl.resetTime()
	defer tl.logTime("Search Complete")

	totalPartialHashes := 0

	for _, searchHash := range hashes {
		currentHashes, currentPartialHashes := m.getCurrentHashes(searchHash.Kind)
		potentialMatches := []uint64{}

		for i, partialHash := range SplitHash(searchHash.Hash) {
			potentialMatches = append(potentialMatches, currentPartialHashes[i][partialHash]...)
		}

		totalPartialHashes += len(potentialMatches)
		mappedIds := map[int]bool{}

		for _, match := range Atleast(max, searchHash.Hash, potentialMatches) {
			matchedHash := Hash{match.Hash, searchHash.Kind}
			index, count := m.findHash(matchedHash)
			if count < 1 {
				continue
			}
			for _, storedHash := range currentHashes[index : index+count] {
				idIndex, _ := m.ids.FindID(&storedHash.ID)
				if mappedIds[idIndex] {
					continue
				}
				mappedIds[idIndex] = true

				foundMatches = append(foundMatches, Result{
					Hash:          storedHash.Hash,
					ID:            storedHash.ID,
					Distance:      0,
					EquivalentIDs: m.ids.GetIDs(&storedHash.ID),
				})

			}
		}
	}
	fmt.Println("Total partial hashes tested:", totalPartialHashes)
	return foundMatches, nil
}

// getCurrentHashes must have a read lock before using
func (m *MapStorage) getCurrentHashes(kind goimagehash.Kind) ([]bmHash, [8]map[uint8][]uint64) {
	if kind == goimagehash.AHash {
		return m.aHashes, m.partialAHash
	}
	if kind == goimagehash.DHash {
		return m.dHashes, m.partialDHash
	}
	if kind == goimagehash.PHash {
		return m.pHashes, m.partialPHash
	}
	panic("Unknown hash type: " + kind.String())
}

func (m *MapStorage) MapHashes(hash ImageHash) {
	m.basicMapStorage.MapHashes(hash)
	for _, hash := range hash.Hashes {
		_, partialHashes := m.getCurrentHashes(hash.Kind)
		for i, partialHash := range SplitHash(hash.Hash) {
			partialHashes[i][partialHash] = Insert(partialHashes[i][partialHash], hash.Hash)
		}
	}
}

func (m *MapStorage) DecodeHashes(hashes *SavedHashes) error {
	if hashes == nil {
		return nil
	}
	if err := m.basicMapStorage.DecodeHashes(hashes); err != nil {
		return err
	}

	mapPartialHashes(m.aHashes, m.partialAHash)
	mapPartialHashes(m.dHashes, m.partialDHash)
	mapPartialHashes(m.pHashes, m.partialPHash)

	compactPartialHashes(m.partialAHash)
	compactPartialHashes(m.partialDHash)
	compactPartialHashes(m.partialPHash)

	return nil
}

func NewMapStorage() (HashStorage, error) {

	storage := &MapStorage{
		basicMapStorage: basicMapStorage{
			hashMutex: &sync.RWMutex{},
			ids: IDMap{
				ids: []IDs{},
			},
			aHashes: []bmHash{},
			dHashes: []bmHash{},
			pHashes: []bmHash{},
		},
		partialAHash: newPartialHash(),
		partialDHash: newPartialHash(),
		partialPHash: newPartialHash(),
	}
	return storage, nil
}

func newPartialHash() [8]map[uint8][]uint64 {
	return [8]map[uint8][]uint64{
		map[uint8][]uint64{},
		map[uint8][]uint64{},
		map[uint8][]uint64{},
		map[uint8][]uint64{},
		map[uint8][]uint64{},
		map[uint8][]uint64{},
		map[uint8][]uint64{},
		map[uint8][]uint64{},
	}
}

func mapPartialHashes(hashes []bmHash, partialHashMap [8]map[uint8][]uint64) {
	for _, savedHash := range hashes {
		for i, partialHash := range SplitHash(savedHash.Hash.Hash) {
			partialHashMap[i][partialHash] = append(partialHashMap[i][partialHash], savedHash.Hash.Hash)
		}
	}
}

func compactPartialHashes(partialHashMap [8]map[uint8][]uint64) {
	for _, partMap := range partialHashMap {
		for part, hashes := range partMap {
			slices.Sort(hashes)
			partMap[part] = slices.Compact(hashes)
		}
	}
}
