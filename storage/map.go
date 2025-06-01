package storage

import (
	"fmt"
	"slices"
	"sync"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type MapStorage struct {
	basicMapStorage
	partialAHash [8]map[uint8][]uint64
	partialDHash [8]map[uint8][]uint64
	partialPHash [8]map[uint8][]uint64
}

func (m *MapStorage) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		foundMatches []ch.Result
		tl           ch.TimeLog
	)
	m.hashMutex.RLock()
	defer m.hashMutex.RUnlock()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		foundMatches = m.exactMatches(hashes, max)

		tl.LogTime("Search Exact")
		if len(foundMatches) > 0 {
			return foundMatches, nil
		}
	}
	tl.ResetTime()
	defer tl.LogTime("Search Complete")

	totalPartialHashes := 0

	for _, searchHash := range hashes {
		currentHashes, currentPartialHashes := m.getCurrentHashes(searchHash.Kind)
		potentialMatches := []uint64{}

		for i, partialHash := range ch.SplitHash(searchHash.Hash) {
			potentialMatches = append(potentialMatches, currentPartialHashes[i][partialHash]...)
		}

		totalPartialHashes += len(potentialMatches)
		mappedIds := map[int]bool{}

		for _, match := range ch.Atleast(max, searchHash.Hash, potentialMatches) {
			matchedHash := ch.Hash{
				Hash: match.Hash,
				Kind: searchHash.Kind,
			}
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

				foundMatches = append(foundMatches, ch.Result{
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
func (m *MapStorage) getCurrentHashes(kind goimagehash.Kind) ([]ch.SavedHash, [8]map[uint8][]uint64) {
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

func (m *MapStorage) MapHashes(hash ch.ImageHash) {
	m.basicMapStorage.MapHashes(hash)
	for _, hash := range hash.Hashes {
		_, partialHashes := m.getCurrentHashes(hash.Kind)
		for i, partialHash := range ch.SplitHash(hash.Hash) {
			partialHashes[i][partialHash] = ch.Insert(partialHashes[i][partialHash], hash.Hash)
		}
	}
}

func (m *MapStorage) DecodeHashes(hashes *ch.SavedHashes) error {
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

func NewMapStorage() (ch.HashStorage, error) {

	storage := &MapStorage{
		basicMapStorage: basicMapStorage{
			hashMutex: &sync.RWMutex{},
			ids: IDMap{
				ids: []IDs{},
			},
			aHashes: []ch.SavedHash{},
			dHashes: []ch.SavedHash{},
			pHashes: []ch.SavedHash{},
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

func mapPartialHashes(hashes []ch.SavedHash, partialHashMap [8]map[uint8][]uint64) {
	for _, savedHash := range hashes {
		for i, partialHash := range ch.SplitHash(savedHash.Hash.Hash) {
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
