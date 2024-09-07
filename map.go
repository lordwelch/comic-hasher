package ch

import (
	"fmt"
	"slices"
	"sync"
)

type MapStorage struct {
	basicMapStorage
	partialHash [3][8]map[uint8][]uint64
}

func (m *MapStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var foundMatches []Result
	m.hashMutex.RLock()
	defer m.hashMutex.RUnlock()
	resetTime()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		for _, hash := range hashes {
			hashType := int(hash.Kind) - 1
			idlist := m.hashes[hashType][hash.Hash]
			if idlist != nil && len(*idlist) > 0 {
				foundMatches = append(foundMatches, Result{
					Distance: 0,
					Hash:     hash,
					IDs:      ToIDList(*idlist),
				})
			}
		}

		// If we have exact matches don't bother with other matches
		if len(foundMatches) > 0 && exactOnly {
			return foundMatches, nil
		}
		logTime("Search Exact")
	}

	totalPartialHashes := 0
	for _, searchHash := range hashes {
		foundHashes := make(map[uint64]struct{})
		hashType := int(searchHash.Kind) - 1
		for i, partialHash := range SplitHash(searchHash.Hash) {
			partialHashes := m.partialHash[hashType][i][partialHash]
			totalPartialHashes += len(partialHashes)
			for _, match := range Atleast(max, searchHash.Hash, partialHashes) {
				_, alreadyMatched := foundHashes[match.Hash]
				if matchedResults, ok := m.hashes[hashType][match.Hash]; ok && !alreadyMatched {
					foundHashes[match.Hash] = struct{}{}
					foundMatches = append(foundMatches, Result{IDs: ToIDList(*matchedResults), Distance: match.Distance, Hash: Hash{Hash: match.Hash, Kind: searchHash.Kind}})
				}
			}
		}
	}
	fmt.Println("Total partial hashes tested:", totalPartialHashes)
	logTime("Search Complete")
	go m.printSizes()
	return foundMatches, nil
}

func (m *MapStorage) MapHashes(hash ImageHash) {
	m.basicMapStorage.MapHashes(hash)
	for _, hash := range hash.Hashes {
		hashType := int(hash.Kind) - 1
		for i, partialHash := range SplitHash(hash.Hash) {
			m.partialHash[hashType][i][partialHash] = Insert(m.partialHash[hashType][i][partialHash], hash.Hash)
		}
	}
}

func (m *MapStorage) DecodeHashes(hashes SavedHashes) error {
	for hashType, sourceHashes := range hashes.Hashes {
		m.hashes[hashType] = make(map[uint64]*[]ID, len(sourceHashes))
		for savedHash, idlistLocation := range sourceHashes {
			for i, partialHash := range SplitHash(savedHash) {
				m.partialHash[hashType][i][partialHash] = append(m.partialHash[hashType][i][partialHash], savedHash)
			}
			m.hashes[hashType][savedHash] = &hashes.IDs[idlistLocation]
		}
	}
	m.printSizes()
	for _, partialHashes := range m.partialHash {
		for _, partMap := range partialHashes {
			for part, hashes := range partMap {
				slices.Sort(hashes)
				partMap[part] = slices.Compact(hashes)
			}
		}
	}
	m.printSizes()
	return nil
}

func (m *MapStorage) printSizes() {
	fmt.Println("Length of hashes:", len(m.hashes[0])+len(m.hashes[1])+len(m.hashes[2]))
	// fmt.Println("Size of", "hashes:", size.Of(m.hashes)/1024/1024, "MB")
	// fmt.Println("Size of", "ids:", size.Of(m.ids)/1024/1024, "MB")
	// fmt.Println("Size of", "MapStorage:", size.Of(m)/1024/1024, "MB")

}

func NewMapStorage() (HashStorage, error) {
	storage := &MapStorage{
		basicMapStorage: basicMapStorage{
			hashMutex: sync.RWMutex{},
			hashes: [3]map[uint64]*[]ID{
				make(map[uint64]*[]ID),
				make(map[uint64]*[]ID),
				make(map[uint64]*[]ID),
			},
		},
		partialHash: [3][8]map[uint8][]uint64{
			{
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
			},
			{
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
			},
			{
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
				make(map[uint8][]uint64),
			},
		},
	}
	return storage, nil
}
