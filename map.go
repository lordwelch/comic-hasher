package ch

import (
	"cmp"
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
	defer logTime("Search Complete")

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		for _, hash := range hashes {
			hashType := int(hash.Kind) - 1
			index, hashFound := m.findHash(hashType, hash.Hash)
			if hashFound {
				foundMatches = append(foundMatches, Result{
					Distance: 0,
					Hash:     hash,
					IDs:      ToIDList(*m.hashes[hashType][index].ids),
				})
			}
		}

		// If we have exact matches don't bother with other matches
		logTime("Search Exact")
		if len(foundMatches) > 0 && exactOnly {
			return foundMatches, nil
		}
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
				if index, hashFound := m.findHash(hashType, match.Hash); hashFound && !alreadyMatched {
					foundHashes[match.Hash] = struct{}{}
					foundMatches = append(foundMatches, Result{IDs: ToIDList(*m.hashes[hashType][index].ids), Distance: match.Distance, Hash: Hash{Hash: match.Hash, Kind: searchHash.Kind}})
				}
			}
		}
	}
	fmt.Println("Total partial hashes tested:", totalPartialHashes)
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
		m.hashes[hashType] = make([]structHash, len(sourceHashes))
		for savedHash, idlistLocation := range sourceHashes {
			m.hashes[hashType] = append(m.hashes[hashType], structHash{savedHash, &hashes.IDs[idlistLocation]})
		}
	}
	for hashType := range m.hashes {
		slices.SortFunc(m.hashes[hashType], func(a, b structHash) int {
			return cmp.Compare(a.hash, b.hash)
		})
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
			hashes: [3][]structHash{
				[]structHash{},
				[]structHash{},
				[]structHash{},
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
