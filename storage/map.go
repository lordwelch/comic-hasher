package storage

import (
	"cmp"
	"slices"
	"sync"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type MapStorage struct {
	BasicMapStorage
	partialAHash [8]map[uint8][]uint64
	partialDHash [8]map[uint8][]uint64
	partialPHash [8]map[uint8][]uint64
}

func (m *MapStorage) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		foundMatches []ch.Result
		tl           ch.TimeLog
	)
	tl.ResetTime()
	defer tl.LogTime("Search Complete")
	m.hashMutex.RLock()
	defer m.hashMutex.RUnlock()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		foundMatches = m.exactMatches(hashes)

		tl.LogTime("Search Exact")
		if len(foundMatches) > 0 {
			return foundMatches, nil
		}
	}

	totalPartialHashes := 0

	var searchHash ch.Hash
	for _, searchHash = range hashes {
		currentHashes, currentPartialHashes := m.getCurrentHashes(searchHash.Kind)
		filteredMatches := []ch.Match{}

		for i, partialHash := range ch.SplitHash(searchHash.Hash) {
			filteredMatches = append(filteredMatches, ch.Atleast(max, searchHash.Hash, currentPartialHashes[i][partialHash])...)
		}
		slices.SortFunc(filteredMatches, func(x, y ch.Match) int {
			return cmp.Compare(x.Hash, y.Hash)
		})
		filteredMatches = slices.CompactFunc(filteredMatches, func(x, y ch.Match) bool {
			return x.Hash == y.Hash
		})

		totalPartialHashes += len(filteredMatches)

		var match ch.Match
		type t struct {
			match        ch.Match
			index, count int
		}
		resultSize := 0

		realMatches := make([]t, 0, len(filteredMatches))
		for _, match = range filteredMatches {
			matchedHash := ch.Hash{
				Hash: match.Hash,
				Kind: searchHash.Kind,
			}
			index, count := m.findHash(matchedHash)
			if count < 1 {
				continue
			}
			realMatches = append(realMatches, t{
				match,
				index,
				count,
			})
			resultSize += count
		}
		var tmatch t
		var storedHash RuntimeHash2
		for _, tmatch = range realMatches {
			for _, storedHash = range currentHashes[tmatch.index : tmatch.index+tmatch.count] {
				foundMatches = append(foundMatches, ch.Result{
					Hash:          ch.Hash{Hash: storedHash.Hash, Kind: searchHash.Kind},
					ID:            m.ids.GetID(storedHash.ID).CHID(),
					Distance:      tmatch.match.Distance,
					EquivalentIDs: m.ids.GetAllIDs(storedHash.ID),
				})
			}
		}
	}

	return foundMatches, nil
}

// getCurrentHashes must have a read lock before using
func (m *MapStorage) getCurrentHashes(kind goimagehash.Kind) ([]RuntimeHash2, [8]map[uint8][]uint64) {
	if kind == goimagehash.AHash {
		return m.AHashes, m.partialAHash
	}
	if kind == goimagehash.DHash {
		return m.DHashes, m.partialDHash
	}
	if kind == goimagehash.PHash {
		return m.PHashes, m.partialPHash
	}
	panic("Unknown hash type: " + kind.String())
}

func (m *MapStorage) MapHashes(hash ch.ImageHash) ch.Metrics {
	metrics := m.BasicMapStorage.MapHashes(hash)
	for _, hash := range hash.Hashes {
		_, partialHashes := m.getCurrentHashes(hash.Kind)
		for i, partialHash := range ch.SplitHash(hash.Hash) {
			partialHashes[i][partialHash] = ch.Insert(partialHashes[i][partialHash], hash.Hash)
		}
	}
	return metrics
}

func (m *MapStorage) DecodeHashes(hashes *ch.SavedHashes) (ch.Metrics, error) {
	if hashes == nil {
		return ch.Metrics{}, nil
	}
	metrics, err := m.BasicMapStorage.DecodeHashes(hashes)
	if err != nil {
		return ch.Metrics{}, err
	}

	mapPartialHashes(m.AHashes, m.partialAHash)
	mapPartialHashes(m.DHashes, m.partialDHash)
	mapPartialHashes(m.PHashes, m.partialPHash)

	compactPartialHashes(m.partialAHash)
	compactPartialHashes(m.partialDHash)
	compactPartialHashes(m.partialPHash)

	return metrics, nil
}

func NewMapStorage() (ch.HashStorage, error) {
	storage := &MapStorage{
		BasicMapStorage: BasicMapStorage{
			hashMutex: &sync.RWMutex{},
		},
		partialAHash: newPartialHash(),
		partialDHash: newPartialHash(),
		partialPHash: newPartialHash(),
	}
	return storage, nil
}

func newPartialHash() [8]map[uint8][]uint64 {
	return [8]map[uint8][]uint64{
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
	}
}

func mapPartialHashes(hashes []RuntimeHash2, partialHashMap [8]map[uint8][]uint64) {
	for _, savedHash := range hashes {
		for i, partialHash := range ch.SplitHash(savedHash.Hash) {
			partialHashMap[i][partialHash] = append(partialHashMap[i][partialHash], savedHash.Hash)
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
