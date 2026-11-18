package storage

import (
	"slices"
	"sync"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type Map struct {
	Basic
	partialAHash [8]map[uint8][]uint64
	partialDHash [8]map[uint8][]uint64
	partialPHash [8]map[uint8][]uint64
}

func (m *Map) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		foundMatches []ch.Result
		exactMatches []ch.Result
		tl           ch.TimeLog
	)
	tl.ResetTime()
	defer tl.LogTime("Search Complete")
	m.hashMutex.RLock()
	defer m.hashMutex.RUnlock()

	var searchHash ch.Hash
	for _, searchHash = range hashes {
		if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
			exactMatches = m.exactMatches(searchHash)

			tl.LogTime("Search Exact")
			if len(exactMatches) > 0 {
				foundMatches = append(foundMatches, exactMatches...)
				continue
			}
		}

		currentHashes, currentPartialHashes := m.getCurrentHashes(searchHash.Kind)
		filteredMatches := []ch.Match{}

		for i, partialHash := range ch.SplitHash(searchHash.Hash) {
			filteredMatches = append(filteredMatches, ch.Atleast(max, searchHash.Hash, currentPartialHashes[i][partialHash])...)
		}
		slices.SortFunc(filteredMatches, func(x, y ch.Match) int {
			if x.Hash != y.Hash {
				if x.Hash < y.Hash {
					return -1
				}
				return 1
			}
			return 0
		})
		filteredMatches = slices.CompactFunc(filteredMatches, func(x, y ch.Match) bool {
			return x.Hash == y.Hash
		})

		var match ch.Match
		type t struct {
			match        ch.Match
			index, count int
		}

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
		}
		var tmatch t
		var storedHash ch.HashV3
		for _, tmatch = range realMatches {
			for _, storedHash = range currentHashes[tmatch.index : tmatch.index+tmatch.count] {
				foundMatches = append(foundMatches, m.hashes.GetResult(storedHash, searchHash.Kind, tmatch.match.Distance))
			}
		}
	}

	return foundMatches, nil
}

// getCurrentHashes must have a read lock before using
func (m *Map) getCurrentHashes(kind goimagehash.Kind) ([]ch.HashV3, [8]map[uint8][]uint64) {
	if kind == goimagehash.AHash {
		return *m.hashes.HashesForKind(kind), m.partialAHash
	}
	if kind == goimagehash.DHash {
		return *m.hashes.HashesForKind(kind), m.partialDHash
	}
	if kind == goimagehash.PHash {
		return *m.hashes.HashesForKind(kind), m.partialPHash
	}
	panic("Unknown hash type: " + kind.String())
}

func (m *Map) AddHashes(hash ch.ImageHash) ch.Metrics {
	metrics := m.Basic.AddHashes(hash)
	for _, hash := range hash.Hashes {
		_, partialHashes := m.getCurrentHashes(hash.Kind)
		for i, partialHash := range ch.SplitHash(hash.Hash) {
			partialHashes[i][partialHash] = ch.Insert(partialHashes[i][partialHash], hash.Hash)
		}
	}
	return metrics
}

func (m *Map) LoadHashes(hashes *ch.SavedHashesV3) (ch.Metrics, error) {
	if hashes == nil {
		return ch.Metrics{}, nil
	}
	metrics, err := m.Basic.LoadHashes(hashes)
	if err != nil {
		return ch.Metrics{}, err
	}

	m.partialAHash = newPartialHash()
	m.partialDHash = newPartialHash()
	m.partialPHash = newPartialHash()

	mapPartialHashes(*m.hashes.HashesForKind(goimagehash.AHash), m.partialAHash)
	mapPartialHashes(*m.hashes.HashesForKind(goimagehash.DHash), m.partialDHash)
	mapPartialHashes(*m.hashes.HashesForKind(goimagehash.PHash), m.partialPHash)

	compactPartialHashes(m.partialAHash)
	compactPartialHashes(m.partialDHash)
	compactPartialHashes(m.partialPHash)

	return metrics, nil
}

func NewMap() (ch.HashStorage, error) {
	storage := &Map{
		hashMutex:    &sync.RWMutex{},
		hashes:       &ch.SavedHashesV3{},
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

func mapPartialHashes(hashes []ch.HashV3, partialHashMap [8]map[uint8][]uint64) {
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
