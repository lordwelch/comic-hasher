package storage

import (
	"fmt"
	"math/bits"
	"slices"
	"sync"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type Basic struct {
	hashMutex *sync.RWMutex
	hashes    *ch.SavedHashesV3
}

func (b *Basic) RLock() {
	b.hashMutex.RLock()
}

func (b *Basic) RUnlock() {
	b.hashMutex.RUnlock()
}

// atleast must have a read lock before using
func (b *Basic) atleast(kind goimagehash.Kind, maxDistance int, searchHash uint64) []ch.Result {
	otherHashes := make([]ch.Result, 0, 20) // hope that we don't need more

	for _, storedHash := range *b.hashes.HashesForKind(kind) {
		distance := bits.OnesCount64(searchHash ^ storedHash.Hash)
		if distance <= maxDistance {
			otherHashes = append(otherHashes, b.hashes.GetResult(storedHash, kind, distance))
		}
	}

	matchingHashes := make([]ch.Result, len(otherHashes)) // For some reason copying to this slice is faster than not........
	copy(matchingHashes, otherHashes)
	return matchingHashes
}

func (b *Basic) exactMatches(hash ch.Hash) []ch.Result {
	var foundMatches []ch.Result
	mappedIds := map[uint32]bool{}

	index, count := b.findHash(hash)
	if count < 1 {
		return nil
	}
	currentHashes := *b.hashes.HashesForKind(hash.Kind)
	for _, storedHash := range currentHashes[index : index+count] {
		if mappedIds[storedHash.ID] {
			continue
		}
		mappedIds[storedHash.ID] = true

		foundMatches = append(foundMatches, b.hashes.GetResult(storedHash, hash.Kind, 0))
	}
	return foundMatches
}

func (b *Basic) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		foundMatches []ch.Result
		exactMatches []ch.Result
		tl           ch.TimeLog
	)
	tl.ResetTime()
	defer tl.LogTime(fmt.Sprintf("Search Complete: max: %v ExactOnly: %v", max, exactOnly))
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()

	for _, hash := range hashes {
		if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
			exactMatches = b.exactMatches(hash)

			tl.LogTime("Search Exact")
			if len(exactMatches) > 0 {
				foundMatches = append(foundMatches, exactMatches...)
				continue
			}
		}

		foundMatches = append(foundMatches, b.atleast(hash.Kind, max, hash.Hash)...)
	}
	return foundMatches, nil
}

// findHash looks for exact matches
// must have a read lock before using
// return value is index, count
// if count < 1 then no results were found
func (b *Basic) findHash(hash ch.Hash) (int, int) {
	currentHashes := *b.hashes.HashesForKind(hash.Kind)
	index, found := slices.BinarySearchFunc(currentHashes, hash.Hash, func(existing ch.HashV3, target uint64) int {
		if existing.Hash != target {
			if existing.Hash < target {
				return -1
			}
			return 1
		}
		return 0
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

func (b *Basic) AddHashes(hash ch.ImageHash) ch.Metrics {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()
	idCount := b.hashes.IDCount
	count := ch.Metrics{
		Hashes:           make(map[ch.Metric]int, 3),
		HashesConsistent: b.hashes.AHashCount == b.hashes.DHashCount && b.hashes.AHashCount == b.hashes.PHashCount,
		IDsConsistent:    b.hashes.AHashCount == b.hashes.IDCount,
		IDCount:          int(b.hashes.IDCount - idCount),
	}
	for _, ih := range hash.Hashes {
		if b.hashes.InsertHash(ih, hash.ID) {
			count.Hashes[ch.Metric{Source: hash.ID.Domain, Kind: ih.Kind}] += 1
		}
	}
	return count
}

// LoadHashes must already have a lock. SavedHashesV3 is already in the
// runtime representation so all that is needed is to keep the pointer.
func (b *Basic) LoadHashes(hashes *ch.SavedHashesV3) (ch.Metrics, error) {
	if hashes == nil {
		return ch.Metrics{}, nil
	}
	b.hashes = hashes
	return hashes.Metrics(), nil
}

// EncodeHashes should already have a lock
func (b *Basic) EncodeHashes() (*ch.SavedHashesV3, error) {
	return b.hashes, nil
}

func (b *Basic) GetDomains() []string {
	return slices.Clone(b.hashes.Sources)
}

func (b *Basic) AssociateIDs(OldID, NewID ch.ID) error {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()
	return b.hashes.AssociateIDs(OldID, NewID)
}

func (b *Basic) GetSources(i uint32) []string {
	s := []string{}
	groupID := b.hashes.IDs[i].Group
	if groupID == ch.NoIDGroup {
		return []string{b.hashes.Sources[b.hashes.IDs[i].Source]}
	}
	for _, rid := range b.hashes.IDGroups[groupID] {
		s = append(s, b.hashes.Sources[b.hashes.IDs[rid].Source])
	}
	slices.Sort(s)
	return s
}

func (b *Basic) hashSourcesCollide(_a, _b uint32) bool {
	if b.hashes.IDs[_a].Source == b.hashes.IDs[_b].Source {
		return true
	}
	bSources := b.GetSources(_b)
	for _, source := range b.GetSources(_a) {
		if slices.Contains(bSources, source) {
			return true
		}
	}
	return false
}

// Returns true if there are at least two seprate sources in this group of hashes
func (b *Basic) hasDuplicate(group []uint32) bool {
	for i, hash := range group {
		for _, shash := range group[i+1:] {
			if !b.hashSourcesCollide(hash, shash) {
				return true
			}
		}
	}
	return false
}

func (b *Basic) results(res [][]uint32) [][]ch.Result {
	results := make([][]ch.Result, 0, len(res))
	for _, currentGroup := range res {
		resGroup := make([]ch.Result, 0, len(currentGroup)*3)
		for _, idIndex := range currentGroup {
			resGroup = append(resGroup, b.hashes.GetHashes(idIndex)...)
		}
		results = append(results, resGroup)
	}
	return results
}

func (b *Basic) GetDuplicateHashes() [][]ch.Result {
	hashes := b.getDuplicateHashes(goimagehash.DHash)
	hashes = append(hashes, b.getDuplicateHashes(goimagehash.PHash)...)
	return hashes
}

func (b *Basic) getDuplicateHashes(kind goimagehash.Kind) [][]ch.Result {
	var (
		currentHash ch.HashV3
		lastHash    ch.HashV3
	)
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	hashes := *b.hashes.HashesForKind(kind)

	groups := [][]uint32{}
	currentGroup := []uint32{}
	lastHash = hashes[0]
	currentGroup = append(currentGroup, lastHash.ID)
	for _, currentHash = range hashes[1:] {
		if lastHash.Hash == currentHash.Hash {
			currentGroup = append(currentGroup, currentHash.ID)
			lastHash = currentHash
			continue
		}

		lastHash = currentHash
		if len(currentGroup) < 2 {
			currentGroup = currentGroup[:0]
			continue
		}
		if b.hasDuplicate(currentGroup) {
			groups = append(groups, slices.Clone(currentGroup))
		}
		currentGroup = currentGroup[:0]
	}
	fmt.Println("basic dupes", len(groups))
	return b.results(groups)
}

func (b *Basic) GetHashes(id ch.ID) []ch.Result {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	idIndex, found := b.hashes.FindID(id)
	if !found {
		return nil
	}
	return b.hashes.GetHashes(idIndex)
}

func (b *Basic) GetIDs(id ch.ID) []ch.ID {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	rid, ok := b.hashes.FindID(id)
	if !ok {
		return nil
	}
	return b.hashes.GetAllIDs(rid)
}

func (b *Basic) DisassociateID(id ch.ID) {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	b.hashes.DisassociateID(id)
}

func NewBasic() (ch.HashStorage, error) {
	storage := &Basic{
		hashMutex: &sync.RWMutex{},
		hashes:    &ch.SavedHashesV3{},
	}
	return storage, nil
}
