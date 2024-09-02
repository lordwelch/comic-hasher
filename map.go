package ch

import (
	"cmp"
	"math/bits"
	"slices"
	"sync"

	"gitea.narnian.us/lordwelch/goimagehash"
)

type mapStorage struct {
	hashMutex   sync.RWMutex
	partialHash [3][8]map[uint8][]int
	// partialAhash [8]map[uint8][]int
	// partialDhash [8]map[uint8][]int
	// partialPhash [8]map[uint8][]int

	ids []ID

	idToHash map[int][3][]int

	hashes [3][]uint64
	// ahashes []uint64
	// dhashes []uint64
	// phashes []uint64

	hashToID [3]map[int][]int
	// ahashToID map[int][]int
	// dhashToID map[int][]int
	// phashToID map[int][]int
}

func (m *mapStorage) addID(id ID) int {
	index, itemFound := slices.BinarySearchFunc(m.ids, id, func(existing, new ID) int {
		return cmp.Or(
			cmp.Compare(existing.Domain, new.Domain),
			cmp.Compare(existing.ID, new.ID),
		)
	})
	if itemFound {
		return index
	}
	m.ids = slices.Insert(m.ids, index, id)
	return index
}

func (m *mapStorage) getID(id ID) (int, bool) {
	return slices.BinarySearchFunc(m.ids, id, func(existing, new ID) int {
		return cmp.Or(
			cmp.Compare(existing.Domain, new.Domain),
			cmp.Compare(existing.ID, new.ID),
		)
	})
}

func (m *mapStorage) Atleast(hashKind goimagehash.Kind, maxDistance int, searchHash uint64, hashes []int) []Result {
	hashType := int(hashKind) - 1
	matchingHashes := make([]Result, 0, len(hashes)/2) // hope that we don't need all of them
	for _, idx := range hashes {
		storedHash := m.hashes[hashType][idx]
		distance := bits.OnesCount64(searchHash ^ storedHash)
		if distance <= maxDistance {
			ids := make(IDList)
			for _, idLocation := range m.hashToID[hashType][idx] {
				ids[m.ids[idLocation].Domain] = Insert(ids[m.ids[idLocation].Domain], m.ids[idLocation].ID)
			}
			matchingHashes = append(matchingHashes, Result{ids, distance, Hash{storedHash, hashKind}})
		}
	}
	return matchingHashes
}
func (m *mapStorage) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var foundMatches []Result
	m.hashMutex.RLock()
	defer m.hashMutex.RUnlock()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		for _, hash := range hashes {
			hashType := int(hash.Kind) - 1
			if hashLocation, found := slices.BinarySearch(m.hashes[hashType], hash.Hash); found {
				idlist := make(IDList)
				for _, idLocation := range m.hashToID[hashType][hashLocation] {

					for _, hashLocation := range m.idToHash[idLocation][0] {
						for _, foundIDLocation := range m.hashToID[hashType][hashLocation] {
							foundID := m.ids[foundIDLocation]
							idlist[foundID.Domain] = Insert(idlist[foundID.Domain], foundID.ID)
						}
					}
				}
				if len(idlist) > 0 {
					foundMatches = append(foundMatches, Result{
						Distance: 0,
						Hash:     hash,
					})
				}
			}
		}

		// If we have exact matches don't bother with other matches
		if len(foundMatches) > 0 && exactOnly {
			return foundMatches, nil
		}
	}

	foundHashes := make(map[uint64]struct{})
	for _, hash := range hashes {
		if hash.Hash == 0 {
			continue
		}
		hashType := int(hash.Kind) - 1
		for i, partialHash := range SplitHash(hash.Hash) {
			for _, match := range m.Atleast(hash.Kind, max, hash.Hash, m.partialHash[hashType][i][partialHash]) {
				_, alreadyMatched := foundHashes[match.Hash.Hash]
				if alreadyMatched {
					continue
				}
				foundMatches = append(foundMatches, match)
			}
		}
	}

	return foundMatches, nil
}

func (m *mapStorage) MapHashes(hash ImageHash) {

	idIndex := m.addID(hash.ID)
	idHashes := m.idToHash[idIndex]
	for _, hash := range hash.Hashes {
		var (
			hashIndex int
			hashType  = int(hash.Kind) - 1
		)
		m.hashes[hashType], hashIndex = InsertIdx(m.hashes[hashType], hash.Hash)
		for i, partialHash := range SplitHash(hash.Hash) {
			m.partialHash[hashType][i][partialHash] = append(m.partialHash[hashType][i][partialHash], hashIndex)
		}
		idHashes[hashType] = Insert(idHashes[hashType], hashIndex)
		m.hashToID[hashType][hashIndex] = Insert(m.hashToID[hashType][hashIndex], idIndex)
	}
	m.idToHash[idIndex] = idHashes
}

func (m *mapStorage) DecodeHashes(hashes SavedHashes) error {

	for _, sourceHashes := range hashes {
		m.hashes[0] = make([]uint64, 0, len(sourceHashes))
		m.hashes[1] = make([]uint64, 0, len(sourceHashes))
		m.hashes[2] = make([]uint64, 0, len(sourceHashes))
		break
	}
	for domain, sourceHashes := range hashes {
		for id, h := range sourceHashes {
			m.ids = append(m.ids, ID{Domain: Source(domain), ID: id})

			for _, hash := range []Hash{Hash{h[0], goimagehash.AHash}, Hash{h[1], goimagehash.DHash}, Hash{h[2], goimagehash.PHash}} {
				var (
					hashType = int(hash.Kind) - 1
				)
				m.hashes[hashType] = append(m.hashes[hashType], hash.Hash)
			}
		}
	}
	slices.SortFunc(m.ids, func(existing, new ID) int {
		return cmp.Or(
			cmp.Compare(existing.Domain, new.Domain),
			cmp.Compare(existing.ID, new.ID),
		)
	})
	slices.Sort(m.hashes[0])
	slices.Sort(m.hashes[1])
	slices.Sort(m.hashes[2])
	for domain, sourceHashes := range hashes {
		for id, h := range sourceHashes {
			m.MapHashes(ImageHash{
				Hashes: []Hash{{h[0], goimagehash.AHash}, {h[1], goimagehash.DHash}, {h[2], goimagehash.PHash}},
				ID:     ID{Domain: Source(domain), ID: id},
			})
		}
	}
	return nil
}

func (m *mapStorage) EncodeHashes() (SavedHashes, error) {
	hashes := make(SavedHashes)
	for idLocation, hashLocation := range m.idToHash {
		id := m.ids[idLocation]
		_, ok := hashes[id.Domain]
		if !ok {
			hashes[id.Domain] = make(map[string][3]uint64)
		}
		// TODO: Add all hashes. Currently saved hashes does not allow multiple IDs for a single hash
		hashes[id.Domain][id.ID] = [3]uint64{
			m.hashes[0][hashLocation[0][0]],
			m.hashes[1][hashLocation[1][0]],
			m.hashes[2][hashLocation[2][0]],
		}
	}
	return hashes, nil
}

func (m *mapStorage) AssociateIDs(newids []NewIDs) {
	for _, ids := range newids {
		oldIDLocation, found := m.getID(ids.OldID)
		if !found {
			msg := "No IDs belonging to " + ids.OldID.Domain + "exist on this server"
			panic(msg)
		}

		newIDLocation := m.addID(ids.NewID)

		for _, hashType := range []int{int(goimagehash.AHash), int(goimagehash.DHash), int(goimagehash.PHash)} {
			for _, hashLocation := range m.idToHash[oldIDLocation][hashType] {
				m.hashToID[hashType][hashLocation] = Insert(m.hashToID[hashType][hashLocation], newIDLocation)
				idHashes := m.idToHash[newIDLocation]
				idHashes[hashType] = Insert(idHashes[hashType], hashLocation)
				m.idToHash[newIDLocation] = idHashes
			}
		}
	}
}

func (m *mapStorage) GetIDs(id ID) IDList {
	idIndex, found := m.getID(id)
	if !found {
		msg := "No IDs belonging to " + id.Domain + "exist on this server"
		panic(msg)
	}
	ids := make(IDList)

	for _, hashLocation := range m.idToHash[idIndex][0] {
		for _, foundIDLocation := range m.hashToID[0][hashLocation] {
			foundID := m.ids[foundIDLocation]
			ids[foundID.Domain] = Insert(ids[foundID.Domain], foundID.ID)
		}
	}
	for _, hashLocation := range m.idToHash[idIndex][1] {
		for _, foundIDLocation := range m.hashToID[1][hashLocation] {
			foundID := m.ids[foundIDLocation]
			ids[foundID.Domain] = Insert(ids[foundID.Domain], foundID.ID)
		}
	}
	for _, hashLocation := range m.idToHash[idIndex][2] {
		for _, foundIDLocation := range m.hashToID[2][hashLocation] {
			foundID := m.ids[foundIDLocation]
			ids[foundID.Domain] = Insert(ids[foundID.Domain], foundID.ID)
		}
	}
	return ids
}

func NewMapStorage() (HashStorage, error) {
	storage := &mapStorage{
		hashMutex: sync.RWMutex{},
		idToHash:  make(map[int][3][]int),
		hashToID: [3]map[int][]int{
			make(map[int][]int),
			make(map[int][]int),
			make(map[int][]int),
		},
	}
	for i := range storage.partialHash[0] {
		storage.partialHash[0][i] = make(map[uint8][]int)
	}
	for i := range storage.partialHash[1] {
		storage.partialHash[1][i] = make(map[uint8][]int)
	}
	for i := range storage.partialHash[2] {
		storage.partialHash[2][i] = make(map[uint8][]int)
	}
	return storage, nil
}
