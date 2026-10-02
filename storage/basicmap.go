package storage

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"
	"sync"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type RuntimeID uint32

type RuntimeHash struct {
	Hash uint64
	ID   *ch.ID
}
type RuntimeHash2 struct {
	Hash uint64
	ID   RuntimeID
}
type BasicMapStorage struct {
	hashMutex *sync.RWMutex
	ids       IDMap
	AHashes   []RuntimeHash2
	DHashes   []RuntimeHash2
	PHashes   []RuntimeHash2
}
type ID struct {
	Domain        *ch.Source
	RuntimeID     RuntimeID // index into IDMap.IDs // This technically shouldn't be needed
	ID            string    // size (16 + (8))
	EquivalentIDs uint32    // index into IDMap.EquivalentIDs
}

func (i ID) CHID() ch.ID {
	return ch.ID{
		Domain: i.Domain,
		ID:     i.ID,
	}
}

type IDMap struct {
	ids           []ID
	IDIndex       []RuntimeID
	EquivalentIDs [][]RuntimeID
}

func (m *IDMap) Sort() {
	if slices.IsSortedFunc(m.ids, func(a ID, b ID) int {
		return cmp.Compare(a.RuntimeID, b.RuntimeID)
	}) {
		panic("ID list is unsorted. This should be impossible")
	}
}

func (m *IDMap) GetID(rid RuntimeID) ID {
	// This should be automatically inlined
	return m.ids[rid]
}

func (m *IDMap) SortIndex() {
	slices.SortFunc(m.IDIndex, func(a RuntimeID, b RuntimeID) int {
		return cmp.Compare(m.ids[a].ID, m.ids[b].ID)
	})
}

func (m *IDMap) FindID(id ch.ID) (RuntimeID, bool) {
	index, found := slices.BinarySearchFunc(m.IDIndex, id, func(rid RuntimeID, target ch.ID) int {
		return cmp.Or(cmp.Compare(*m.ids[rid].Domain, *target.Domain),
			cmp.Compare(m.ids[rid].ID, target.ID))
	})
	if !found {
		return 0, false
	}
	return m.IDIndex[index], true
}

func (m *IDMap) InsertID(id ch.ID) RuntimeID {
	rid := m.insertID(id)
	m.SortIndex()
	return rid
}

func (m *IDMap) insertID(id ch.ID) RuntimeID {
	rid, found := m.FindID(id)
	if found {
		return rid
	}
	rid = RuntimeID(len(m.ids))
	m.ids = append(m.ids, ID{
		ID:            id.ID,
		RuntimeID:     rid,
		Domain:        id.Domain,
		EquivalentIDs: math.MaxUint32,
	})
	m.IDIndex = append(m.IDIndex, rid)
	return rid
}

func (m *IDMap) FindAllIDs(id ch.ID) []ch.ID {
	rid, found := m.FindID(id)

	if !found {
		return nil
	}

	return m.GetAllIDs(rid)
}

func (m *IDMap) GetAllIDs(rid RuntimeID) []ch.ID {
	var ids []ch.ID
	id := m.GetID(rid)
	if m.ids[rid].EquivalentIDs == math.MaxUint32 {
		return []ch.ID{id.CHID()}
	}
	if len(m.EquivalentIDs[m.ids[rid].EquivalentIDs]) < 2 {
		log.Println(log.Fatal, "An ID refers to an empty id list. This should never happen")
		return nil
	}
	ids = make([]ch.ID, 0, len(m.EquivalentIDs[m.ids[rid].EquivalentIDs]))
	for _, eid := range m.EquivalentIDs[m.ids[rid].EquivalentIDs] {
		ids = append(ids, ch.ID{
			Domain: m.ids[eid].Domain,
			ID:     m.ids[eid].ID,
		})
	}
	return ids
}

func (m *IDMap) AssociateIDs(newids []ch.NewIDs) error {
	for _, newid := range newids {
		orid, found := m.FindID(newid.OldID)
		if !found {
			return ErrIDNotFound
		}
		nrid, found := m.FindID(newid.NewID)
		if !found {
			return ErrIDNotFound
		}
		oeid := m.ids[orid].EquivalentIDs
		neid := m.ids[nrid].EquivalentIDs
		if oeid == neid {
			return nil
		}
		if oeid == math.MaxUint32 && neid != math.MaxUint32 {
			m.EquivalentIDs[neid] = append(m.EquivalentIDs[neid], orid)
			m.ids[orid].EquivalentIDs = neid
			return nil
		}
		if neid == math.MaxUint32 && oeid != math.MaxUint32 {
			m.EquivalentIDs[oeid] = append(m.EquivalentIDs[oeid], nrid)
			m.ids[nrid].EquivalentIDs = oeid
			return nil
		}
		if neid == math.MaxUint32 && oeid == math.MaxUint32 {
			eid := uint32(len(m.EquivalentIDs))
			m.EquivalentIDs = append(m.EquivalentIDs, []RuntimeID{orid, nrid})
			m.ids[nrid].EquivalentIDs = eid
			m.ids[orid].EquivalentIDs = eid
			return nil
		}
		// neid and oeid both have an exist list
		// if NewID.Domain == metron: check that no metron exists in OldID's id list
		for _, rid := range m.EquivalentIDs[neid] {
			if *m.ids[rid].Domain == *newid.OldID.Domain {
				return fmt.Errorf("ID %v is already matched to %v:%v. Cannot associate two ID's in the same source", newid.NewID, m.ids[rid].Domain, m.ids[rid].ID)
			}
		}
		// if OldID.Domain == GCD: check that no gcd exists in NewID's id list
		for _, rid := range m.EquivalentIDs[oeid] {
			if *m.ids[rid].Domain == *newid.NewID.Domain {
				return fmt.Errorf("ID %v is already matched to %v:%v. Cannot associate two ID's in the same source", newid.OldID, m.ids[rid].Domain, m.ids[rid].ID)
			}
		}
		// if NewID(metron) already equivalent to CV:123
		// and if OldID(GCD)    already equivalent to CV:321
		// return err
		for _, nnrid := range m.EquivalentIDs[neid] {
			nnSource := m.ids[nnrid].Domain
			nnID := m.ids[nnrid].Domain
			for _, oorid := range m.EquivalentIDs[oeid] {
				ooSource := m.ids[oorid].Domain
				ooID := m.ids[oorid].Domain
				if nnSource == ooSource {
					// return fmt.Errorf("ID metron:1 == CV:123 and ID GCD:45 == CV:321. Cannot associate metron:1 to GCD:45", newid.OldID, nnSource, nnID)
					return fmt.Errorf(
						"ID %v == %v:%v and ID %v == %v:%v. Cannot associate %v to %v",
						newid.NewID, nnSource, nnID, newid.OldID, ooSource, ooID, newid.NewID, newid.OldID,
					)
				}
			}
		}

		// we've now validated that their are no conflicts so we need to merge and re-do everything
		allIDs := make([]RuntimeID, 0, len(m.EquivalentIDs[oeid])+len(m.EquivalentIDs[neid]))
		allIDs = append(allIDs, m.EquivalentIDs[oeid]...)
		allIDs = append(allIDs, m.EquivalentIDs[neid]...)
		// For no particular reason we use the neid as the only real id
		// Because we currently use the index into the slice as an index we can't delete it so we just leave it empty
		for _, id := range m.EquivalentIDs[oeid] {
			m.ids[id].EquivalentIDs = neid
			m.EquivalentIDs[neid] = append(m.EquivalentIDs[neid], id)
		}
		m.EquivalentIDs[oeid] = nil // marks as unused
		// Nothing should refer to this index again
	}
	return nil
}

var ErrIDNotFound = errors.New("ID not found on this server")

func (b *BasicMapStorage) RLock() {
	b.hashMutex.RLock()
}

func (b *BasicMapStorage) RUnlock() {
	b.hashMutex.RUnlock()
}

// atleast must have a read lock before using
func (b *BasicMapStorage) atleast(kind goimagehash.Kind, maxDistance int, searchHash uint64) []ch.Result {
	otherHashes := make([]ch.Result, 0, 20) // hope that we don't need more

	storedHash := RuntimeHash2{}
	for _, storedHash = range *b.getCurrentHashes(kind) {
		distance := bits.OnesCount64(searchHash ^ storedHash.Hash)
		if distance <= maxDistance {
			otherHashes = append(otherHashes, ch.Result{
				Hash: ch.Hash{
					Hash: storedHash.Hash,
					Kind: kind,
				},
				ID:            b.ids.GetID(storedHash.ID).CHID(),
				Distance:      distance,
				EquivalentIDs: b.ids.GetAllIDs(storedHash.ID),
			})
		}
	}

	matchingHashes := make([]ch.Result, 0, len(otherHashes)) // For some reason copying to this slice is faster than not........
	for i := range otherHashes {
		matchingHashes = append(matchingHashes, ch.Result{
			Hash:          otherHashes[i].Hash,
			ID:            otherHashes[i].ID,
			Distance:      otherHashes[i].Distance,
			EquivalentIDs: otherHashes[i].EquivalentIDs,
		})
	}
	return matchingHashes
}

func (b *BasicMapStorage) exactMatches(hashes []ch.Hash) []ch.Result {
	var foundMatches []ch.Result
	for _, hash := range hashes {
		mappedIds := map[RuntimeID]bool{}

		index, count := b.findHash(hash)
		if count < 1 {
			continue
		}
		var storedHash RuntimeHash2
		for _, storedHash = range (*b.getCurrentHashes(hash.Kind))[index : index+count] {
			if mappedIds[storedHash.ID] {
				continue
			}
			mappedIds[storedHash.ID] = true

			foundMatches = append(foundMatches, ch.Result{
				Hash:          ch.Hash{Hash: storedHash.Hash, Kind: hash.Kind},
				ID:            b.ids.GetID(storedHash.ID).CHID(),
				Distance:      0,
				EquivalentIDs: b.ids.GetAllIDs(storedHash.ID),
			})
		}
	}
	return foundMatches
}

func (b *BasicMapStorage) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		foundMatches []ch.Result
		tl           ch.TimeLog
	)
	tl.ResetTime()
	defer tl.LogTime(fmt.Sprintf("Search Complete: max: %v ExactOnly: %v", max, exactOnly))
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()

	if exactOnly { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		foundMatches = b.exactMatches(hashes)

		tl.LogTime("Search Exact")
		if len(foundMatches) > 0 {
			return foundMatches, nil
		}
	}

	totalPartialHashes := 0

	for _, hash := range hashes {
		totalPartialHashes += len(*b.getCurrentHashes(hash.Kind))
		foundMatches = append(foundMatches, b.atleast(hash.Kind, max, hash.Hash)...)
	}
	return foundMatches, nil
}

// getCurrentHashes must have a read lock before using
func (b *BasicMapStorage) getCurrentHashes(kind goimagehash.Kind) *[]RuntimeHash2 {
	if kind == goimagehash.AHash {
		return &b.AHashes
	}
	if kind == goimagehash.DHash {
		return &b.DHashes
	}
	if kind == goimagehash.PHash {
		return &b.PHashes
	}
	panic("Unknown hash type: " + kind.String())
}

// findHash looks for exact matches
// must have a read lock before using
// return value is index, count
// if count < 1 then no results were found
func (b *BasicMapStorage) findHash(hash ch.Hash) (int, int) {
	currentHashes := *b.getCurrentHashes(hash.Kind)
	index, found := slices.BinarySearchFunc(currentHashes, hash, func(existing RuntimeHash2, target ch.Hash) int {
		return cmp.Compare(existing.Hash, target.Hash)
	})
	if !found {
		return index, 0
	}
	count := 1 // Skip the index we already found because we know it's equal
	for i := index + 1; i < len(currentHashes) && currentHashes[i].Hash == hash.Hash; i++ {
		count++
	}
	return index, count
}

// insertHash must already have a lock
func (b *BasicMapStorage) insertHash(hash ch.Hash, id ch.ID) bool {
	currentHashes := b.getCurrentHashes(hash.Kind)
	start, count := b.findHash(hash)
	m := start + count
	index := start
	for ; index < m; index++ {
		if id.Compare(b.ids.GetID((*currentHashes)[index].ID).CHID()) == 0 {
			return true
		}
	}

	rh := RuntimeHash2{
		Hash: hash.Hash,
		ID:   b.ids.InsertID(id),
	}
	*currentHashes = slices.Insert(*currentHashes, index, rh)

	slices.SortFunc((*currentHashes), b.hashCmp)
	return false
}

func (b *BasicMapStorage) MapHashes(hash ch.ImageHash) ch.Metrics {
	b.hashMutex.Lock()
	defer b.hashMutex.Unlock()

	count := ch.Metrics{
		Hashes: make(map[ch.Metric]int, 3),
	}
	for _, ih := range hash.Hashes {
		if b.insertHash(ih, hash.ID) {
			count.Hashes[ch.Metric{Source: hash.ID.Domain, Kind: ih.Kind}] += 1
		}
	}
	return count
}

// DecodeHashes must already have a lock
func (b *BasicMapStorage) DecodeHashes(hashes *ch.SavedHashes) (ch.Metrics, error) {
	if hashes == nil {
		return ch.Metrics{}, nil
	}
	b.ids.ids = make([]ID, 0, len(hashes.Hashes))

	// Initialize all the known equal IDs
	for _, ids := range hashes.IDs {
		if len(ids) < 2 {
			continue
		}
		eid := uint32(len(b.ids.EquivalentIDs))
		b.ids.EquivalentIDs = append(b.ids.EquivalentIDs, make([]RuntimeID, 0, len(ids)))
		for _, id := range ids {
			b.ids.ids = append(b.ids.ids, ID{
				Domain:        id.Domain,
				ID:            id.ID,
				RuntimeID:     RuntimeID(len(b.ids.ids)),
				EquivalentIDs: eid,
			})
		}
	}

	slices.SortFunc(hashes.Hashes, func(existing, target ch.SavedHash) int {
		return cmp.Or(
			cmp.Compare(*existing.ID.Domain, *target.ID.Domain), // Sorted for id insertion efficiency
			cmp.Compare(existing.ID.ID, target.ID.ID),           // Sorted for id insertion efficiency
			cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash), // This should never realisticaly happen
		)
	})
	aHashCount := 0
	dHashCount := 0
	pHashCount := 0
	for _, savedHash := range hashes.Hashes {
		if savedHash.Hash.Kind == goimagehash.AHash {
			aHashCount += 1
		}
		if savedHash.Hash.Kind == goimagehash.DHash {
			dHashCount += 1
		}
		if savedHash.Hash.Kind == goimagehash.PHash {
			pHashCount += 1
		}
	}

	b.AHashes = make([]RuntimeHash2, 0, aHashCount)
	b.DHashes = make([]RuntimeHash2, 0, dHashCount)
	b.PHashes = make([]RuntimeHash2, 0, pHashCount)
	var hash ch.SavedHash
	for _, hash = range hashes.Hashes {
		// TODO: Investigate better options to load in the ID
		if hash.Hash.Kind == goimagehash.AHash {
			b.AHashes = append(b.AHashes, RuntimeHash2{
				Hash: hash.Hash.Hash,
				ID:   b.ids.insertID(hash.ID),
			})
		} else if hash.Hash.Kind == goimagehash.DHash {
			b.DHashes = append(b.DHashes, RuntimeHash2{
				Hash: hash.Hash.Hash,
				ID:   b.ids.insertID(hash.ID),
			})
		} else if hash.Hash.Kind == goimagehash.PHash {
			b.PHashes = append(b.PHashes, RuntimeHash2{
				Hash: hash.Hash.Hash,
				ID:   b.ids.insertID(hash.ID),
			})
		}

		if hash.ID == (ch.ID{}) {
			return ch.Metrics{}, fmt.Errorf("Empty ID detected: %v", hash)
		}
	}
	b.ids.SortIndex()

	hashCompact := func(existing, target RuntimeHash2) bool {
		return b.hashCmp(existing, target) == 0
	}
	// sort for lookup
	slices.SortFunc(b.AHashes, b.hashCmp)
	slices.SortFunc(b.DHashes, b.hashCmp)
	slices.SortFunc(b.PHashes, b.hashCmp)
	// remove duplicates
	b.AHashes = slices.CompactFunc(b.AHashes, hashCompact)
	b.DHashes = slices.CompactFunc(b.DHashes, hashCompact)
	b.PHashes = slices.CompactFunc(b.PHashes, hashCompact)

	count := ch.Metrics{
		Hashes: make(map[ch.Metric]int, 6),
	}
	var rhash RuntimeHash2
	for _, rhash = range b.AHashes {
		count.Hashes[ch.Metric{Source: b.ids.GetID(rhash.ID).Domain, Kind: goimagehash.AHash}] += 1
	}
	for _, rhash = range b.DHashes {
		count.Hashes[ch.Metric{Source: b.ids.GetID(rhash.ID).Domain, Kind: goimagehash.DHash}] += 1
	}
	for _, rhash = range b.PHashes {
		count.Hashes[ch.Metric{Source: b.ids.GetID(rhash.ID).Domain, Kind: goimagehash.PHash}] += 1
	}
	return count, nil
}

func (b *BasicMapStorage) hashCmp(existing, target RuntimeHash2) int {
	existingID := b.ids.GetID(existing.ID).CHID()
	return cmp.Or(
		cmp.Compare(existing.Hash, target.Hash),
		existingID.Compare(b.ids.GetID(target.ID).CHID()),
	)
}

func appendHashes(kind goimagehash.Kind, rhashes []RuntimeHash2, ids IDMap, savedHashes *ch.SavedHashes) {
	var rhash RuntimeHash2
	for _, rhash = range rhashes {
		savedHashes.Hashes = append(savedHashes.Hashes, ch.SavedHash{
			Hash: ch.Hash{
				Hash: rhash.Hash,
				Kind: kind,
			},
			ID: ids.GetID(rhash.ID).CHID(),
		})
	}
}

// EncodeHashes should already have a lock
func (b *BasicMapStorage) EncodeHashes() (*ch.SavedHashes, error) {
	savedHashes := ch.SavedHashes{
		Hashes: make([]ch.SavedHash, 0, len(b.AHashes)+len(b.DHashes)+len(b.PHashes)),
	}
	appendHashes(goimagehash.AHash, b.AHashes, b.ids, &savedHashes)
	appendHashes(goimagehash.DHash, b.DHashes, b.ids, &savedHashes)
	appendHashes(goimagehash.PHash, b.PHashes, b.ids, &savedHashes)

	// Only keep groups len>1 as they are mapped in SavedHashes.Hashes
	for _, ids := range b.ids.EquivalentIDs {
		if len(ids) > 1 {
			idl := make([]ch.ID, 0, len(ids))
			for _, rid := range ids {
				idl = append(idl, b.ids.GetID(rid).CHID())
			}

			savedHashes.IDs = append(savedHashes.IDs, idl)
		}
	}

	return &savedHashes, nil
}

func (b *BasicMapStorage) AssociateIDs(newids []ch.NewIDs) error {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	return b.ids.AssociateIDs(newids)
}

func (b *BasicMapStorage) GetIDs(id ch.ID) ch.IDList {
	b.hashMutex.RLock()
	defer b.hashMutex.RUnlock()
	rid, ok := b.ids.FindID(id)
	if !ok {
		return ch.IDList{}
	}
	return ch.ToIDList(b.ids.GetAllIDs(rid))
}

func NewBasicMapStorage() (ch.HashStorage, error) {
	storage := &BasicMapStorage{
		hashMutex: &sync.RWMutex{},
		ids: IDMap{
			ids: []ID{},
		},
		AHashes: []RuntimeHash2{},
		DHashes: []RuntimeHash2{},
		PHashes: []RuntimeHash2{},
	}
	return storage, nil
}
