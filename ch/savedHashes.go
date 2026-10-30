package ch

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"unsafe"

	"gitea.narnian.us/lordwelch/comic-hasher/log"
	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/zeebo/xxh3"
)

var DELogger = log.NewLogger("Decode/Encode")

const (
	Magic                            = "CHBF"
	CurrentSavedHashesVersion        = 3
	NoIDGroup                 uint32 = math.MaxUint32
	MaxIDLength                      = int(unsafe.Sizeof(SavedIDV3{}.ID))
	savedHashesV3HeaderSize          = int(unsafe.Sizeof(V3Header{}))
	savedHashV3Size                  = int(unsafe.Sizeof(SavedHashV3{})) // Hash uint64 + ID uint32 + 4 padding bytes
	savedIDV3Size                    = int(unsafe.Sizeof(SavedIDV3{}))   // Source byte + ID [32]byte + 3 padding bytes + Group uint32
)

var (
	ErrNoHashes       = errors.New("no hashes")
	ErrDecodeFail     = errors.New("failed to decode hashes")
	ErrIDNotFound     = errors.New("ID not found")
	ErrIDConflict     = errors.New("cannot associate two ID's in the same source")
	ErrTooManySources = errors.New("sorry we already have 256 Sources and we can't add any more")
	ErrSourceTooLong  = errors.New("sorry we cant handle source names longer than 128 characters")
)

type Metric struct {
	Source *Source
	Kind   goimagehash.Kind
}

type Metrics struct {
	Hashes map[Metric]int
}

type SavedHashesV2 struct {
	Version int
	IDs     [][]ID        // List of sets of IDs that are the same across Sources, should generally only have one Source per set
	Hashes  []SavedHashV2 // List of all known hashes, hashes will be duplicated for each source
}

type SavedHashV2 struct {
	ID   ID
	Hash Hash
}

// V3Header is stored verbatim at the beginning of a V3 hash file. The arrays
// that follow it are fixed size records so they can be used directly from the
// memory that was read from disk.
type V3Header struct {
	Magic      [4]byte
	Version    uint32
	Sources    [256][128]byte
	IDCount    uint32
	GroupCount uint32
	GroupBytes uint32 // size of the IDGroups section in bytes
	AHashCount uint32
	DHashCount uint32
	PHashCount uint32
	// TODO: decide on an option for later additions
}

// SavedHashesV3 is designed to be loaded from disk in-place and used during runtime
type SavedHashesV3 struct {
	V3Header
	Sources  []string
	AHashes  []SavedHashV3
	DHashes  []SavedHashV3
	PHashes  []SavedHashV3
	IDs      []SavedIDV3
	IDIndex  []uint32
	IDGroups [][]uint32 // This is a list of indexes into IDs. There can only be one id for a given source in a single group

	// IDGroups uses 1 KB per group (256*4) at 1 million groups that is 976 MB
	// Now we don't really have any groups but we could match them all to GCD data which would add all ~1 million
	// It doesn't seem to be possible to direct load from disk the in-memory representation
	// We can do a direct load for Hashes and IDs but IDGroups will have to be parsed in some way
	// as of 10/24/2026 ComicVine: 1_143_667, Metron: 186_718, GCD: 2_210_245

	// V3Header                              :  40 KB
	// Hashes   3_540_630 * 3 * 16           :  162 MB
	// IDs      3_540_630 * 32               :  108 MB
	// IDIndex  3_540_630 * 4                :   13 MB
	// IDGroups 1_143_667 * (4*256)          : 1116 MB
	// Total                                 : 1399 MB
	// IDGroups 1_143_667 * ((4*3)+24)       :   39 MB
	// Total (dynamic)                       :  322 MB

	// Current expected memory usage as ComicVine and metron are currently scraped
	// V3Header                              :  40 KB
	// Hashes   (1_143_667+186_718) * 3 * 16 :  60 MB
	// IDs      (1_143_667+186_718) * 32     :  40 MB
	// IDIndex  (1_143_667+186_718) * 4      :   5 MB
	// Total                                 : 105 MB
}

type SavedIDV3 struct {
	ID     [24]byte // ID is a string but for this use we need it to be sized. All known ID's are numbers so we have a maximum 32 digit number
	Pad    [2]byte
	IDLen  byte
	Source byte   // This is an index into Sources. We only support 256 different sources. There is no logical reason for this but it means that we have an exact size for the table
	Group  uint32 // This is an index into IDGroups. This should be NoIDGroup if there are no other ID's to group with this ID
	// IDs are usually 8 characters or less which means we waste ~22 MB
	// Technically Group will be mostly unused which will also waste ~4 MB but that will actually go down over time
}

func (s *SavedIDV3) IDString() string {
	return unsafe.String(&s.ID[0], int(s.IDLen))
}

type SavedHashV3 struct {
	Hash uint64
	ID   uint32 // index into IDs Go upgrades this value to a 8 byte aligned value no matter what due to the uint64 above. Note that IDIndex and IDGroups are where the space savings happens
	Pad  [4]byte
}

func (h SavedHashV3) Compare(o SavedHashV3) int {
	if h.Hash != o.Hash {
		if h.Hash < o.Hash {
			return -1
		}
		return 1
	}
	if h.ID != o.ID {
		if h.ID < o.ID {
			return -1
		}
		return 1
	}
	// This should be faster than a string compare
	a := uint32(h.Pad[0]) | uint32(h.Pad[1])<<8 | uint32(h.Pad[2])<<16 | uint32(h.Pad[3])<<24
	b := uint32(o.Pad[0]) | uint32(o.Pad[1])<<8 | uint32(o.Pad[2])<<16 | uint32(o.Pad[3])<<24
	if a != b {
		if a < b {
			return -1
		}
		return 1
	}
	return 0
}

func (s *SavedHashesV3) addSource(name string) error {
	if name == "" { // should never happen
		return nil
	}
	if len(name) > 128 {
		return ErrSourceTooLong
	}
	if slices.Contains(s.Sources, name) {
		return nil
	}
	i := len(s.Sources)
	if i > 255 {
		return ErrTooManySources
	}
	s.Sources = append(s.Sources, "")
	b := []byte(name)
	copy(s.V3Header.Sources[i][:], b)
	s.Sources[i] = unsafe.String(&s.V3Header.Sources[i][0], len(name))
	return nil
}

func UnsafeCString(b []byte, length ...int) string {
	if len(length) < 1 || length[0] < 1 || length[0] > len(b) {
		length = []int{bytes.IndexByte(b[:], 0)}
		if length[0] == -1 {
			length[0] = len(b)
		}
	}
	return unsafe.String(&b[0], length[0])
}

// Compact must not be called during operation
func (s *SavedHashesV3) Compact() {
	cmpSort := func(a, b SavedHashV3) int { return a.Compare(b) }
	cmpCompact := func(a, b SavedHashV3) bool { return a.Compare(b) == 0 }
	slices.SortFunc(s.AHashes, cmpSort)
	slices.SortFunc(s.DHashes, cmpSort)
	slices.SortFunc(s.PHashes, cmpSort)
	s.AHashes = slices.CompactFunc(s.AHashes, cmpCompact)
	s.DHashes = slices.CompactFunc(s.DHashes, cmpCompact)
	s.PHashes = slices.CompactFunc(s.PHashes, cmpCompact)
	s.SortIDs()
	// s.Sources can never realistically get a duplicate.
	// Technically associating IDs could add more sources that aren't used anywhere but I'll deal with that later

	// IDGroups should never have a duplicate as you can only belong to one group
	// but you can end up with un-used groups if you merge two previously un-related groups
	groupTranslation := make(map[uint32]uint32)
	groupTranslation[NoIDGroup] = NoIDGroup
	emptyGroups := 0
	for _, group := range s.IDGroups {
		if len(group) == 0 {
			emptyGroups += 1
		}
	}
	if emptyGroups > 0 {
		newGroups := make([][]uint32, 0, len(s.IDGroups)-emptyGroups)
		for i, group := range s.IDGroups {
			if len(group) == 0 { // This index shouldn't be used anymore anywhere so it should be safe to ignore
				continue
			}
			groupTranslation[uint32(i)] = uint32(len(newGroups))
			newGroups = append(newGroups, group)
		}
		var (
			ok       bool
			newGroup uint32
		)
		for i := range s.IDs {
			newGroup, ok = groupTranslation[s.IDs[i].Group]
			if !ok {
				panic(fmt.Errorf("error compacting groups: we have an unknown group in use here.... group: %v. Max used group %v -> %v", s.IDs[i].Group, len(s.IDGroups), len(newGroups)))
			}
			s.IDs[i].Group = newGroup
		}
		s.IDGroups = newGroups
	}
}

func (s *SavedHashesV3) SortIDs() {
	// old -> new map
	remap := make([]uint32, len(s.IDs))
	for newIdx, old := range s.IDIndex {
		remap[old] = uint32(newIdx)
	}

	// permute IDs in place by following cycles
	// IDIndex[j] == j marks a slot as placed, so IDIndex ends as the identity
	for i := range s.IDIndex {
		if s.IDIndex[i] == uint32(i) {
			continue
		}
		tmp := s.IDs[i]
		j := i
		for {
			k := int(s.IDIndex[j])
			s.IDIndex[j] = uint32(j)
			if k == i {
				s.IDs[j] = tmp
				break
			}
			s.IDs[j] = s.IDs[k]
			j = k
		}
	}

	// remap references to IDs
	for _, hashes := range [][]SavedHashV3{s.AHashes, s.DHashes, s.PHashes} {
		for i := range hashes {
			hashes[i].ID = remap[hashes[i].ID]
		}
	}
	for g := range s.IDGroups {
		for i, id := range s.IDGroups[g] {
			s.IDGroups[g][i] = remap[id]
		}
	}
}

func (s *SavedHashesV3) compareIndex(a uint32, b uint32) int {
	return cmp.Or(
		strings.Compare(s.Sources[s.IDs[a].Source], s.Sources[s.IDs[b].Source]),
		strings.Compare(s.IDs[a].IDString(), s.IDs[b].IDString()),
	)
}

func (s *SavedHashesV3) SortIndex() {
	if !slices.IsSortedFunc(s.IDIndex, s.compareIndex) {
		slices.SortFunc(s.IDIndex, s.compareIndex)
	}
}

func (s *SavedHashesV3) FindID(id ID) (uint32, bool) {
	index, found := slices.BinarySearchFunc(s.IDIndex, id, func(rid uint32, target ID) int {
		return cmp.Or(
			strings.Compare(s.Sources[s.IDs[rid].Source], string(*target.Domain)),
			strings.Compare(s.IDs[rid].IDString(), target.ID),
		)
	})
	if !found {
		return 0, false
	}
	return s.IDIndex[index], true
}

// InsertIDNoSort is the same as InsertID but does not sort the IDIndex. You must call SortIndex after this
func (s *SavedHashesV3) InsertIDNoSort(id ID) (uint32, error) {
	if id.Domain == nil {
		return 0, errors.New("cannot insert an ID without a source")
	}
	if len(id.ID) > MaxIDLength {
		return 0, fmt.Errorf("ID is longer than %d bytes: %q", MaxIDLength, id.ID)
	}
	if len(s.IDs) >= math.MaxUint32 {
		return 0, fmt.Errorf("sorry we already have 4,294,967,295 IDs and we can't add any more")
	}
	err := s.addSource(string(*id.Domain))
	if err != nil {
		return 0, err
	}
	target := SavedIDV3{
		Source: byte(slices.Index(s.Sources, string(*id.Domain))),
		Group:  NoIDGroup,
		IDLen:  byte(len(id.ID)),
	}
	copy(target.ID[:], id.ID)
	i, found := s.FindID(id)
	if found {
		return i, nil
	}
	i = uint32(len(s.IDs))
	s.IDs = append(s.IDs, target)
	s.IDIndex = append(s.IDIndex, i)
	s.IDCount = uint32(len(s.IDs))

	return i, nil
}

// InsertID returns the index of id, adding it to the ID table if needed.
func (s *SavedHashesV3) InsertID(id ID) (uint32, error) {
	i, err := s.InsertIDNoSort(id)
	if err != nil {
		return 0, err
	}
	s.SortIndex()

	return i, nil
}

// IDAt returns the ID stored at index.
func (s *SavedHashesV3) IDAt(index uint32) ID {
	stored := s.IDs[index]
	return ID{
		Domain: NewSource(s.Sources[stored.Source]),
		ID:     UnsafeCString(stored.ID[:], int(stored.IDLen)),
	} // Strings are read-only we can use unsafe here. We don't currently support removing an ID
}

// GetAllIDs returns all IDs equivalent to the ID at index.
func (s *SavedHashesV3) GetAllIDs(index uint32) []ID {
	// We can probably remove an operation or two here
	if index >= uint32(len(s.IDs)) {
		return nil
	}
	id := s.IDAt(index)
	group := s.IDs[index].Group
	if group == NoIDGroup || int(group) >= len(s.IDGroups) {
		return []ID{id}
	}
	groupIDs := s.IDGroups[group]
	if len(groupIDs) < 2 {
		return []ID{id}
	}
	ids := make([]ID, 0, len(groupIDs))
	for _, rid := range groupIDs {
		ids = append(ids, s.IDAt(rid))
	}
	return ids
}

// HashesForKind returns the sorted hash records for kind.
func (s *SavedHashesV3) HashesForKind(kind goimagehash.Kind) *[]SavedHashV3 {
	switch kind {
	case goimagehash.AHash:
		return &s.AHashes
	case goimagehash.DHash:
		return &s.DHashes
	case goimagehash.PHash:
		return &s.PHashes
	default:
		panic("Unknown hash type: " + kind.String())
	}
}

func (s *SavedHashesV3) findHash(kind goimagehash.Kind, hash uint64, id uint32) (int, bool) {
	hashes := s.HashesForKind(kind)
	target := SavedHashV3{Hash: hash, ID: id}
	index, found := slices.BinarySearchFunc(*hashes, target, func(a, b SavedHashV3) int {
		return a.Compare(b)
	})
	return index, found
}

// insertHashRecord inserts a hash record without looking up the ID.
func (s *SavedHashesV3) insertHashRecord(hash Hash, id uint32) bool {
	hashes := s.HashesForKind(hash.Kind)
	target := SavedHashV3{Hash: hash.Hash, ID: id}
	index, found := slices.BinarySearchFunc(*hashes, target, func(a, b SavedHashV3) int {
		return a.Compare(b)
	})
	if found {
		return false
	}
	*hashes = slices.Insert(*hashes, index, target)

	switch hash.Kind {
	case goimagehash.AHash:
		s.AHashCount += 1
	case goimagehash.DHash:
		s.DHashCount += 1
	case goimagehash.PHash:
		s.PHashCount += 1
	default:
		panic("Unknown hash type: " + hash.Kind.String())
	}

	return true
}

// InsertHash adds hash for id if it is not already present.
func (s *SavedHashesV3) InsertHash(hash Hash, id ID) bool {
	// TODO: should this return error???
	rid, err := s.InsertID(id)
	if err != nil {
		return false
	}
	_, existing := s.findHash(hash.Kind, hash.Hash, rid)
	if existing {
		return false
	}
	return s.insertHashRecord(hash, rid)
}

func (s *SavedHashesV3) AssociateIDs(OldID, NewID ID) error {
	if *NewID.Domain == *OldID.Domain {
		return fmt.Errorf("cannot associate two IDs in the same source")
	}
	oldIndex, found := s.FindID(OldID)
	if !found {
		return fmt.Errorf("old id %v: %w", OldID, ErrIDNotFound)
	}
	newIndex, found := s.FindID(NewID)
	if !found {
		return fmt.Errorf("new id %v: %w", NewID, ErrIDNotFound)
	}
	oldGroup := s.IDs[oldIndex].Group
	newGroup := s.IDs[newIndex].Group
	if oldGroup == NoIDGroup && newGroup == NoIDGroup {
		group := uint32(len(s.IDGroups))
		s.IDGroups = append(s.IDGroups, []uint32{oldIndex, newIndex})
		s.IDs[oldIndex].Group = group
		s.IDs[newIndex].Group = group
		return nil
	}
	if oldGroup == newGroup {
		return nil
	}
	// if NewID.Domain == metron: check that no metron exists in OldID's id list
	// if OldID.Domain == GCD: check that no gcd exists in NewID's id list
	if oldGroup == NoIDGroup {
		for _, rid := range s.IDGroups[newGroup] {
			if s.Sources[s.IDs[rid].Source] == string(*OldID.Domain) {
				return fmt.Errorf("ID %v is already matched to %v:%v. %w", NewID, s.Sources[s.IDs[rid].Source], UnsafeCString(s.IDs[rid].ID[:], int(s.IDs[rid].IDLen)), ErrIDConflict)
			}
		}
		s.IDGroups[newGroup] = append(s.IDGroups[newGroup], oldIndex)
		s.IDs[oldIndex].Group = newGroup
		return nil
	}
	if newGroup == NoIDGroup {
		for _, rid := range s.IDGroups[oldGroup] {
			if s.Sources[s.IDs[rid].Source] == string(*NewID.Domain) {
				return fmt.Errorf("ID %v is already matched to %v:%v. %w", OldID, s.Sources[s.IDs[rid].Source], UnsafeCString(s.IDs[rid].ID[:], int(s.IDs[rid].IDLen)), ErrIDConflict)
			}
		}
		s.IDGroups[oldGroup] = append(s.IDGroups[oldGroup], newIndex)
		s.IDs[newIndex].Group = oldGroup
		return nil
	}

	// newGroup and oldGroup both have an existing list
	for _, rid := range s.IDGroups[oldGroup] {
		if s.Sources[s.IDs[rid].Source] == string(*NewID.Domain) {
			return fmt.Errorf("ID %v is already matched to %v:%v. %w", OldID, s.Sources[s.IDs[rid].Source], UnsafeCString(s.IDs[rid].ID[:], int(s.IDs[rid].IDLen)), ErrIDConflict)
		}
	}
	for _, rid := range s.IDGroups[newGroup] {
		if s.Sources[s.IDs[rid].Source] == string(*OldID.Domain) {
			return fmt.Errorf("ID %v is already matched to %v:%v. %w", NewID, s.Sources[s.IDs[rid].Source], UnsafeCString(s.IDs[rid].ID[:], int(s.IDs[rid].IDLen)), ErrIDConflict)
		}
	}

	// if NewID(metron)  already equivalent to CV:123
	// and OldID(GCD) already equivalent to CV:456
	// return err
	for _, oldRID := range s.IDGroups[oldGroup] {
		oldSource := s.Sources[s.IDs[oldRID].Source]
		for _, newRID := range s.IDGroups[newGroup] {
			if oldSource == s.Sources[s.IDs[newRID].Source] {
				return fmt.Errorf(
					"new ID(%v) group contains (%v) and old ID(%v) group contains (%v). Cannot associate new ID(%v) to old ID(%v)",
					NewID, *s.IDAt(newRID).Domain,
					OldID, *s.IDAt(oldRID).Domain,
					NewID, OldID,
				)
			}
		}
	}
	// we've now validated that their are no conflicts so we need to merge and re-do everything
	s.IDGroups[newGroup] = append(s.IDGroups[newGroup], s.IDGroups[oldGroup]...)

	for _, rid := range s.IDGroups[oldGroup] {
		s.IDs[rid].Group = newGroup
	}
	s.IDGroups[oldGroup] = nil
	return nil
}

func (s *SavedHashesV3) Metrics() Metrics {
	nSources := len(s.Sources)
	count := Metrics{
		Hashes: make(map[Metric]int, 3*nSources),
	}
	if nSources == 1 {
		source := (*Source)(&s.Sources[0])
		count.Hashes[Metric{Source: source, Kind: goimagehash.AHash}] = len(s.AHashes)
		count.Hashes[Metric{Source: source, Kind: goimagehash.DHash}] = len(s.DHashes)
		count.Hashes[Metric{Source: source, Kind: goimagehash.PHash}] = len(s.PHashes)
		return count
	}

	// Compact ID→Source table: much smaller than s.IDs, so the random lookups stay in cache
	src := make([]uint32, len(s.IDs))
	for i := range s.IDs {
		src[i] = uint32(s.IDs[i].Source)
	}

	counts := make([]int, 3*nSources)
	aCounts := counts[:nSources:nSources]
	dCounts := counts[nSources : 2*nSources : 2*nSources]
	pCounts := counts[2*nSources:]
	var i int
	for i = range s.AHashes {
		aCounts[src[s.AHashes[i].ID]]++
	}
	for i = range s.DHashes {
		dCounts[src[s.DHashes[i].ID]]++
	}
	for i = range s.PHashes {
		pCounts[src[s.PHashes[i].ID]]++
	}

	for i := range nSources {
		source := (*Source)(&s.Sources[i])
		count.Hashes[Metric{Source: source, Kind: goimagehash.AHash}] = aCounts[i]
		count.Hashes[Metric{Source: source, Kind: goimagehash.DHash}] = dCounts[i]
		count.Hashes[Metric{Source: source, Kind: goimagehash.PHash}] = pCounts[i]
	}
	return count
}

// Sort restores the ordering required by the V3 format in place.
func (s *SavedHashesV3) Sort() {
	s.SortIndex()
	sortHashes := func(a, b SavedHashV3) int { return a.Compare(b) }
	if !slices.IsSortedFunc(s.AHashes, sortHashes) {
		slices.SortFunc(s.AHashes, sortHashes)
	}
	if !slices.IsSortedFunc(s.DHashes, sortHashes) {
		slices.SortFunc(s.DHashes, sortHashes)
	}
	if !slices.IsSortedFunc(s.PHashes, sortHashes) {
		slices.SortFunc(s.PHashes, sortHashes)
	}
	s.IDCount = uint32(len(s.IDs))
	s.GroupCount = uint32(len(s.IDGroups))
	s.AHashCount = uint32(len(s.AHashes))
	s.DHashCount = uint32(len(s.DHashes))
	s.PHashCount = uint32(len(s.PHashes))
}

func NewSavedHashesV3(hashes *SavedHashesV2) (*SavedHashesV3, error) {
	if hashes == nil || hashes.Hashes == nil {
		return nil, nil
	}
	b := &SavedHashesV3{
		Magic:   [4]byte([]byte(Magic)),
		Version: 3,
		IDs:     make([]SavedIDV3, 0, len(hashes.Hashes)/3),
	}

	slices.SortFunc(hashes.Hashes, func(existing, target SavedHashV2) int {
		return cmp.Or(
			strings.Compare(string(*existing.ID.Domain), string(*target.ID.Domain)), // Sorted for id insertion efficiency
			strings.Compare(existing.ID.ID, target.ID.ID),                           // Sorted for id insertion efficiency
			cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
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

	b.AHashes = make([]SavedHashV3, 0, aHashCount)
	b.DHashes = make([]SavedHashV3, 0, dHashCount)
	b.PHashes = make([]SavedHashV3, 0, pHashCount)
	var hash SavedHashV2
	for _, hash = range hashes.Hashes {
		// InsertIDNoSort is an append with extra checks it's fast enough for this purpose
		// Note that SortIndex must be called after these inserts it creates the IDIndex which is critical for operation
		id, err := b.InsertIDNoSort(hash.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to create V3 hashes: %w", err)
		}
		switch hash.Hash.Kind {
		case goimagehash.AHash:
			b.AHashes = append(b.AHashes, SavedHashV3{
				Hash: hash.Hash.Hash,
				ID:   id,
			})
		case goimagehash.DHash:
			b.DHashes = append(b.DHashes, SavedHashV3{
				Hash: hash.Hash.Hash,
				ID:   id,
			})
		case goimagehash.PHash:
			b.PHashes = append(b.PHashes, SavedHashV3{
				Hash: hash.Hash.Hash,
				ID:   id,
			})
		}

		if hash.ID == (ID{}) {
			return nil, fmt.Errorf("empty ID detected: %v", hash)
		}
	}

	b.SortIndex()

	for _, ids := range hashes.IDs {
		if len(ids) < 2 {
			continue
		}
		sources := make([]Source, 0, 256)
		eid := uint32(len(b.IDGroups))
		newGroup := make([]uint32, 0, len(ids))
		for _, id := range ids {
			if slices.Contains(sources, *id.Domain) {
				return nil, fmt.Errorf("you can only have a single id for a source in a group")
			}
			sources = append(sources, *id.Domain)
			rid, err := b.InsertID(id)
			if err != nil {
				return nil, fmt.Errorf("failed to insert ID when adding ID Groups: %w", err)
			}
			b.IDs[rid].Group = eid
			newGroup = append(newGroup, rid)
		}
		b.IDGroups = append(b.IDGroups, newGroup)
	}

	b.Compact()

	b.Sort()
	return b, nil
}

func writeSavedHashV3(w io.Writer, src []SavedHashV3) error {
	var rec [savedHashV3Size]byte
	for i := range src {
		binary.LittleEndian.PutUint64(rec[:], src[i].Hash)
		binary.LittleEndian.PutUint32(rec[8:], src[i].ID)
		if _, err := w.Write(rec[:]); err != nil {
			return err
		}
	}
	return nil
}

func writeSavedIDsV3(w io.Writer, src []SavedIDV3) error {
	var rec [savedIDV3Size]byte
	for i := range src {
		copy(rec[0:24], src[i].ID[:])
		copy(rec[24:26], src[i].Pad[:])
		rec[26] = src[i].IDLen
		rec[27] = src[i].Source
		binary.LittleEndian.PutUint32(rec[28:32], src[i].Group)
		if _, err := w.Write(rec[:32]); err != nil {
			return err
		}
	}
	return nil
}

// EncodeHashesV3 serializes hashes in the V3 binary format. w should be buffered.
func EncodeHashesV3(hashes *SavedHashesV3, w io.Writer) error {
	if hashes == nil {
		return errors.New("cannot encode nil hashes")
	}
	hashes.Compact()
	hashes.Sort()
	if hashes.AHashCount != uint32(len(hashes.AHashes)) ||
		hashes.DHashCount != uint32(len(hashes.DHashes)) ||
		hashes.PHashCount != uint32(len(hashes.PHashes)) ||
		hashes.IDCount != uint32(len(hashes.IDs)) ||
		hashes.GroupCount != uint32(len(hashes.IDGroups)) {
		DELogger.Log(log.Verbose, "hash and ID counts do not match, this means there's probably a bug somewhere")
	}
	// This is the only way to enforce at compiletime that every field is explicitly filled out
	// If you use named fields it allows you to omit fields
	hashes.V3Header = V3Header{
		[4]byte([]byte(Magic)),
		CurrentSavedHashesVersion,
		hashes.V3Header.Sources,
		uint32(len(hashes.IDs)),
		uint32(len(hashes.IDGroups)),
		0,
		uint32(len(hashes.AHashes)),
		uint32(len(hashes.DHashes)),
		uint32(len(hashes.PHashes)),
	}

	for _, group := range hashes.IDGroups {
		hashes.GroupBytes += 1 + uint32(binary.Size(group))
	}

	err := binary.Write(w, binary.LittleEndian, hashes.V3Header)
	if err != nil {
		return err
	}

	var (
		sum [16]byte
		h   = xxh3.New()
		hw  = io.MultiWriter(w, h)
	)
	writeSum := func() error {
		sum = h.Sum128().Bytes()
		h.Reset()
		_, err := w.Write(sum[:])
		return err
	}

	err = writeSavedHashV3(hw, hashes.AHashes)
	if err != nil {
		return err
	}
	err = writeSum()
	if err != nil {
		return err
	}

	err = writeSavedHashV3(hw, hashes.DHashes)
	if err != nil {
		return err
	}
	err = writeSum()
	if err != nil {
		return err
	}

	err = writeSavedHashV3(hw, hashes.PHashes)
	if err != nil {
		return err
	}
	err = writeSum()
	if err != nil {
		return err
	}

	err = writeSavedIDsV3(hw, hashes.IDs)
	if err != nil {
		return err
	}
	err = writeSum()
	if err != nil {
		return err
	}

	var u [4]byte
	for _, group := range hashes.IDGroups {
		if _, err := hw.Write([]byte{byte(len(group))}); err != nil {
			return err
		}
		for _, id := range group {
			binary.LittleEndian.PutUint32(u[:], id)
			if _, err := hw.Write(u[:]); err != nil {
				return err
			}
		}
	}
	return writeSum()
}

// countingReader counts the bytes read through it so a truncated file can
// report how much of its declared size was present.
type countingReader struct {
	r io.Reader
	n int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}

func readSavedHashesV3(r io.Reader, dst []SavedHashV3) error {
	// Even though this is "safe" we re-use the allocated array so we don't waste time copying
	// This should never cause a problem
	if len(dst) == 0 {
		return nil
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&dst[0])), len(dst)*savedHashV3Size)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	var rec []byte
	for i := range dst {
		// So we are using the slice of SavedHashV3 as the buffer so normally we would need to do some math
		// to get the appropriate byte offset but the struct includes all padding so we can just iterate on the typed
		// slice and get it's offset from a pointer to the current item
		rec = unsafe.Slice((*byte)(unsafe.Pointer(&dst[i])), savedHashV3Size)
		dst[i].Hash = binary.LittleEndian.Uint64(rec[:8])
		dst[i].ID = binary.LittleEndian.Uint32(rec[8:12])
		copy(dst[i].Pad[:], rec[12:savedHashV3Size])
	}
	return nil
}

func readSavedIDsV3(r io.Reader, dst []SavedIDV3) error {
	// Even though this is "safe" we re-use the allocated array so we don't waste time copying
	// This should never cause a problem
	var rec []byte
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&dst[0])), len(dst)*savedIDV3Size)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	for i := range dst {
		// We are using the slice of SavedIDV3 as the buffer so normally we would need to do some math
		// to get the appropriate byte offset but the struct includes all padding so we can just iterate on the typed
		// slice and get it's offset from a pointer to the current item
		rec = unsafe.Slice((*byte)(unsafe.Pointer(&dst[i])), savedIDV3Size)
		copy(dst[i].ID[:], rec[0:24])
		copy(dst[i].Pad[:], rec[24:26])
		dst[i].IDLen = rec[26]
		dst[i].Source = rec[27]
		dst[i].Group = binary.LittleEndian.Uint32(rec[28:32])
	}
	return nil
}

func readSavedGroup(group []uint32) {
	// We use the []uint32 as the []byte when reading it in so we don't waste a copy
	// Here we just re-interpret them as little endian uint32s
	b := unsafe.Slice((*byte)(unsafe.Pointer(&group[0])), len(group)*int(unsafe.Sizeof(uint32(0))))
	for j := range group {
		group[j] = binary.LittleEndian.Uint32(b[j*4:])
	}
}

var SafeOnly = false

// DecodeHashesV3 reads the V3 binary format. r should be buffered.
func DecodeHashesV3(r io.Reader) (*SavedHashesV3, error) {
	if r == nil {
		return nil, ErrNoHashes
	}
	hashes := SavedHashesV3{}
	cr := &countingReader{r: r}
	var err error

	err = binary.Read(cr, binary.LittleEndian, &hashes.V3Header)
	if err != nil {
		return nil, err
	}
	if string(hashes.Magic[:]) != Magic {
		return nil, fmt.Errorf("%w: not a CHBF file", ErrDecodeFail)
	}
	if !(hashes.Version == 3 || hashes.Version == 4) {
		return nil, fmt.Errorf("%w: unsupported saved hashes version: %d", ErrDecodeFail, hashes.V3Header.Version)
	}
	totalExpectedSize := savedHashesV3HeaderSize

	if cr.n != totalExpectedSize {
		return nil, fmt.Errorf("%w: truncated header: read %d bytes, expected %d bytes", ErrDecodeFail, cr.n, totalExpectedSize)
	}
	if hashes.GroupCount > hashes.IDCount {
		DELogger.Log(log.Verbose, "We have more groups than ID's this shouldn't happen: %d ID groups for %d IDs", hashes.GroupCount, hashes.IDCount)
	}

	for i := range hashes.V3Header.Sources {
		if hashes.V3Header.Sources[i][0] == 0 {
			break
		}
		hashes.Sources = append(hashes.Sources, UnsafeCString(hashes.V3Header.Sources[i][:]))
	}

	truncated := func(err error) error {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: truncated saved hashes: read %d bytes: %w", ErrDecodeFail, cr.n, err)
		}
		return fmt.Errorf("%w: %w", ErrDecodeFail, err)
	}

	h := xxh3.New()
	tr := io.TeeReader(cr, h)
	checkSum := func(name string) error {
		var fileHash [16]byte
		if _, err := io.ReadFull(cr, fileHash[:]); err != nil {
			return truncated(err)
		}
		if sum := h.Sum128().Bytes(); sum != fileHash {
			return fmt.Errorf("%s failed validation. Refusing to load hashes: %#x != %#x", name, sum, fileHash)
		}
		h.Reset()
		return nil
	}

	// Allocate an extra 10% so we don't immediately copy the entire list of hashes
	hashes.AHashes = make([]SavedHashV3, hashes.AHashCount, int(float64(hashes.AHashCount)*1.1))
	hashes.DHashes = make([]SavedHashV3, hashes.DHashCount, int(float64(hashes.DHashCount)*1.1))
	hashes.PHashes = make([]SavedHashV3, hashes.PHashCount, int(float64(hashes.PHashCount)*1.1))

	if err = readSavedHashesV3(tr, hashes.AHashes); err != nil {
		return nil, truncated(err)
	}
	if err = checkSum("average hashes"); err != nil {
		return nil, err
	}
	totalExpectedSize += len(hashes.AHashes)*savedHashV3Size + 16

	if err = readSavedHashesV3(tr, hashes.DHashes); err != nil {
		return nil, truncated(err)
	}
	if err = checkSum("difference hashes"); err != nil {
		return nil, err
	}
	totalExpectedSize += len(hashes.DHashes)*savedHashV3Size + 16

	if err = readSavedHashesV3(tr, hashes.PHashes); err != nil {
		return nil, truncated(err)
	}
	if err = checkSum("perceptual hashes"); err != nil {
		return nil, err
	}
	totalExpectedSize += len(hashes.PHashes)*savedHashV3Size + 16

	hashes.IDs = make([]SavedIDV3, hashes.IDCount, int(float64(hashes.IDCount)*1.1))
	hashes.IDIndex = make([]uint32, hashes.IDCount, int(float64(hashes.IDCount)*1.1))
	for i := range hashes.IDCount {
		hashes.IDIndex[i] = i
	}
	idsSize := len(hashes.IDs)*savedIDV3Size + 16
	if err = readSavedIDsV3(tr, hashes.IDs); err != nil {
		return nil, truncated(err)
	}
	if err = checkSum("IDs"); err != nil {
		return nil, err
	}
	totalExpectedSize += idsSize

	hashes.IDGroups = make([][]uint32, hashes.GroupCount)
	var b [1]byte
	for i := range hashes.IDGroups {
		if _, err = io.ReadFull(tr, b[:]); err != nil {
			return nil, truncated(err)
		}
		n := int(b[0])
		if n == 0 {
			n = 256
		}
		group := make([]uint32, n)
		b := unsafe.Slice((*byte)(unsafe.Pointer(&group[0])), n*int(unsafe.Sizeof(uint32(0))))
		if _, err = io.ReadFull(tr, b); err != nil {
			return nil, truncated(err)
		}
		readSavedGroup(group)
		hashes.IDGroups[i] = group
	}
	if err = checkSum("ID Groups"); err != nil {
		return nil, err
	}
	totalExpectedSize += int(hashes.GroupBytes) + 16
	if cr.n != totalExpectedSize {
		return nil, fmt.Errorf("%w: truncated ID Groups: read %d bytes, expected %d bytes: missing %d bytes", ErrDecodeFail, cr.n, totalExpectedSize, totalExpectedSize-cr.n)
	}
	hashes.Sort()
	return &hashes, nil
}
