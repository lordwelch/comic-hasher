package ch

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gitea.narnian.us/lordwelch/comic-hasher/log"

	// json "github.com/goccy/go-json"
	json "github.com/json-iterator/go"
	// "encoding/json"

	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/vmihailenco/msgpack/v5"
)

var DELogger = log.NewLogger("Decode/Encode")

type Format int

const (
	Msgpack Format = iota + 1
	JSON

	CurrentSavedHashesVersion int = 2
)

var versionMap = map[int]versionDecoder{
	0: DecodeHashesV0,
	1: DecodeHashesV1,
	2: DecodeHashesV2,
}

var formatNames = map[Format]string{
	JSON:    "json",
	Msgpack: "msgpack",
}

var formatValues = map[string]Format{
	"json":    JSON,
	"msgpack": Msgpack,
}

type (
	OldSavedHashes map[Source]map[string][3]uint64
	SavedHashesv1  struct {
		IDs    [][]ID
		Hashes [3]map[uint64]int
	}
)

type Metric struct {
	Source *Source
	Kind   goimagehash.Kind
}

type Metrics struct {
	Hashes map[Metric]int
	// IDs map[*Source]int
}

// SavedHashesV2 The IDs and Hashes fields have no direct correlation
// It is perfectly valid to have an empty IDs or an empty Hashes field
// If two covers have identical hashes then they should be two entries in Hashes not a set in IDs with two IDs from the same source
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

	// V3Header                       :  40 KB
	// Hashes   3_540_630 * 3 * 16    :  162 MB
	// IDs      3_540_630 * 40        :  135 MB
	// IDIndex  3_540_630 * 4         :   13 MB
	// IDGroups 3_540_630 * (4*256)   : 3457 MB
	// IDGroups 3_540_630 * ((4*3)+24):  121 MB
	// Total                          : 3767 MB
	// Total (dynamic)                :  431 MB
}

type SavedIDV3 struct {
	Source byte     // This is an index into Sources. We only support 256 different sources. There is no logical reason for this but it means that we have an exact size for the table
	ID     [32]byte // ID is a string but for this use we need it to be sized. All known ID's are numbers so we have a maximum 32 digit number
	_      byte     // Go Automatically adds padding here
	_      byte
	_      byte
	Group  uint32 // This is an index into IDGroups. This should be math.MaxUint32 if there are no other ID's to group with this ID
	// IDs are usually 8 characters or less which means we waste ~22 MB
	// Technically Group will be mostly unused which will also waste ~4 MB but that will actually go down over time
}

type SavedHashV3 struct {
	Hash uint64
	ID   uint32 // index into IDs Go upgrades this value to a 8 byte aligned value no matter what due to the uint64 above
	_    byte
	_    byte
	_    byte
	_    byte
}

type (
	Encoder        func(any) ([]byte, error)
	Decoder        func([]byte, any) error
	versionDecoder func(Decoder, []byte) (*SavedHashesV2, error)
)

var (
	ErrNoHashes   = errors.New("no hashes")
	ErrDecodeFail = errors.New("decoder failure")
)

func (f Format) String() string {
	if name, known := formatNames[f]; known {
		return name
	}
	return "Unknown"
}

func (f *Format) Set(s string) error {
	if format, known := formatValues[strings.ToLower(s)]; known {
		*f = format
	} else {
		return fmt.Errorf("unknown format: %d", f)
	}
	return nil
}

func (h *SavedHashV2) Clone() SavedHashV2 {
	return SavedHashV2{
		Hash: Hash{
			Hash: h.Hash.Hash,
			Kind: h.Hash.Kind,
		},
		ID: ID{
			Domain: NewSource(*h.ID.Domain),
			ID:     Clone(h.ID.ID),
		},
	}
}

func (s *SavedHashesV2) InsertHash(hash SavedHashV2) {
	index, itemFound := slices.BinarySearchFunc(s.Hashes, hash, func(existing SavedHashV2, target SavedHashV2) int {
		return cmp.Or(
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
			cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
			cmp.Compare(*existing.ID.Domain, *target.ID.Domain),
			cmp.Compare(existing.ID.ID, target.ID.ID),
		)
	})
	if !itemFound {
		s.Hashes = slices.Insert(s.Hashes, index, hash)
	}
}

func ConvertHashesV0(oldHashes OldSavedHashes) *SavedHashesV2 {
	t := SavedHashesV2{}
	idcount := 0
	for _, ids := range oldHashes {
		idcount += len(ids)
	}
	t.Hashes = make([]SavedHashV2, 0, idcount)
	for domain, sourceHashes := range oldHashes {
		for id, hashes := range sourceHashes {
			for hashType, hash := range hashes {
				t.Hashes = append(t.Hashes, SavedHashV2{
					Hash: Hash{
						Kind: goimagehash.Kind(hashType + 1),
						Hash: hash,
					},
					ID: ID{NewSource(domain), id},
				})
			}
		}
	}
	DELogger.Println(log.Verbose, "Length of hashes", len(t.Hashes))
	DELogger.Println(log.Verbose, "Length of ID lists", len(t.IDs))
	return &t
}

func ConvertHashesV1(oldHashes SavedHashesv1) *SavedHashesV2 {
	t := SavedHashesV2{}
	hashCount := 0
	for _, hashes := range oldHashes.Hashes {
		hashCount += len(hashes)
	}
	t.IDs = oldHashes.IDs
	t.Hashes = make([]SavedHashV2, 0, hashCount)
	for hashType, sourceHashes := range oldHashes.Hashes {
		for hash, index := range sourceHashes {
			for _, id := range oldHashes.IDs[index] {
				t.Hashes = append(t.Hashes, SavedHashV2{
					ID: ID{NewSource(*id.Domain), id.ID},
					Hash: Hash{
						Kind: goimagehash.Kind(hashType + 1),
						Hash: hash,
					},
				})
			}
		}
	}
	DELogger.Println(log.Verbose, "Length of hashes", len(t.Hashes))
	DELogger.Println(log.Verbose, "Length of ID lists", len(t.IDs))
	return &t
}

func DecodeHashesV0(decode Decoder, hashes []byte) (*SavedHashesV2, error) {
	DELogger.Println(log.Debug, "Attempting to decode v0 hashes")
	loadedHashes := OldSavedHashes{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeFail, err)
	}
	if len(loadedHashes) == 0 {
		return nil, ErrNoHashes
	}
	DELogger.Println(log.Standard, "Loading V0 hashes")
	return ConvertHashesV0(loadedHashes), nil
}

func DecodeHashesV1(decode Decoder, hashes []byte) (*SavedHashesV2, error) {
	DELogger.Println(log.Debug, "Attempting to decode v1 hashes")
	loadedHashes := SavedHashesv1{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeFail, err)
	}
	hashesCount := 0
	for _, hashes := range loadedHashes.Hashes {
		hashesCount += len(hashes)
	}
	if hashesCount < 1 {
		return nil, ErrNoHashes
	}
	DELogger.Println(log.Standard, "Loading V1 hashes")
	return ConvertHashesV1(loadedHashes), nil
}

func DecodeHashesV2(decode Decoder, hashes []byte) (*SavedHashesV2, error) {
	DELogger.Println(log.Debug, "Attempting to decode v2 hashes")
	loadedHashes := SavedHashesV2{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeFail, err)
	}
	if len(loadedHashes.Hashes) < 1 && len(loadedHashes.IDs) < 1 {
		return nil, ErrNoHashes
	}

	DELogger.Println(log.Verbose, "Loading V2 hashes")
	DELogger.Println(log.Verbose, "Length of hashes", len(loadedHashes.Hashes))
	DELogger.Println(log.Verbose, "Length of ID lists", len(loadedHashes.IDs))
	return &loadedHashes, nil
}

func getSavedHashesVersion(decode Decoder, hashes []byte) (int, error) {
	type version struct {
		Version int
	}
	DELogger.Println(log.Debug, "Attempting to decode saved hashes version")
	var savedVersion version
	err := decode(hashes, &savedVersion)
	if err != nil {
		DELogger.Log(log.Verbose2, "Failed to decode saved hashes version: %v", err)
		return -1, fmt.Errorf("%w: %w", ErrDecodeFail, err)
	}
	if savedVersion.Version > 1 {
		DELogger.Log(log.Verbose2, "Decoded saved hashes version: %v", savedVersion.Version)
		return savedVersion.Version, nil
	}
	return -1, nil
}

func DecodeHashes(format Format, hashes []byte) (*SavedHashesV2, error) {
	if len(hashes) < 18 { // keys in ch.SavedHashes are 18 characters even with no values so if it's less than that we don't have anything to load
		return nil, ErrNoHashes
	}
	var decode Decoder
	switch format {
	case Msgpack:
		decode = msgpack.Unmarshal
		DELogger.Println(log.Verbose, "Decode Msgpack")
	case JSON:
		decode = json.Unmarshal
		DELogger.Println(log.Verbose, "Decode JSON")
		if len(hashes) < 1 || hashes[0] != '{' {
			return nil, ErrDecodeFail
		}

	default:
		return nil, fmt.Errorf("unknown format: %v", format)
	}
	version, err := getSavedHashesVersion(decode, hashes)
	if err != nil {
		return nil, err
	}

	if decodeVersion, knownVersion := versionMap[version]; knownVersion {
		return decodeVersion(decode, hashes)
	}

	for _, decodeVersion := range []versionDecoder{
		DecodeHashesV0,
		DecodeHashesV1,
		DecodeHashesV2,
	} {
		loadedHashes, err := decodeVersion(decode, hashes)
		if err == nil {
			return loadedHashes, nil
		}
	}

	return nil, ErrNoHashes
}

func EncodeHashes(hashes *SavedHashesV2, format Format) ([]byte, error) {
	var encoder Encoder
	switch format {
	case Msgpack:
		encoder = msgpack.Marshal
	case JSON:
		encoder = json.Marshal
	default:
		return nil, fmt.Errorf("unknown format: %v", format)
	}
	hashes.Version = CurrentSavedHashesVersion
	return encoder(hashes)
}
