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
