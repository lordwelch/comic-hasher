package ch

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/vmihailenco/msgpack"
)

type Format int

const (
	Msgpack Format = iota + 1
	JSON

	CurrentSavedHashesVersion int = 2
)

var versionMap map[int]versionDecoder

var formatNames = map[Format]string{
	JSON:    "json",
	Msgpack: "msgpack",
}

var formatValues = map[string]Format{
	"json":    JSON,
	"msgpack": Msgpack,
}

type OldSavedHashes map[Source]map[string][3]uint64
type SavedHashesv1 struct {
	IDs    [][]ID
	Hashes [3]map[uint64]int
}

// SavedHashes The IDs and Hashes fields have no direct correlation
// It is perfectly valid to have an empty IDs or an empty Hashes field
// If two covers have identical hashes then they should be two entries in Hashes not a set in IDs with two IDs from the same source
type SavedHashes struct {
	Version int
	IDs     [][]ID      // List of sets of IDs that are the same across Sources, should generally only have one Source per set
	Hashes  []SavedHash // List of all known hashes, hashes will be duplicated for each source
}

type SavedHash struct {
	Hash Hash
	ID   ID
}
type Encoder func(any) ([]byte, error)
type Decoder func([]byte, interface{}) error
type versionDecoder func(Decoder, []byte) (*SavedHashes, error)

var NoHashes = errors.New("no hashes")
var DecodeError = errors.New("decoder failure")

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
		return fmt.Errorf("Unknown format: %d", f)
	}
	return nil
}

func (s *SavedHashes) InsertHash(hash SavedHash) {
	index, itemFound := slices.BinarySearchFunc(s.Hashes, hash, func(existing SavedHash, target SavedHash) int {
		return cmp.Or(
			cmp.Compare(existing.Hash.Hash, target.Hash.Hash),
			cmp.Compare(existing.Hash.Kind, target.Hash.Kind),
			cmp.Compare(existing.ID.Domain, target.ID.Domain),
			cmp.Compare(existing.ID.ID, target.ID.ID),
		)
	})
	if !itemFound {
		s.Hashes = slices.Insert(s.Hashes, index, hash)
	}
}

func ConvertHashesV0(oldHashes OldSavedHashes) *SavedHashes {
	t := SavedHashes{}
	idcount := 0
	for _, ids := range oldHashes {
		idcount += len(ids)
	}
	t.IDs = make([][]ID, 0, idcount)
	t.Hashes = make([]SavedHash, 0, idcount)
	for domain, sourceHashes := range oldHashes {
		for id, hashes := range sourceHashes {
			t.IDs = append(t.IDs, []ID{{domain, id}})
			for hashType, hash := range hashes {
				t.Hashes = append(t.Hashes, SavedHash{
					Hash: Hash{
						Kind: goimagehash.Kind(hashType + 1),
						Hash: hash,
					},
					ID: ID{domain, id},
				})
			}
		}
	}
	fmt.Println("length of hashes", len(t.Hashes))
	fmt.Println("Length of ID lists", len(t.IDs))
	return &t
}

func ConvertHashesV1(oldHashes SavedHashesv1) *SavedHashes {
	t := SavedHashes{}
	hashCount := 0
	for _, hashes := range oldHashes.Hashes {
		hashCount += len(hashes)
	}
	t.IDs = oldHashes.IDs
	t.Hashes = make([]SavedHash, 0, hashCount)
	for hashType, sourceHashes := range oldHashes.Hashes {
		for hash, index := range sourceHashes {
			for _, id := range oldHashes.IDs[index] {
				t.Hashes = append(t.Hashes, SavedHash{
					ID: id,
					Hash: Hash{
						Kind: goimagehash.Kind(hashType + 1),
						Hash: hash,
					},
				})
			}
		}
	}
	fmt.Println("length of hashes", len(t.Hashes))
	fmt.Println("Length of ID lists", len(t.IDs))
	return &t
}

func DecodeHashesV0(decode Decoder, hashes []byte) (*SavedHashes, error) {
	loadedHashes := OldSavedHashes{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", DecodeError, err)
	}
	if len(loadedHashes) == 0 {
		return nil, NoHashes
	}
	return ConvertHashesV0(loadedHashes), nil
}

func DecodeHashesV1(decode Decoder, hashes []byte) (*SavedHashes, error) {
	loadedHashes := SavedHashesv1{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", DecodeError, err)
	}
	hashesCount := 0
	for _, hashes := range loadedHashes.Hashes {
		hashesCount += len(hashes)
	}
	if hashesCount < 1 {
		return nil, NoHashes
	}
	return ConvertHashesV1(loadedHashes), nil
}

func DecodeHashesV2(decode Decoder, hashes []byte) (*SavedHashes, error) {
	loadedHashes := SavedHashes{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", DecodeError, err)
	}
	if len(loadedHashes.Hashes) < 1 && len(loadedHashes.IDs) < 1 {
		return nil, NoHashes
	}

	return &loadedHashes, nil
}

func getSavedHashesVersion(decode Decoder, hashes []byte) (int, error) {
	type version struct {
		Version int
	}
	var savedVersion version
	err := decode(hashes, &savedVersion)
	if err != nil {
		return -1, fmt.Errorf("%w: %w", DecodeError, err)
	}
	if savedVersion.Version > 1 {
		return savedVersion.Version, nil
	}
	return -1, nil
}
func DecodeHashes(format Format, hashes []byte) (*SavedHashes, error) {
	var decode Decoder
	switch format {
	case Msgpack:
		decode = msgpack.Unmarshal
	case JSON:
		decode = json.Unmarshal

	default:
		return nil, fmt.Errorf("Unknown format: %v", format)
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

	return nil, NoHashes
}

func EncodeHashes(hashes SavedHashes, format Format) ([]byte, error) {
	var encoder Encoder
	switch format {
	case Msgpack:
		encoder = msgpack.Marshal
	case JSON:
		encoder = json.Marshal
	default:
		return nil, fmt.Errorf("Unknown format: %v", format)
	}

	hashes.Version = CurrentSavedHashesVersion
	return encoder(hashes)
}
