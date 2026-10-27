package main

import (
	"fmt"
	"unsafe"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
	"gitea.narnian.us/lordwelch/goimagehash"

	json "github.com/json-iterator/go"
	"github.com/vmihailenco/msgpack/v5"
)

var DELogger = log.NewLogger("Convert")

// Decoder is the function used to decode a saved hashes blob into a value.
type Decoder func([]byte, any) error

type versionDecoder func(Decoder, []byte) (*ch.SavedHashesV2, error)

var versionMap = map[int]versionDecoder{
	0: DecodeHashesV0,
	1: DecodeHashesV1,
	2: DecodeHashesV2,
}

// OldSavedHashes is the V0 in-memory representation of the saved hashes.
type OldSavedHashes map[ch.Source]map[string][3]uint64

// SavedHashesv1 is the V1 in-memory representation of the saved hashes.
type SavedHashesv1 struct {
	IDs    [][]ch.ID
	Hashes [3]map[uint64]int
}

func ConvertHashesV0(oldHashes OldSavedHashes) *ch.SavedHashesV2 {
	t := ch.SavedHashesV2{}
	idcount := 0
	for _, ids := range oldHashes {
		idcount += len(ids)
	}
	t.Hashes = make([]ch.SavedHashV2, 0, idcount)
	for domain, sourceHashes := range oldHashes {
		for id, hashes := range sourceHashes {
			for hashType, hash := range hashes {
				t.Hashes = append(t.Hashes, ch.SavedHashV2{
					Hash: ch.Hash{
						Kind: goimagehash.Kind(hashType + 1),
						Hash: hash,
					},
					ID: ch.ID{Domain: ch.NewSource(domain), ID: id},
				})
			}
		}
	}
	DELogger.Println(log.Verbose, "Length of hashes", len(t.Hashes))
	DELogger.Println(log.Verbose, "Length of ID lists", len(t.IDs))
	return &t
}

func ConvertHashesV1(oldHashes SavedHashesv1) *ch.SavedHashesV2 {
	t := ch.SavedHashesV2{}
	hashCount := 0
	for _, hashes := range oldHashes.Hashes {
		hashCount += len(hashes)
	}
	t.IDs = oldHashes.IDs
	t.Hashes = make([]ch.SavedHashV2, 0, hashCount)
	for hashType, sourceHashes := range oldHashes.Hashes {
		for hash, index := range sourceHashes {
			for _, id := range oldHashes.IDs[index] {
				t.Hashes = append(t.Hashes, ch.SavedHashV2{
					ID: ch.ID{Domain: id.Domain, ID: id.ID},
					Hash: ch.Hash{
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

func DecodeHashesV0(decode Decoder, hashes []byte) (*ch.SavedHashesV2, error) {
	DELogger.Println(log.Debug, "Attempting to decode v0 hashes")
	loadedHashes := OldSavedHashes{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ch.ErrDecodeFail, err)
	}
	if len(loadedHashes) == 0 {
		return nil, ch.ErrNoHashes
	}
	DELogger.Println(log.Standard, "Loading V0 hashes")
	return ConvertHashesV0(loadedHashes), nil
}

func DecodeHashesV1(decode Decoder, hashes []byte) (*ch.SavedHashesV2, error) {
	DELogger.Println(log.Debug, "Attempting to decode v1 hashes")
	loadedHashes := SavedHashesv1{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ch.ErrDecodeFail, err)
	}
	hashesCount := 0
	for _, hashes := range loadedHashes.Hashes {
		hashesCount += len(hashes)
	}
	if hashesCount < 1 {
		return nil, ch.ErrNoHashes
	}
	DELogger.Println(log.Standard, "Loading V1 hashes")
	return ConvertHashesV1(loadedHashes), nil
}

func DecodeHashesV2(decode Decoder, hashes []byte) (*ch.SavedHashesV2, error) {
	DELogger.Println(log.Debug, "Attempting to decode v2 hashes")
	loadedHashes := ch.SavedHashesV2{}
	err := decode(hashes, &loadedHashes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ch.ErrDecodeFail, err)
	}
	if len(loadedHashes.Hashes) < 1 && len(loadedHashes.IDs) < 1 {
		return nil, ch.ErrNoHashes
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
		return -1, fmt.Errorf("%w: %w", ch.ErrDecodeFail, err)
	}
	if savedVersion.Version > 1 {
		DELogger.Log(log.Verbose2, "Decoded saved hashes version: %v", savedVersion.Version)
		return savedVersion.Version, nil
	}
	return -1, nil
}

// DecodeOldHashes decodes a V0, V1, or V2 saved hashes blob into a
// SavedHashesV2. The format is detected (msgpack or json) and the version is
// used to pick the old decoder.
func DecodeOldHashes(hashes []byte) (*ch.SavedHashesV2, error) {
	if len(hashes) < 18 { // keys in ch.SavedHashes are 18 characters even with no values so if it's less than that we don't have anything to load
		return nil, ch.ErrNoHashes
	}
	var decode Decoder
	if len(hashes) > 0 && hashes[0] == '{' {
		decode = json.Unmarshal
		DELogger.Println(log.Verbose, "Decode JSON")
	} else {
		decode = msgpack.Unmarshal
		DELogger.Println(log.Verbose, "Decode Msgpack")
	}

	version, err := getSavedHashesVersion(decode, hashes)
	if err != nil {
		DELogger.Log(log.Verbose2, "Failed to decode saved hashes version: %v", err)
		version = -1
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

	return nil, ch.ErrNoHashes
}
func ReinterpretSlice[A, B any](s []A) []B {
	if len(s) == 0 {
		return nil
	}
	// Calculate total byte size and re-use the same backing memory
	return unsafe.Slice((*B)(unsafe.Pointer(&s[0])), len(s))
}
