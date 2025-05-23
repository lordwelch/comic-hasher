package ch

import (
	"cmp"
	_ "embed"
	"fmt"
	"image"
	"log"
	"math/bits"
	"runtime"
	"slices"

	"gitea.narnian.us/lordwelch/goimagehash"
)

//go:embed hashes.gz
var Hashes []byte

const (
	H0 uint64 = 0b11111111 << (8 * iota)
	H1
	H2
	H3
	H4
	H5
	H6
	H7
)

const (
	Shift0 = (8 * iota)
	Shift1
	Shift2
	Shift3
	Shift4
	Shift5
	Shift6
	Shift7
)

const (
	ComicVine        Source = "comicvine.gamespot.com"
	SavedHashVersion int    = 2
)

type Source string

type Match struct {
	Distance int
	Hash     uint64
}

type ID struct {
	Domain Source
	ID     string
}

type Result struct {
	Hash          Hash
	ID            ID
	Distance      int
	EquivalentIDs []ID
}
type Im struct {
	Im      image.Image
	Format  string
	ID      ID
	NewOnly bool
}

type ImageHash struct {
	Hashes []Hash
	ID     ID
}

type Hash struct {
	Hash uint64
	Kind goimagehash.Kind
}

// IDList is a map of domain to ID eg IDs["comicvine.gamespot.com"] = []string{"1235"}
// Maps are extremely expensive in go for small maps this should only be used to return info to a user or as a map containing all IDs for a source
type IDList map[Source][]string

func ToIDList(ids []ID) IDList {
	idlist := IDList{}
	for _, id := range ids {
		idlist[id.Domain] = Insert(idlist[id.Domain], id.ID)
	}
	return idlist
}
func InsertID(ids []ID, id ID) []ID {
	index, itemFound := slices.BinarySearchFunc(ids, id, func(existing ID, target ID) int {
		return cmp.Or(
			cmp.Compare(existing.Domain, target.Domain),
			cmp.Compare(existing.ID, target.ID),
		)
	})
	if itemFound {
		return ids
	}
	return slices.Insert(ids, index, id)
}

type NewIDs struct {
	OldID ID
	NewID ID
}

type HashStorage interface {
	GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error)
	MapHashes(ImageHash)
	DecodeHashes(hashes *SavedHashes) error
	EncodeHashes() (*SavedHashes, error)
	AssociateIDs(newIDs []NewIDs) error
	GetIDs(id ID) IDList
}

func Atleast(maxDistance int, searchHash uint64, hashes []uint64) []Match {
	matchingHashes := make([]Match, 0, 20) // hope that we don't need all of them
	for _, storedHash := range hashes {
		distance := bits.OnesCount64(searchHash ^ storedHash)
		if distance <= maxDistance {
			matchingHashes = append(matchingHashes, Match{distance, storedHash})
		}
	}
	return matchingHashes
}

func Insert[S ~[]E, E cmp.Ordered](slice S, item E) S {
	index, itemFound := slices.BinarySearch(slice, item)
	if itemFound {
		return slice
	}
	return slices.Insert(slice, index, item)
}

func InsertIdx[S ~[]E, E cmp.Ordered](slice S, item E) (S, int) {
	index, itemFound := slices.BinarySearch(slice, item)
	if itemFound {
		return slice, index
	}
	return slices.Insert(slice, index, item), index
}

func MemStats() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

func HashImage(i Im) ImageHash {
	if i.Format == "webp" {
		i.Im = goimagehash.FancyUpscale(i.Im.(*image.YCbCr))
	}

	var (
		err error
	)

	ahash, err := goimagehash.AverageHash(i.Im)
	if err != nil {
		msg := fmt.Sprintf("Failed to ahash Image: %s", err)
		log.Println(msg)
		return ImageHash{}
	}
	dhash, err := goimagehash.DifferenceHash(i.Im)
	if err != nil {
		msg := fmt.Sprintf("Failed to dhash Image: %s", err)
		log.Println(msg)
		return ImageHash{}
	}
	phash, err := goimagehash.PerceptionHash(i.Im)
	if err != nil {
		msg := fmt.Sprintf("Failed to phash Image: %s", err)
		log.Println(msg)
		return ImageHash{}
	}
	return ImageHash{
		Hashes: []Hash{{ahash.GetHash(), ahash.GetKind()}, {dhash.GetHash(), dhash.GetKind()}, {phash.GetHash(), phash.GetKind()}},
		ID:     i.ID,
	}
}

func SplitHash(hash uint64) [8]uint8 {
	return [8]uint8{
		uint8((hash & H7) >> Shift7),
		uint8((hash & H6) >> Shift6),
		uint8((hash & H5) >> Shift5),
		uint8((hash & H4) >> Shift4),
		uint8((hash & H3) >> Shift3),
		uint8((hash & H2) >> Shift2),
		uint8((hash & H1) >> Shift1),
		uint8((hash & H0) >> Shift0),
	}
}
