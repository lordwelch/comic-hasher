package ch

import (
	"cmp"
	"fmt"
	"image"
	"log"
	"math/bits"
	"runtime"
	"slices"

	"gitea.narnian.us/lordwelch/goimagehash"
)

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

type Source string

type Match struct {
	Distance int
	Hash     uint64
}

type Result struct {
	IDs      IDList
	Distance int
	Hash     ImageHash
}

type Im struct {
	Im       image.Image
	Format   string
	Domain   Source
	ID, Path string
}

type Hash struct {
	Ahash  *goimagehash.ImageHash
	Dhash  *goimagehash.ImageHash
	Phash  *goimagehash.ImageHash
	Domain Source
	ID     string
}

type ImageHash struct {
	Hash uint64
	Kind goimagehash.Kind
}

func Atleast(maxDistance int, searchHash uint64, hashes []uint64) []Match {
	matchingHashes := make([]Match, 0, len(hashes)/2) // hope that we don't need all of them
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

func MemStats() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

func HashImage(i Im) Hash {
	if i.Format == "webp" {
		i.Im = goimagehash.FancyUpscale(i.Im.(*image.YCbCr))
	}

	var (
		err   error = nil
		ahash *goimagehash.ImageHash
		dhash *goimagehash.ImageHash
		phash *goimagehash.ImageHash
	)

	ahash, err = goimagehash.AverageHash(i.Im)
	if err != nil {
		msg := fmt.Sprintf("Failed to ahash Image: %s", err)
		log.Println(msg)
		return Hash{}
	}
	dhash, err = goimagehash.DifferenceHash(i.Im)
	if err != nil {
		msg := fmt.Sprintf("Failed to dhash Image: %s", err)
		log.Println(msg)
		return Hash{}
	}
	phash, err = goimagehash.PerceptionHash(i.Im)
	if err != nil {
		msg := fmt.Sprintf("Failed to phash Image: %s", err)
		log.Println(msg)
		return Hash{}
	}
	return Hash{
		Ahash:  ahash,
		Dhash:  dhash,
		Phash:  phash,
		Domain: i.Domain,
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

type IDList map[Source][]string // IDs is a map of domain to ID eg IDs['comicvine.gamespot.com'] = []string{"1235"}
