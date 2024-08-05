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
	H_0 uint64 = 0b11111111 << (8 * iota)
	H_1
	H_2
	H_3
	H_4
	H_5
	H_6
	H_7
)

const (
	Shift_0 = (8 * iota)
	Shift_1
	Shift_2
	Shift_3
	Shift_4
	Shift_5
	Shift_6
	Shift_7
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

func Atleast(maxDistance int, search_hash uint64, hashes []uint64) []Match {
	matching_hashes := make([]Match, 0, len(hashes)/2) // hope that we don't need all of them
	for _, stored_hash := range hashes {
		distance := bits.OnesCount64(search_hash ^ stored_hash)
		if distance <= maxDistance {
			matching_hashes = append(matching_hashes, Match{distance, stored_hash})
		}
	}
	return matching_hashes
}

func Insert[S ~[]E, E cmp.Ordered](slice S, item E) S {
	index, item_found := slices.BinarySearch(slice, item)
	if item_found {
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
		uint8((hash & H_7) >> Shift_7),
		uint8((hash & H_6) >> Shift_6),
		uint8((hash & H_5) >> Shift_5),
		uint8((hash & H_4) >> Shift_4),
		uint8((hash & H_3) >> Shift_3),
		uint8((hash & H_2) >> Shift_2),
		uint8((hash & H_1) >> Shift_1),
		uint8((hash & H_0) >> Shift_0),
	}
}

type IDList map[Source][]string // IDs is a map of domain to ID eg IDs['comicvine.gamespot.com'] = []string{"1235"}
