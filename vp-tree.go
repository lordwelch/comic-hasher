package ch

import (
	"errors"
	"fmt"
	"math/bits"

	"gitea.narnian.us/lordwelch/goimagehash"
	"gonum.org/v1/gonum/spatial/vptree"
)

type VPTree struct {
	trees  [3]*vptree.Tree
	hashes [3][]vptree.Comparable
}
type VPHash struct {
	Hash Hash
	IDs  []ID
}

func (h *VPHash) Distance(c vptree.Comparable) float64 {
	h2, ok := c.(*VPHash)
	if !ok {
		return -99
	}
	return float64(bits.OnesCount64(h.Hash.Hash ^ h2.Hash.Hash))
}

func (v *VPTree) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var matches []Result
	var exactMatches []Result
	fmt.Println(hashes)
	for _, hash := range hashes {
		results := vptree.NewDistKeeper(float64(max))
		hashType := int(hash.Kind) - 1
		v.trees[hashType].NearestSet(results, &VPHash{Hash: hash})
		for _, result := range results.Heap {
			vphash := result.Comparable.(*VPHash)
			if result.Dist == 0 {
				exactMatches = append(exactMatches, Result{
					IDs:      ToIDList(vphash.IDs),
					Distance: int(result.Dist),
					Hash:     vphash.Hash,
				})
			} else {
				matches = append(matches, Result{
					IDs:      ToIDList(vphash.IDs),
					Distance: int(result.Dist),
					Hash:     vphash.Hash,
				})
			}
		}
	}
	if len(exactMatches) > 0 && exactOnly {
		return exactMatches, nil
	}
	matches = append(exactMatches[:len(exactMatches):len(exactMatches)], matches...)
	return matches, nil
}

func (v *VPTree) MapHashes(ImageHash) {
	panic("Not Implemented")
}

func (v *VPTree) DecodeHashes(hashes SavedHashes) error {
	var err error
	for hashType, sourceHashes := range hashes.Hashes {
		for hash, idsLocation := range sourceHashes {
			var (
				hashKind = goimagehash.Kind(hashType + 1)
			)
			hash := &VPHash{Hash{hash, hashKind}, hashes.IDs[idsLocation]}
			v.hashes[hashType] = append(v.hashes[hashType], hash)
		}
	}
	for hashType := range 3 {
		v.trees[hashType], err = vptree.New(v.hashes[hashType], 3, nil)
		if err != nil {
			return err
		}
	}
	return nil
}
func (v *VPTree) EncodeHashes() (SavedHashes, error) {
	return SavedHashes{}, errors.New("Not Implemented")
}

func (v *VPTree) AssociateIDs(newIDs []NewIDs) error {
	return errors.New("Not Implemented")
}

func (v *VPTree) GetIDs(id ID) IDList {
	return nil
}

func NewVPStorage() (HashStorage, error) {

	return &VPTree{
		hashes: [3][]vptree.Comparable{
			make([]vptree.Comparable, 0, 1_000_000),
			make([]vptree.Comparable, 0, 1_000_000),
			make([]vptree.Comparable, 0, 1_000_000),
		},
	}, nil
}
