//go:build !gokrazy

package ch

import (
	"errors"
	"fmt"
	"math/bits"

	"gitea.narnian.us/lordwelch/goimagehash"
	"gonum.org/v1/gonum/spatial/vptree"
)

type VPTree struct {
	aTree *vptree.Tree
	dTree *vptree.Tree
	pTree *vptree.Tree
	ids   map[ID]*[]ID

	aHashes []vptree.Comparable // temporary, only used for vptree creation
	dHashes []vptree.Comparable // temporary, only used for vptree creation
	pHashes []vptree.Comparable // temporary, only used for vptree creation
}
type VPHash struct {
	SavedHash
}

func (h *VPHash) Distance(c vptree.Comparable) float64 {
	h2, ok := c.(*VPHash)
	if !ok {
		return -99
	}
	return float64(bits.OnesCount64(h.Hash.Hash ^ h2.Hash.Hash))
}

func (v *VPTree) GetMatches(hashes []Hash, max int, exactOnly bool) ([]Result, error) {
	var (
		matches      []Result
		exactMatches []Result
		tl           timeLog
	)
	tl.resetTime()
	defer tl.logTime("Search Complete")

	for _, hash := range hashes {
		results := vptree.NewDistKeeper(float64(max))

		currentTree := v.getCurrentTree(hash.Kind)
		currentTree.NearestSet(results, &VPHash{SavedHash{Hash: hash}})

		mappedIds := map[*[]ID]bool{}
		for _, result := range results.Heap {
			storedHash := result.Comparable.(*VPHash)
			ids := v.ids[storedHash.ID]
			if mappedIds[ids] {
				continue
			}
			mappedIds[ids] = true
			if result.Dist == 0 {
				exactMatches = append(exactMatches, Result{
					Hash:          storedHash.Hash,
					ID:            storedHash.ID,
					Distance:      0,
					EquivalentIDs: *v.ids[storedHash.ID],
				})
			} else {
				matches = append(matches, Result{
					Hash:          storedHash.Hash,
					ID:            storedHash.ID,
					Distance:      0,
					EquivalentIDs: *v.ids[storedHash.ID],
				})
			}
		}
	}
	if exactOnly && len(exactMatches) > 0 {
		return exactMatches, nil
	}
	exactMatches = append(exactMatches, matches...)
	return matches, nil
}

func (v *VPTree) getCurrentTree(kind goimagehash.Kind) *vptree.Tree {
	if kind == goimagehash.AHash {
		return v.aTree
	}
	if kind == goimagehash.DHash {
		return v.dTree
	}
	if kind == goimagehash.PHash {
		return v.pTree
	}
	panic("Unknown hash type: " + kind.String())
}

func (v *VPTree) MapHashes(ImageHash) {
	panic("Not Implemented")
}

func (v *VPTree) DecodeHashes(hashes *SavedHashes) error {
	if hashes == nil {
		return nil
	}

	// Initialize all the known equal IDs
	for _, ids := range hashes.IDs {
		for _, id := range ids {
			v.ids[id] = &ids
		}
	}
	var err error
	for _, savedHash := range hashes.Hashes {
		if savedHash.Hash.Kind == goimagehash.AHash {
			v.aHashes = append(v.aHashes, &VPHash{savedHash})
		}
		if savedHash.Hash.Kind == goimagehash.DHash {
			v.dHashes = append(v.dHashes, &VPHash{savedHash})
		}
		if savedHash.Hash.Kind == goimagehash.PHash {
			v.pHashes = append(v.pHashes, &VPHash{savedHash})
		}

		if savedHash.ID == (ID{}) {
			fmt.Println("Empty ID detected")
			panic(savedHash)
		}
		// All known equal IDs are already mapped we can add any missing ones from hashes
		if _, ok := v.ids[savedHash.ID]; !ok {
			v.ids[savedHash.ID] = &[]ID{savedHash.ID}
		}
	}

	v.aTree, err = vptree.New(v.aHashes, 3, nil)
	if err != nil {
		return err
	}
	v.dTree, err = vptree.New(v.dHashes, 3, nil)
	if err != nil {
		return err
	}
	v.pTree, err = vptree.New(v.pHashes, 3, nil)
	if err != nil {
		return err
	}
	return nil
}
func (v *VPTree) EncodeHashes() (*SavedHashes, error) {
	return &SavedHashes{}, errors.New("Not Implemented")
}

func (v *VPTree) AssociateIDs(newIDs []NewIDs) error {
	return errors.New("Not Implemented")
}

func (v *VPTree) GetIDs(id ID) IDList {
	ids, found := v.ids[id]
	if !found {
		return nil
	}
	return ToIDList(*ids)
}

func NewVPStorage() (HashStorage, error) {
	var err error
	v := &VPTree{
		aHashes: []vptree.Comparable{},
		dHashes: []vptree.Comparable{},
		pHashes: []vptree.Comparable{},
	}
	v.aTree, err = vptree.New(v.aHashes, 3, nil)
	if err != nil {
		return v, err
	}
	v.dTree, err = vptree.New(v.dHashes, 3, nil)
	if err != nil {
		return v, err
	}
	v.pTree, err = vptree.New(v.pHashes, 3, nil)
	if err != nil {
		return v, err
	}
	return v, nil
}
