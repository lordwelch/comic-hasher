//go:build !gokrazy

package storage

import (
	"errors"
	"fmt"
	"math/bits"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
	"gonum.org/v1/gonum/spatial/vptree"
)

type VPTree struct {
	aTree *vptree.Tree
	dTree *vptree.Tree
	pTree *vptree.Tree
	ids   map[ch.ID]*[]ch.ID

	aHashes []vptree.Comparable // temporary, only used for vptree creation
	dHashes []vptree.Comparable // temporary, only used for vptree creation
	pHashes []vptree.Comparable // temporary, only used for vptree creation
}
type VPHash struct {
	ch.SavedHash
}

func (h *VPHash) Distance(c vptree.Comparable) float64 {
	h2, ok := c.(*VPHash)
	if !ok {
		return -99
	}
	return float64(bits.OnesCount64(h.Hash.Hash ^ h2.Hash.Hash))
}

func (v *VPTree) GetMatches(hashes []ch.Hash, max int, exactOnly bool) ([]ch.Result, error) {
	var (
		matches      []ch.Result
		exactMatches []ch.Result
		tl           ch.TimeLog
	)
	tl.ResetTime()
	defer tl.LogTime("Search Complete")

	for _, hash := range hashes {
		results := vptree.NewDistKeeper(float64(max))

		currentTree := v.getCurrentTree(hash.Kind)
		currentTree.NearestSet(results, &VPHash{ch.SavedHash{Hash: hash}})

		mappedIds := map[*[]ch.ID]bool{}
		for _, result := range results.Heap {
			storedHash := result.Comparable.(*VPHash)
			ids := v.ids[storedHash.ID]
			if mappedIds[ids] {
				continue
			}
			mappedIds[ids] = true
			if result.Dist == 0 {
				exactMatches = append(exactMatches, ch.Result{
					Hash:          storedHash.Hash,
					ID:            storedHash.ID,
					Distance:      0,
					EquivalentIDs: *v.ids[storedHash.ID],
				})
			} else {
				matches = append(matches, ch.Result{
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

func (v *VPTree) MapHashes(ch.ImageHash) {
	panic("Not Implemented")
}

func (v *VPTree) DecodeHashes(hashes *ch.SavedHashes) error {
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

		if savedHash.ID == (ch.ID{}) {
			fmt.Println("Empty ID detected")
			panic(savedHash)
		}
		// All known equal IDs are already mapped we can add any missing ones from hashes
		if _, ok := v.ids[savedHash.ID]; !ok {
			v.ids[savedHash.ID] = &[]ch.ID{savedHash.ID}
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
func (v *VPTree) EncodeHashes() (*ch.SavedHashes, error) {
	return &ch.SavedHashes{}, errors.New("Not Implemented")
}

func (v *VPTree) AssociateIDs(newIDs []ch.NewIDs) error {
	return errors.New("Not Implemented")
}

func (v *VPTree) GetIDs(id ch.ID) ch.IDList {
	ids, found := v.ids[id]
	if !found {
		return nil
	}
	return ch.ToIDList(*ids)
}

func NewVPStorage() (ch.HashStorage, error) {
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
