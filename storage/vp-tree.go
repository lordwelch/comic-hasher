//go:build !gokrazy

package storage

import (
	"errors"
	"fmt"
	"math/bits"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/goimagehash"
	"gonum.org/v1/gonum/spatial/vptree"
)

type VPTree struct {
	aTree *vptree.Tree
	dTree *vptree.Tree
	pTree *vptree.Tree

	hashes *ch.SavedHashesV3

	aHashes []vptree.Comparable // temporary, only used for vptree creation
	dHashes []vptree.Comparable // temporary, only used for vptree creation
	pHashes []vptree.Comparable // temporary, only used for vptree creation
}

// VPTree is not editable
func (s *VPTree) RLock()   {}
func (s *VPTree) RUnlock() {}

type VPHash struct {
	Hash          ch.Hash
	ID            ch.ID
	EquivalentIDs []ch.ID
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
		currentTree.NearestSet(results, &VPHash{Hash: hash})

		mappedIds := map[ch.ID]bool{}
		for _, result := range results.Heap {
			storedHash := result.Comparable.(*VPHash)
			if mappedIds[storedHash.ID] {
				continue
			}
			mappedIds[storedHash.ID] = true
			if result.Dist == 0 {
				exactMatches = append(exactMatches, ch.Result{
					Hash:          storedHash.Hash,
					ID:            storedHash.ID,
					Distance:      0,
					EquivalentIDs: storedHash.EquivalentIDs,
				})
			} else {
				matches = append(matches, ch.Result{
					Hash:          storedHash.Hash,
					ID:            storedHash.ID,
					Distance:      int(result.Dist),
					EquivalentIDs: storedHash.EquivalentIDs,
				})
			}
		}
	}
	if exactOnly && len(exactMatches) > 0 {
		return exactMatches, nil
	}
	matches = append(matches, exactMatches...)
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

func (v *VPTree) MapHashes(ch.ImageHash) ch.Metrics {
	panic("Not Implemented")
}

func (v *VPTree) DecodeHashes(hashes *ch.SavedHashesV3) (ch.Metrics, error) {
	if hashes == nil {
		return ch.Metrics{}, nil
	}
	v.hashes = hashes

	m := ch.Metrics{
		Hashes: make(map[ch.Metric]int),
	}
	for _, kind := range []goimagehash.Kind{goimagehash.AHash, goimagehash.DHash, goimagehash.PHash} {
		for _, savedHash := range *hashes.HashesForKind(kind) {
			id := hashes.IDAt(savedHash.ID)
			hash := &VPHash{
				Hash: ch.Hash{
					Hash: savedHash.Hash,
					Kind: kind,
				},
				ID:            id,
				EquivalentIDs: hashes.GetAllIDs(savedHash.ID),
			}
			m.Hashes[ch.Metric{
				Source: id.Domain,
				Kind:   kind,
			}] += 1

			switch kind {
			case goimagehash.AHash:
				v.aHashes = append(v.aHashes, hash)
			case goimagehash.DHash:
				v.dHashes = append(v.dHashes, hash)
			case goimagehash.PHash:
				v.pHashes = append(v.pHashes, hash)
			}

			if id == (ch.ID{}) {
				return ch.Metrics{}, fmt.Errorf("empty ID detected")
			}
		}
	}

	var err error
	v.aTree, err = vptree.New(v.aHashes, 3, nil)
	if err != nil {
		return ch.Metrics{}, err
	}
	v.dTree, err = vptree.New(v.dHashes, 3, nil)
	if err != nil {
		return ch.Metrics{}, err
	}
	v.pTree, err = vptree.New(v.pHashes, 3, nil)
	if err != nil {
		return ch.Metrics{}, err
	}
	v.aHashes = nil
	v.dHashes = nil
	v.pHashes = nil
	return m, nil
}

func (v *VPTree) EncodeHashes() (*ch.SavedHashesV3, error) {
	return &ch.SavedHashesV3{}, errors.New("not implemented")
}

func (v *VPTree) AssociateIDs(OldID, NewID ch.ID) error {
	return errors.New("not implemented")
}

func (v *VPTree) GetIDs(id ch.ID) []ch.ID {
	if v.hashes == nil {
		return nil
	}
	rid, found := v.hashes.FindID(id)
	if !found {
		return nil
	}
	return v.hashes.GetAllIDs(rid)
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
