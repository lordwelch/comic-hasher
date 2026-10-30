package ch

import (
	"testing"

	"gitea.narnian.us/lordwelch/goimagehash"
)

func TestSavedHashesV3AssociateIDsMergesGroups(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "1"}
	metronID := ID{Domain: NewSource("metron.cloud"), ID: "2"}
	gcdID := ID{Domain: NewSource("comics.org"), ID: "3"}
	otherID := ID{Domain: NewSource("example.org"), ID: "4"}
	hashes, err := NewSavedHashesV3(&SavedHashesV2{
		IDs: [][]ID{{cvID, metronID}, {gcdID, otherID}},
		Hashes: []SavedHashV2{
			{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := hashes.AssociateIDs(metronID, gcdID); err != nil {
		t.Fatal("failed to associate IDs:", err)
	}
	index, found := hashes.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID")
	}
	if got := len(hashes.GetAllIDs(index)); got != 4 {
		t.Fatalf("expected all 4 IDs to be in one group, got %d", got)
	}
}

func TestSavedHashesV3AssociateIDsSameSourceConflict(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "1"}
	metronID := ID{Domain: NewSource("metron.cloud"), ID: "2"}
	cvOther := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "3"}
	hashes, err := NewSavedHashesV3(&SavedHashesV2{
		IDs: [][]ID{{cvID, metronID}},
		Hashes: []SavedHashV2{
			{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
			{ID: cvOther, Hash: Hash{Kind: goimagehash.AHash, Hash: 2}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// metron:2 already belongs to a group that contains a comicvine ID so
	// comicvine:3 cannot be added to it.
	if err := hashes.AssociateIDs(cvOther, metronID); err == nil {
		t.Fatal("expected associating two IDs from the same source to fail")
	}
	index, found := hashes.FindID(cvOther)
	if !found {
		t.Fatal("failed to find CV ID")
	}
	if got := hashes.IDs[index].Group; got != NoIDGroup {
		t.Fatalf("failed association modified the ID group: %d", got)
	}
}
