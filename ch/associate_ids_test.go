package ch

import (
	"bytes"
	"errors"
	"testing"

	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/google/go-cmp/cmp"
)

func TestAssociateIDsMergesGroups(t *testing.T) {
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

	// Merging leaves an unused group behind. Encoding must compact or it will write an invalid file.
	// We ensure that we can encode and decode after merging groups
	buf := &bytes.Buffer{}
	if err := EncodeHashesV3(hashes, buf); err != nil {
		t.Fatal("failed to encode merged ID groups:", err)
	}
	loaded, err := DecodeHashesV3(buf)
	if err != nil {
		t.Fatal("failed to decode merged ID groups:", err)
	}
	index, found = loaded.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID after round trip")
	}
	if got := len(loaded.GetAllIDs(index)); got != 4 {
		t.Fatalf("expected all 4 IDs to be in one group after round trip, got %d", got)
	}
}

func TestAssociateIDsCreatesGroup(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "1"}
	metronID := ID{Domain: NewSource("metron.cloud"), ID: "2"}
	hashes, err := NewSavedHashesV3(&SavedHashesV2{Hashes: []SavedHashV2{
		{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
		{ID: metronID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := hashes.AssociateIDs(cvID, metronID); err != nil {
		t.Fatal(err)
	}
	index, found := hashes.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID")
	}
	if got := len(hashes.GetAllIDs(index)); got != 2 {
		t.Fatalf("expected 2 equivalent IDs, got %d", got)
	}
}

func TestAssociateIDsAddsUngroupedID(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "1"}
	metronID := ID{Domain: NewSource("metron.cloud"), ID: "2"}
	gcdID := ID{Domain: NewSource("comics.org"), ID: "3"}
	tests := []struct {
		name      string
		oldID     ID
		newID     ID
		ungrouped ID
	}{
		{name: "old ID is already grouped", oldID: metronID, newID: gcdID, ungrouped: gcdID},
		{name: "new ID is already grouped", oldID: gcdID, newID: metronID, ungrouped: gcdID},
	}
	for _, test := range tests {
		// Note that we have to create this on both iterations otherwise AssociateIDs does nothing on the second test
		hashes, err := NewSavedHashesV3(&SavedHashesV2{
			IDs: [][]ID{{cvID, metronID}},
			Hashes: []SavedHashV2{
				{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
				{ID: gcdID, Hash: Hash{Kind: goimagehash.AHash, Hash: 2}},
			},
		})
		t.Run(test.name, func(t *testing.T) {
			if err != nil {
				t.Fatal(err)
			}
			if err := hashes.AssociateIDs(test.oldID, test.newID); err != nil {
				t.Fatal("failed to associate grouped and ungrouped IDs:", err)
			}
			index, found := hashes.FindID(test.ungrouped)
			if !found {
				t.Fatal("failed to find formerly ungrouped ID:", test.ungrouped)
			}
			if diff := cmp.Diff([]ID{cvID, metronID, gcdID}, hashes.GetAllIDs(index), cmpOpts...); diff != "" {
				t.Errorf("Expected all 3  (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAssociateIDsSameSourceConflict(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "1"}
	metronID := ID{Domain: NewSource("metron.cloud"), ID: "2"}
	cvOther := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "3"}
	hashes := SavedHashesV3{}
	hashes.InsertID(metronID)
	hashes.InsertHash(Hash{Kind: goimagehash.AHash, Hash: 1}, cvID)
	hashes.InsertHash(Hash{Kind: goimagehash.AHash, Hash: 2}, cvOther)
	if err := hashes.AssociateIDs(metronID, cvID); err != nil {
		t.Fatal("unable to prepare test:", err)
	}

	// metron:2 already belongs to a group that contains a comicvine ID so
	// comicvine:3 cannot be added to it.
	if err := hashes.AssociateIDs(cvOther, metronID); !errors.Is(err, ErrIDConflict) {
		t.Fatal("expected associating two IDs from the same source to fail: error:", err)
	}
	if err := hashes.AssociateIDs(metronID, cvOther); !errors.Is(err, ErrIDConflict) {
		t.Fatal("expected the reversed association to fail for the same source conflict: error:", err)
	}
	index, found := hashes.FindID(cvOther)
	if !found {
		t.Fatal("failed to find CV ID")
	}
	if got := hashes.IDs[index].Group; got != NoIDGroup {
		t.Fatalf("failed association modified the ID group: %d", got)
	}
}
