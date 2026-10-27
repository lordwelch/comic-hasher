package ch

import (
	"bytes"
	"testing"

	"gitea.narnian.us/lordwelch/goimagehash"
)

func TestSavedHashesV3RoundTrip(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "100"}
	metronID := ID{Domain: NewSource("metron.cloud"), ID: "200"}
	otherID := ID{Domain: NewSource("example.org"), ID: "a"}
	entries := []SavedHashV2{
		{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
		{ID: cvID, Hash: Hash{Kind: goimagehash.DHash, Hash: 2}},
		{ID: cvID, Hash: Hash{Kind: goimagehash.PHash, Hash: 3}},
		{ID: metronID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
		{ID: otherID, Hash: Hash{Kind: goimagehash.PHash, Hash: 4}},
	}

	hashes, err := NewSavedHashesV3(&SavedHashesV2{Hashes: entries, IDs: [][]ID{{cvID, metronID}}})
	if err != nil {
		t.Fatal(err)
	}
	index, found := hashes.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID after NewSavedHashesV3")
	}
	ids := hashes.GetAllIDs(index)
	if len(ids) != 2 {
		t.Fatalf("expected 2 equivalent IDs, got %v", ids)
	}
	buf := &bytes.Buffer{}
	err = EncodeHashesV3(hashes, buf)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := DecodeHashesV3(buf)
	if err != nil {
		t.Fatal(err)
	}

	index, found = loaded.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID after round trip")
	}
	ids = loaded.GetAllIDs(index)
	if len(ids) != 2 {
		t.Fatalf("expected 2 equivalent IDs, got %v", ids)
	}

	metronIndex, found := loaded.FindID(metronID)
	if !found {
		t.Fatal("failed to find metron ID after round trip")
	}
	if got := loaded.IDs[metronIndex].Group; got != loaded.IDs[index].Group {
		t.Fatalf("expected IDs to be in the same group: %d != %d", got, loaded.IDs[index].Group)
	}

	// Inserting an ID in the middle of the table must not invalidate the
	// indexes stored in the hash table.
	newID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "0"}
	loaded.InsertID(newID)
	// if rid != 0 {
	// 	t.Fatalf("expected the new ID to sort first, got index %d", rid)
	// }
	_, found = loaded.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID after insert")
	}

	// New hashes use the existing ID and are encoded in the correct kind range.
	newHash := Hash{Kind: goimagehash.DHash, Hash: 5}
	if !loaded.InsertHash(newHash, cvID) {
		t.Fatal("expected a new hash to be inserted")
	}
	if got := len(loaded.DHashes); got != 2 {
		t.Fatalf("expected 2 D hashes, got %d", got)
	}

	// A second round trip must preserve the appended values.
	buf.Reset()
	err = EncodeHashesV3(loaded, buf)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = DecodeHashesV3(buf)
	if err != nil {
		t.Fatal(err)
	}
	index, found = loaded.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID after second round trip")
	}
	if got := len(loaded.GetAllIDs(index)); got != 2 {
		t.Fatalf("expected 2 equivalent IDs after second round trip, got %d", got)
	}
}

func TestSavedHashesV3AssociateIDs(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "1"}
	metronID := ID{Domain: NewSource("metron.cloud"), ID: "2"}
	hashes, err := NewSavedHashesV3(&SavedHashesV2{Hashes: []SavedHashV2{
		{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
		{ID: metronID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := hashes.AssociateIDs(NewIDs{OldID: cvID, NewID: metronID}); err != nil {
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

func TestSavedHashesV3InsertHashUsesResolvedID(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "10"}
	hashes, err := NewSavedHashesV3(&SavedHashesV2{Hashes: []SavedHashV2{
		{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 42}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// A separate Source pointer with the same name resolves to the same stored
	// ID and must be detected as a duplicate hash.
	sameID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "10"}
	if hashes.InsertHash(Hash{Kind: goimagehash.AHash, Hash: 42}, sameID) {
		t.Fatal("expected the duplicate hash to be rejected")
	}

	// The same hash for a different ID is a new record.
	otherID := ID{Domain: NewSource("metron.cloud"), ID: "11"}
	if !hashes.InsertHash(Hash{Kind: goimagehash.AHash, Hash: 42}, otherID) {
		t.Fatal("expected the hash for a new ID to be inserted")
	}
	if got := len(hashes.AHashes); got != 2 {
		t.Fatalf("expected 2 A hashes, got %d", got)
	}
	rid, found := hashes.FindID(otherID)
	if !found {
		t.Fatal("failed to find the inserted ID")
	}
	if _, found := hashes.findHash(goimagehash.AHash, 42, rid); !found {
		t.Fatal("hash was not recorded for the resolved ID")
	}
}
