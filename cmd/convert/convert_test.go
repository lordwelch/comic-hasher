package main

import (
	"bytes"
	"testing"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/goimagehash"
)

func TestConvertToV3(t *testing.T) {
	cvID := ch.ID{Domain: ch.NewSource("comicvine.gamespot.com"), ID: "100"}
	metronID := ch.ID{Domain: ch.NewSource("metron.cloud"), ID: "200"}
	oldHashes := &ch.SavedHashesV2{
		Version: 2,
		IDs: [][]ch.ID{
			{cvID, metronID},
		},
		Hashes: []ch.SavedHashV2{
			{ID: cvID, Hash: ch.Hash{Kind: goimagehash.AHash, Hash: 1}},
			{ID: cvID, Hash: ch.Hash{Kind: goimagehash.DHash, Hash: 2}},
			{ID: metronID, Hash: ch.Hash{Kind: goimagehash.PHash, Hash: 3}},
		},
	}

	v3Hashes, err := ch.NewSavedHashesV3(oldHashes)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	err = ch.EncodeHashesV3(v3Hashes, buf)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ch.DecodeHashesV3(buf)
	if err != nil {
		t.Fatal(err)
	}

	index, found := loaded.FindID(cvID)
	if !found {
		t.Fatal("failed to find converted ID after round trip")
	}
	if got := len(loaded.GetAllIDs(index)); got != 2 {
		t.Fatalf("expected 2 equivalent IDs, got %v", got)
	}

	metronIndex, found := loaded.FindID(metronID)
	if !found {
		t.Fatal("failed to find converted ID after round trip")
	}
	if got := loaded.IDs[metronIndex].Group; got != loaded.IDs[index].Group {
		t.Fatalf("expected IDs to be in the same group: %d != %d", got, loaded.IDs[index].Group)
	}

	if len(loaded.AHashes) != 1 {
		t.Fatalf("expected 1 ahash, got %v", len(loaded.AHashes))
	}
	if loaded.AHashes[0].Hash != 1 {
		t.Fatalf("expected ahash value 1, got %v", loaded.AHashes[0].Hash)
	}
	if got := len(loaded.DHashes); got != 1 {
		t.Fatalf("expected 1 dhash, got %v", got)
	}
	if got := len(loaded.PHashes); got != 1 {
		t.Fatalf("expected 1 phash, got %v", got)
	}
}

func TestConvertToV3ErrorCases(t *testing.T) {
	if _, err := ch.NewSavedHashesV3(nil); err != nil {
		t.Fatal("Unexpected error converting nil hashes:", err)
	}
	badHashes := &ch.SavedHashesV2{
		Version: 2,
		Hashes: []ch.SavedHashV2{
			{ID: ch.ID{Domain: nil, ID: "100"}, Hash: ch.Hash{Kind: goimagehash.AHash, Hash: 1}},
		},
	}
	if _, err := ch.NewSavedHashesV3(badHashes); err == nil {
		t.Fatal("expected an error for a hash without a source")
	}
	if _, err := DecodeOldHashes([]byte("not hashes at all")); err == nil {
		t.Fatal("expected an error decoding invalid hashes")
	}
}
