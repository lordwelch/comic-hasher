package ch

import (
	"bytes"
	gcmp "cmp"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unsafe"

	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// Keep in-line with storage_test.go
var cmpOpts = []cmp.Option{
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(func(a Result, b Result) int {
		return gcmp.Or(
			gcmp.Compare(a.Hash.Kind, b.Hash.Kind),
			gcmp.Compare(a.Hash.Hash, b.Hash.Hash),
			a.ID.Compare(b.ID),
		)
	}),
}

func TestDecodeHashesV3Truncated(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "1"}
	hashes, err := NewSavedHashesV3(&SavedHashesV2{Hashes: []SavedHashV2{
		{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	if err := EncodeHashesV3(hashes, buf); err != nil {
		t.Fatal(err)
	}
	// Drop an arbitrary amount of bytes off the end.
	truncated := buf.Bytes()[:buf.Len()-int(unsafe.Sizeof(SavedHashV3{}))]

	wantTruncatedErr := fmt.Errorf("%w: truncated saved hashes: read %d bytes: %w", ErrDecodeFail, len(truncated), io.EOF)
	_, err = DecodeHashesV3(bytes.NewReader(truncated))
	if !errors.Is(err, ErrDecodeFail) {
		t.Fail()
		t.Logf("expected decoding a truncated file to fail with '%v', got: '%v'", ErrDecodeFail, err)
	}
	if diff := cmp.Diff(wantTruncatedErr.Error(), err.Error(), cmpOpts...); diff != "" {
		t.Fail()
		t.Errorf("unexpected truncated error message (-want +got):\n%s", diff)
	}
	_, err = DecodeHashesV3(nil)
	if !errors.Is(err, ErrNoHashes) {
		t.Fail()
		t.Logf("expected decoding a nil reader to fail with %v, got: %v", ErrNoHashes, err)
	}
}

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

	wantA := []SavedHashV3{{Hash: 1, ID: 0}, {Hash: 1, ID: 2}}
	wantD := []SavedHashV3{{Hash: 2, ID: 0}}
	wantP := []SavedHashV3{{Hash: 3, ID: 0}, {Hash: 4, ID: 1}}
	if diff := cmp.Diff(wantA, hashes.AHashes, cmpOpts...); diff != "" {
		t.Errorf("failed to preprae test: converted A hashes mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantD, hashes.DHashes, cmpOpts...); diff != "" {
		t.Errorf("failed to preprae test: converted D hashes mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantP, hashes.PHashes, cmpOpts...); diff != "" {
		t.Errorf("failed to preprae test: converted P hashes mismatch (-want +got):\n%s", diff)
	}

	index, found := hashes.FindID(cvID)
	if !found {
		t.Fatal("failed to preprae test: failed to find CV ID after NewSavedHashesV3")
	}
	ids := hashes.GetAllIDs(index)
	if len(ids) != 2 {
		t.Fatalf("failed to preprae test: expected 2 equivalent IDs, got %v", ids)
	}
	buf := &bytes.Buffer{}
	err = EncodeHashesV3(hashes, buf)
	if err != nil {
		t.Fatal("failed to encode hashes:", err)
	}
	loaded, err := DecodeHashesV3(buf)
	if err != nil {
		t.Fatal("failed to decode hashes:", err)
	}

	index, found = loaded.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID after round trip")
	}
	ids = loaded.GetAllIDs(index)
	if diff := cmp.Diff([]ID{cvID, metronID}, ids, cmpOpts...); diff != "" {
		t.Fatalf("expected 2 equivalent IDs, (-want +got):\n%s", diff)
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
	_, found = loaded.FindID(cvID)
	if !found {
		t.Fatal("failed to find CV ID after insert")
	}

	// New hashes use the existing ID
	newHash := Hash{Kind: goimagehash.DHash, Hash: 5}
	if !loaded.InsertHash(newHash, cvID) {
		t.Fatal("expected a new hash to be inserted")
	}
	if diff := cmp.Diff([]SavedHashV3{{Hash: 2, ID: 0}, {Hash: 5, ID: 0}}, loaded.DHashes, cmpOpts...); diff != "" {
		t.Fatalf("expected 2 D hashes, (-want +got):\n%s", diff)
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
	ids = loaded.GetAllIDs(index)
	if diff := cmp.Diff([]ID{cvID, metronID}, ids, cmpOpts...); diff != "" {
		t.Fatalf("expected 2 equivalent IDs, (-want +got):\n%s", diff)
	}
}

func TestSavedHashesV3SourceLengthLimit(t *testing.T) {
	hashes := &SavedHashesV3{}
	maxSourceLength := len(hashes.V3Header.Sources[0])
	validID := ID{Domain: NewSource(strings.Repeat("s", maxSourceLength)), ID: "1"}
	if _, err := hashes.InsertID(validID); err != nil {
		t.Fatalf("expected a %d-byte source to be accepted: %v", maxSourceLength, err)
	}
	if _, found := hashes.FindID(validID); !found {
		t.Fatal("failed to find ID with the maximum source length")
	}

	hashes = &SavedHashesV3{}
	invalidID := ID{Domain: NewSource(strings.Repeat("s", maxSourceLength+1)), ID: "1"}
	_, err := hashes.InsertID(invalidID)
	if !errors.Is(err, ErrSourceTooLong) {
		t.Fatalf("expected a 129-byte source to fail with '%v', got: '%v'", ErrSourceTooLong, err)
	}
}

func TestSavedHashesV3SourceCountLimit(t *testing.T) {
	hashes := &SavedHashesV3{}
	maxSources := len(hashes.V3Header.Sources)
	for i := range maxSources {
		id := ID{Domain: NewSource(fmt.Sprintf("source-%03d", i)), ID: "1"}
		if _, err := hashes.InsertID(id); err != nil {
			t.Fatalf("failed to prepare test: failed to insert source %d of %d: %v", i+1, maxSources, err)
		}
	}

	id := ID{Domain: NewSource("one-source-too-many"), ID: "1"}
	_, err := hashes.InsertID(id)
	if !errors.Is(err, ErrTooManySources) {
		t.Fatalf("want: '%v' got: '%v'", ErrTooManySources, err)
	}
}

func TestSavedHashesV3InsertHashUsesExistingID(t *testing.T) {
	cvID := ID{Domain: NewSource("comicvine.gamespot.com"), ID: "10"}
	hashes, err := NewSavedHashesV3(&SavedHashesV2{Hashes: []SavedHashV2{
		{ID: cvID, Hash: Hash{Kind: goimagehash.AHash, Hash: 42}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if hashes.InsertHash(Hash{Kind: goimagehash.AHash, Hash: 42}, cvID) {
		t.Fatal("expected inserting a duplicate AHash to be rejected")
	}

	if !hashes.InsertHash(Hash{Kind: goimagehash.DHash, Hash: 42}, cvID) {
		t.Fatal("expected inserting a DHash with the same ID to be accepted")
	}
	if diff := cmp.Diff([]SavedHashV3{{Hash: 42, ID: 0}}, hashes.AHashes, cmpOpts...); diff != "" {
		t.Fatalf("expected 1 A hash, (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]SavedHashV3{{Hash: 42, ID: 0}}, hashes.DHashes, cmpOpts...); diff != "" {
		t.Fatalf("expected 1 D hash, (-want +got):\n%s", diff)
	}

	// The same hash for a different ID is a new record.
	otherID := ID{Domain: NewSource("metron.cloud"), ID: "11"}
	if !hashes.InsertHash(Hash{Kind: goimagehash.AHash, Hash: 42}, otherID) {
		t.Fatal("expected the hash for a new ID to be inserted")
	}
	if diff := cmp.Diff([]SavedHashV3{{Hash: 42, ID: 0}, {Hash: 42, ID: 1}}, hashes.AHashes, cmpOpts...); diff != "" {
		t.Fatalf("expected 2 A hashes, (-want +got):\n%s", diff)
	}
	rid, found := hashes.FindID(otherID)
	if !found {
		t.Fatal("failed to find the inserted ID")
	}
	if _, found := hashes.findHash(goimagehash.AHash, 42, rid); !found {
		t.Fatal("hash was not recorded for the resolved ID")
	}
}

func TestNewSavedHashesV3RespectsSourceLimit(t *testing.T) {
	oldGroup := make([]ID, 255)
	for i := range oldGroup {
		oldGroup[i] = ID{Domain: NewSource(fmt.Sprintf("source-%03d", i)), ID: "1"}
	}
	newGroup := []ID{
		{Domain: NewSource("source-256"), ID: "2"},
	}
	_, err := NewSavedHashesV3(&SavedHashesV2{
		IDs: [][]ID{oldGroup, newGroup},
		Hashes: []SavedHashV2{
			{ID: oldGroup[0], Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
			{ID: newGroup[0], Hash: Hash{Kind: goimagehash.AHash, Hash: 2}},
		},
	})
	if err != nil {
		t.Fatal("expected to be able to create 256 sources:", err)
	}
	newGroup = []ID{
		{Domain: NewSource("source-256"), ID: "2"},
		{Domain: NewSource("source-257"), ID: "2"},
	}
	_, err = NewSavedHashesV3(&SavedHashesV2{
		IDs: [][]ID{oldGroup, newGroup},
		Hashes: []SavedHashV2{
			{ID: oldGroup[0], Hash: Hash{Kind: goimagehash.AHash, Hash: 1}},
			{ID: newGroup[0], Hash: Hash{Kind: goimagehash.AHash, Hash: 2}},
		},
	})
	if !errors.Is(err, ErrTooManySources) {
		t.Fatalf("want: '%v' got: '%v'", ErrTooManySources, err)
	}
}
