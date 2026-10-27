package ch

import (
	"bytes"
	"testing"
	"unsafe"

	"gitea.narnian.us/lordwelch/goimagehash"
)

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
	// Drop the last hash record but keep the header intact.
	truncated := buf.Bytes()[:buf.Len()-int(unsafe.Sizeof(SavedHashV3{}))]
	if _, err := DecodeHashesV3(bytes.NewReader(truncated)); err == nil {
		t.Fatal("expected decoding a truncated file to fail")
	}
	if _, err := DecodeHashesV3(nil); err == nil {
		t.Fatal("expected decoding a nil reader to fail")
	}
}
