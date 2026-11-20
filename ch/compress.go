package ch

import (
	minlz "github.com/minio/minlz"
)

// DecompressMinLZ returns the decoded data if src is minlz encoded.
// Data that is not minlz encoded, such as the raw text stored before
// compression was added, is returned unchanged.
func DecompressMinLZ(src []byte) []byte {
	ok, _, err := minlz.IsMinLZ(src)
	if err != nil || !ok {
		return src
	}
	decoded, err := minlz.Decode(nil, src)
	if err != nil {
		return src
	}
	return decoded
}
