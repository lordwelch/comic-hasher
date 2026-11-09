//go:build embed

package ch

import _ "embed"

//go:embed hashes.gz
var Hashes []byte
