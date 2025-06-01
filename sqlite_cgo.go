//go:build cgo && !moderncOnly

package ch

import (
	_ "github.com/mattn/go-sqlite3"
)
