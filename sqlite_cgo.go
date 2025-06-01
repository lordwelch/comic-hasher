//go:build cgo && !gokrazy

package ch

import (
	_ "github.com/mattn/go-sqlite3"
)
