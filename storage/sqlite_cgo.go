//go:build cgo && !gokrazy

package storage

import (
	_ "github.com/mattn/go-sqlite3"
)
