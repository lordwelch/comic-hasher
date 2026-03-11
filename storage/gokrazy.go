//go:build gokrazy

package storage

import (
	"errors"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
)

func NewVPStorage() (ch.HashStorage, error) {
	return nil, errors.New("VPTree not available")
}

func NewSqliteStorage(db, path string) (ch.HashStorage, error) {
	return nil, errors.New("sqlite not available")
}
