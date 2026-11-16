//go:build gokrazy

package storage

import (
	"errors"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
)

func NewVPTree() (ch.HashStorage, error) {
	return nil, errors.New("VPTree not available")
}
