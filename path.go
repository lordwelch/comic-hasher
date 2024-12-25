package ch

import (
	"os"
	"path/filepath"
)

func RmdirP(path string) error {
	err := os.Remove(path)
	if err != nil {
		return err
	}
	dir, _ := filepath.Split(path)
	_ = RmdirP(dir) // We only care about errors for the first directory we always expect atleast one to fail
	return nil
}
