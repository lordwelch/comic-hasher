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
	for path != "" {
		dir, _ := filepath.Split(path)
		err := os.Remove(dir)
		if err != nil {
			return nil // We only care about errors for the first directory we always expect atleast one to fail
		}
	}
	return nil
}
