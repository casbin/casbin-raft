package util

import (
	"os"
)

// DirExists checks if the path exists and is a directory
func DirExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		return info.IsDir(), nil
	} else if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// MkdirAll creates a directory named path, along with any necessary parents.
func MkdirAll(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}
