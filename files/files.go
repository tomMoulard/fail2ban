// Package files contains the files management for the plugin.
package files

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// GetFileContent read the file(with the path of the input) and return the
// content of the file as a string.
func GetFileContent(fileName string) (string, error) {
	// Opening the file.
	file, err := os.Open(filepath.Clean(fileName)) // O_RDONLY mode
	if err != nil {
		return "", fmt.Errorf("error opening file: %w", err)
	}

	defer func() { _ = file.Close() }()

	res, err := ioutil.ReadAll(file)

	return string(res), err
}
