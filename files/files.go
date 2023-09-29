package files

import (
	"io/ioutil"
	"os"
)

// GetFileContent read the file(with the path of the input) and return the
// content of the file as a string
func GetFileContent(fileName string) (string, error) {
	// Opening the file.
	file, err := os.Open(fileName) // O_RDONLY mode
	if err != nil {
		return "", err
	}
	defer file.Close()

	res, err := ioutil.ReadAll(file)

	return string(res), err
}
