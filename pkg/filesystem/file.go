package filesystem

import (
	"io/ioutil"
	"os"
)

// WriteContentsToFile writes a string into a file
func WriteContentsToFile(path, contents string) error {

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(contents)
	return err

}

// ReadContentsFromFile reads all bytes from a file
func ReadContentsFromFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}
