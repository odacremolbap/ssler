// +build mage

package main

import (
	"errors"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const cmdPackage = "cmd"

// List of binaries to build.
// They should be packaged under $REPO/cmd/<binary name>
var binaries = []string{"ssler"}

var Default = Build

// Build at the repository root folder
func Build() error {
	log.Println("Building...")
	return build(".")
}

// Install at gopath bin directory
func Install() error {
	mg.Deps(Build)
	log.Println("Installing...")
	goPath, err := sh.Output("go", "env", "GOPATH")
	if err != nil {
		return err
	}
	if len(goPath) == 0 {
		return errors.New("GOPATH is not set")
	}

	paths := strings.Split(goPath, string([]rune{os.PathListSeparator}))
	binPath := filepath.Join(paths[0], "bin")
	return build(binPath)
}

// Clean up
func Clean() error {
	log.Println("Cleaning...")
	for _, b := range binaries {
		if err := os.RemoveAll(b); err != nil {
			return err
		}
	}
	return nil
}

func build(outPath string) error {
	for _, b := range binaries {
		file := path.Join(outPath, b)
		if err := sh.RunV("go", "build", "-o", file, "./"+cmdPackage+"/"+b); err != nil {
			return err
		}
	}
	return nil
}
