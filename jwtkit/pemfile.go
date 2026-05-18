package jwtkit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// readPEMFile reads bytes from a single local file path using the directory FS API
// so reads are constrained to the file's parent directory and basename.
func readPEMFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is empty")
	}
	if strings.Contains(path, "\x00") {
		return nil, errors.New("invalid path")
	}

	clean := filepath.Clean(path)
	dir, file := filepath.Split(clean)
	if file == "" || file == "." {
		return nil, errors.New("path must name a file")
	}
	if strings.Contains(file, "..") {
		return nil, errors.New("invalid file name")
	}
	if dir == "" {
		dir = "."
	}

	return fs.ReadFile(os.DirFS(dir), file)
}
