package compression

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CompressZIP creates a ZIP archive from a given source directory or file
func CompressZIP(src, dst string) error {
	zipFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(filepath.Dir(src), path)
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}
		_, err = io.Copy(zipEntry, file)
		return err
	})
}

// ExtractZIP extracts a ZIP archive to the given destination
func ExtractZIP(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dst, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.Create(fpath)
		if err != nil {
			return err
		}
		defer outFile.Close()

		zippedFile, err := f.Open()
		if err != nil {
			return err
		}
		defer zippedFile.Close()

		_, err = io.Copy(outFile, zippedFile)
		if err != nil {
			return err
		}
	}

	return nil
}
