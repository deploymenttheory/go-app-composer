package compression

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// CompressGZIP compresses a file using GZIP format
func CompressGZIP(src, dst string) error {
	inputFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	outputFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	gzipWriter := gzip.NewWriter(outputFile)
	defer gzipWriter.Close()

	_, err = io.Copy(gzipWriter, inputFile)
	if err != nil {
		return fmt.Errorf("failed to compress file: %w", err)
	}

	return nil
}

// ExtractGZIP decompresses a GZIP file
func ExtractGZIP(src, dst string) error {
	inputFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	gzipReader, err := gzip.NewReader(inputFile)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	outputFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, gzipReader)
	if err != nil {
		return fmt.Errorf("failed to decompress file: %w", err)
	}

	return nil
}
