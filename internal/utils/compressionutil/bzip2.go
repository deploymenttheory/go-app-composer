package compression

import (
	"fmt"
	"io"
	"os"

	"github.com/dsnet/compress/bzip2"
)

// CompressBZIP2 compresses a file using BZIP2 format
func CompressBZIP2(src, dst string) error {
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

	bzip2Writer, err := bzip2.NewWriter(outputFile, nil)
	if err != nil {
		return err
	}
	defer bzip2Writer.Close()

	_, err = io.Copy(bzip2Writer, inputFile)
	if err != nil {
		return fmt.Errorf("failed to compress file: %w", err)
	}

	return nil
}

// ExtractBZIP2 decompresses a BZIP2 file
func ExtractBZIP2(src, dst string) error {
	inputFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	bzip2Reader, err := bzip2.NewReader(inputFile, nil)
	if err != nil {
		return err
	}

	outputFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, bzip2Reader)
	if err != nil {
		return fmt.Errorf("failed to decompress file: %w", err)
	}

	return nil
}
