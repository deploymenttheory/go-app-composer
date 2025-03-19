package compression

import (
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz"
)

// CompressXZ compresses a file using XZ format
func CompressXZ(src, dst string) error {
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

	xzWriter, err := xz.NewWriter(outputFile)
	if err != nil {
		return err
	}
	defer xzWriter.Close()

	_, err = io.Copy(xzWriter, inputFile)
	if err != nil {
		return fmt.Errorf("failed to compress file: %w", err)
	}

	return nil
}

// ExtractXZ decompresses an XZ file
func ExtractXZ(src, dst string) error {
	inputFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	xzReader, err := xz.NewReader(inputFile)
	if err != nil {
		return err
	}

	outputFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, xzReader)
	if err != nil {
		return fmt.Errorf("failed to decompress file: %w", err)
	}

	return nil
}
