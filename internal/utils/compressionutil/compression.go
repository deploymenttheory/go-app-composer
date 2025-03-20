package compression

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var magicNumbers = map[string][]byte{
	"zip":   {0x50, 0x4B, 0x03, 0x04},
	"tar":   {0x75, 0x73, 0x74, 0x61, 0x72},
	"gzip":  {0x1F, 0x8B},
	"bzip2": {0x42, 0x5A, 0x68},
	"xz":    {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00},
}

// DetectArchiveFormat determines the archive format using magic numbers and file extension
func DetectArchiveFormat(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	header := make([]byte, 6)
	_, err = file.Read(header)
	if err != nil && err != io.EOF {
		return "", err
	}

	// Check magic numbers first
	for format, magic := range magicNumbers {
		if bytes.HasPrefix(header, magic) {
			return format, nil
		}
	}

	// Fallback to extension-based detection
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".zip":
		return "zip", nil
	case ".tar":
		return "tar", nil
	case ".gz", ".tgz":
		return "gzip", nil
	case ".bz2", ".tbz2":
		return "bzip2", nil
	case ".xz", ".txz":
		return "xz", nil
	default:
		return "", errors.New("unsupported archive format")
	}
}

// EstimateCompressionSize provides an approximate compressed size for a given source.
func EstimateCompressionSize(src string, format string) (uint64, error) {
	var totalSize uint64

	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += uint64(info.Size())
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to calculate size: %w", err)
	}

	// Approximate compression ratios based on format
	compressionRatios := map[string]float64{
		"zip":   0.60, // ~40% reduction
		"tar":   1.00, // No compression, just packaging
		"gzip":  0.50, // ~50% reduction
		"bzip2": 0.40, // ~60% reduction
		"xz":    0.30, // ~70% reduction
	}

	ratio, exists := compressionRatios[format]
	if !exists {
		return 0, fmt.Errorf("unsupported compression format: %s", format)
	}

	estimatedSize := uint64(float64(totalSize) * ratio)
	return estimatedSize, nil
}
