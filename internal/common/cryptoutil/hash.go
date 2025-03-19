// Package cryptoutil provides cryptographic utilities for hashing, encryption, and signature operations
package cryptoutil

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	commonerrors "github.com/deploymenttheory/go-app-composer/internal/common/errors"
)

// Custom errors
var (
	ErrInvalidHasher = errors.New("invalid hasher implementation")
)

// Bytes2Hex encodes a byte slice to hex string
func Bytes2Hex(d []byte) string {
	return hex.EncodeToString(d)
}

// HashAlgorithm represents supported hash algorithms
type HashAlgorithm string

const (
	// MD5 algorithm (not recommended for security-critical applications)
	MD5 HashAlgorithm = "md5"

	// SHA1 algorithm (not recommended for security-critical applications)
	SHA1 HashAlgorithm = "sha1"

	// SHA256 algorithm
	SHA256 HashAlgorithm = "sha256"

	// SHA512 algorithm
	SHA512 HashAlgorithm = "sha512"
)

// Hasher provides an interface for hashing operations
type Hasher interface {
	// Hash hashes the provided data
	Hash(data []byte) (string, error)

	// HashFile hashes the content of a file
	HashFile(path string) (string, error)

	// HashReader hashes data from a reader
	HashReader(reader io.Reader) (string, error)

	// NewHashWriter creates a writer for streaming hash calculation
	NewHashWriter() (io.Writer, error)

	// Verify checks if the provided hash matches the calculated hash for the data
	Verify(data []byte, expectedHash string) (bool, error)

	// VerifyFile checks if the provided hash matches the calculated hash for the file
	VerifyFile(path string, expectedHash string) (bool, error)
}

// hasherImpl implements the Hasher interface
type hasherImpl struct {
	algorithm HashAlgorithm
	newHash   func() hash.Hash
}

// NewHasher creates a new Hasher for the specified algorithm
func NewHasher(algorithm HashAlgorithm) (Hasher, error) {
	var newHashFunc func() hash.Hash

	switch strings.ToLower(string(algorithm)) {
	case string(MD5):
		newHashFunc = md5.New
	case string(SHA1):
		newHashFunc = sha1.New
	case string(SHA256):
		newHashFunc = sha256.New
	case string(SHA512):
		newHashFunc = sha512.New
	default:
		return nil, fmt.Errorf("%w: unsupported hash algorithm '%s'", commonerrors.ErrInvalidArgument, algorithm)
	}

	return &hasherImpl{
		algorithm: algorithm,
		newHash:   newHashFunc,
	}, nil
}

// Hash hashes the provided data
func (h *hasherImpl) Hash(data []byte) (string, error) {
	hasher := h.newHash()
	_, err := hasher.Write(data)
	if err != nil {
		return "", fmt.Errorf("hash operation failed: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// HashFile hashes the content of a file
func (h *hasherImpl) HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", commonerrors.ErrFileNotFound, path)
		}
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	return h.HashReader(file)
}

// HashReader hashes data from a reader
func (h *hasherImpl) HashReader(reader io.Reader) (string, error) {
	hasher := h.newHash()
	_, err := io.Copy(hasher, reader)
	if err != nil {
		return "", fmt.Errorf("hash operation failed: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// NewHashWriter creates a writer for streaming hash calculation
func (h *hasherImpl) NewHashWriter() (io.Writer, error) {
	return &HashWriter{
		hash: h.newHash(),
	}, nil
}

// Verify checks if the provided hash matches the calculated hash for the data
func (h *hasherImpl) Verify(data []byte, expectedHash string) (bool, error) {
	actualHash, err := h.Hash(data)
	if err != nil {
		return false, err
	}

	return strings.EqualFold(actualHash, expectedHash), nil
}

// VerifyFile checks if the provided hash matches the calculated hash for the file
func (h *hasherImpl) VerifyFile(path string, expectedHash string) (bool, error) {
	actualHash, err := h.HashFile(path)
	if err != nil {
		return false, err
	}

	return strings.EqualFold(actualHash, expectedHash), nil
}

// ParseHashWithAlgorithm parses a hash string that might include the algorithm as a prefix
// Example formats: "sha256:1234abcd..." or "1234abcd..."
func ParseHashWithAlgorithm(hashStr string) (string, HashAlgorithm) {
	parts := strings.SplitN(hashStr, ":", 2)

	if len(parts) == 2 {
		algorithmStr := strings.ToLower(parts[0])
		hash := parts[1]

		// Check if the algorithm part is a known algorithm
		switch algorithmStr {
		case string(MD5), string(SHA1), string(SHA256), string(SHA512):
			return hash, HashAlgorithm(algorithmStr)
		}
	}

	// If no algorithm was specified or it wasn't recognized, just return the hash as-is
	return hashStr, ""
}

// CalculateFileChecksum calculates a file's checksum using the specified algorithm
func CalculateFileChecksum(filePath string, algorithm HashAlgorithm) (string, error) {
	hasher, err := NewHasher(algorithm)
	if err != nil {
		return "", err
	}

	return hasher.HashFile(filePath)
}

// VerifyFileChecksum verifies a file's checksum against an expected value
func VerifyFileChecksum(filePath, expectedChecksum string, algorithm HashAlgorithm) (bool, error) {
	hasher, err := NewHasher(algorithm)
	if err != nil {
		return false, err
	}

	return hasher.VerifyFile(filePath, expectedChecksum)
}

// VerifyChecksumFile verifies a file against a checksum file
// The checksum file should contain the hash as the first field on each line
func VerifyChecksumFile(filePath, checksumFilePath string, algorithm HashAlgorithm) (bool, error) {
	// Read the checksum file
	data, err := os.ReadFile(checksumFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, fmt.Errorf("%w: %s", commonerrors.ErrFileNotFound, checksumFilePath)
		}
		return false, fmt.Errorf("failed to read checksum file: %w", err)
	}

	// Parse the checksum (typically the first word in the file)
	checksumStr := strings.TrimSpace(string(data))
	fields := strings.Fields(checksumStr)
	if len(fields) == 0 {
		return false, fmt.Errorf("checksum file is empty or malformed")
	}

	expectedChecksum := fields[0]

	// If there are two fields and the second looks like a filename with an asterisk prefix,
	// the first field is likely the checksum (common format in checksum files)
	if len(fields) >= 2 && strings.HasPrefix(fields[1], "*") {
		expectedChecksum = fields[0]
	} else if len(fields) >= 2 && !strings.HasPrefix(fields[0], "*") && strings.HasPrefix(fields[1], "*") {
		// Format where checksum is first, then filename with asterisk
		expectedChecksum = fields[0]
	} else if len(fields) >= 2 && strings.HasPrefix(fields[0], "*") && !strings.HasPrefix(fields[1], "*") {
		// Format where filename with asterisk is first, then checksum
		expectedChecksum = fields[1]
	}

	// Verify the checksum
	hasher, err := NewHasher(algorithm)
	if err != nil {
		return false, err
	}

	return hasher.VerifyFile(filePath, expectedChecksum)
}
