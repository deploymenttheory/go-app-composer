package cryptoutil

import (
	"hash"

	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
)

// HashWriter implements io.Writer and provides methods to access the underlying hash
type HashWriter struct {
	hash hash.Hash
}

// Write implements io.Writer
func (hw *HashWriter) Write(p []byte) (n int, err error) {
	return hw.hash.Write(p)
}

// Sum returns the current hash value
func (hw *HashWriter) Sum(b []byte) []byte {
	return hw.hash.Sum(b)
}

// SumHex returns the current hash value as a hex-encoded string
func (hw *HashWriter) SumHex() string {
	return Bytes2Hex(hw.hash.Sum(nil))
}

// Reset resets the hash state
func (hw *HashWriter) Reset() {
	hw.hash.Reset()
}

// Size returns the hash's output size in bytes
func (hw *HashWriter) Size() int {
	return hw.hash.Size()
}

// BlockSize returns the hash's underlying block size in bytes
func (hw *HashWriter) BlockSize() int {
	return hw.hash.BlockSize()
}

// NewHashWriter creates a new HashWriter with the given hash algorithm
func NewHashWriter(algorithm HashAlgorithm) (*HashWriter, error) {
	hasher, err := NewHasher(algorithm)
	if err != nil {
		return nil, err
	}

	hashImpl, ok := hasher.(*hasherImpl)
	if !ok {
		return nil, errors.ErrInvalidHasher
	}

	return &HashWriter{
		hash: hashImpl.newHash(),
	}, nil
}
