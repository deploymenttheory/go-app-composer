package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// UnwrapKey unwraps a key using AES key wrapping (RFC 3394)
func UnwrapKey(wrappingKey, wrappedKey []byte) ([]byte, error) {
	if len(wrappingKey) != 16 && len(wrappingKey) != 24 && len(wrappingKey) != 32 {
		return nil, errors.New("invalid wrapping key size")
	}

	if len(wrappedKey) < 8 || len(wrappedKey)%8 != 0 {
		return nil, errors.New("wrapped key invalid size - must be multiple of 8 bytes")
	}

	// Create AES cipher with wrapping key
	c, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	// Implement RFC 3394 Key Unwrapping
	n := (len(wrappedKey) / 8) - 1
	if n < 1 {
		return nil, errors.New("wrapped key too short")
	}

	// Initialize variables
	A := make([]byte, 8)
	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, 8)
	}

	// Copy wrapped data into A and R
	copy(A, wrappedKey[:8])
	for i := 0; i < n; i++ {
		copy(R[i], wrappedKey[8*(i+1):8*(i+2)])
	}

	// Unwrapping process
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// A = MSB(64) of AES-DEC(K, (A ^ t) | R[i])
			t := uint64(n*j + i)

			// Create concatenated block: (A ^ t) | R[i]
			block := make([]byte, 16)

			// XOR A with t
			A_xor_t := make([]byte, 8)
			copy(A_xor_t, A)
			binary.BigEndian.PutUint64(A_xor_t, binary.BigEndian.Uint64(A_xor_t)^t)

			// Concatenate (A ^ t) with R[i]
			copy(block[:8], A_xor_t)
			copy(block[8:], R[i-1])

			// AES decrypt
			output := make([]byte, 16)
			c.Decrypt(output, block)

			// Split result back
			copy(A, output[:8])
			copy(R[i-1], output[8:])
		}
	}

	// Check integrity - RFC 3394 uses a fixed Initial Value (IV)
	// The standard IV is 0xA6A6A6A6A6A6A6A6
	fixedIV := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if !bytes.Equal(A, fixedIV) {
		return nil, errors.New("key unwrapping integrity check failed")
	}

	// Assemble and return the unwrapped key
	unwrappedKey := make([]byte, n*8)
	for i := 0; i < n; i++ {
		copy(unwrappedKey[i*8:], R[i])
	}

	return unwrappedKey, nil
}

// WrapKey wraps a key using AES key wrapping (RFC 3394)
// This is the inverse of UnwrapKey and can be used for testing/validation
func WrapKey(wrappingKey, keyToWrap []byte) ([]byte, error) {
	if len(wrappingKey) != 16 && len(wrappingKey) != 24 && len(wrappingKey) != 32 {
		return nil, errors.New("invalid wrapping key size")
	}

	// The key to wrap must be a multiple of 8 bytes
	if len(keyToWrap) == 0 || len(keyToWrap)%8 != 0 {
		return nil, errors.New("key to wrap must be a multiple of 8 bytes")
	}

	// Create the AES cipher
	c, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	// Implement RFC 3394 Key Wrapping
	n := len(keyToWrap) / 8

	// Initialize variables
	// Fixed IV from RFC 3394
	A := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	R := make([][]byte, n)

	// Split the key into 8-byte blocks
	for i := 0; i < n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], keyToWrap[i*8:(i+1)*8])
	}

	// Wrapping process
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// Concatenate A with R[i]
			block := make([]byte, 16)
			copy(block[:8], A)
			copy(block[8:], R[i-1])

			// AES encrypt
			output := make([]byte, 16)
			c.Encrypt(output, block)

			// Calculate t value
			t := uint64(n*j + i)

			// A = MSB(64, AES(K, A|R[i])) ^ t
			copy(A, output[:8])

			// XOR A with t
			binary.BigEndian.PutUint64(A, binary.BigEndian.Uint64(A)^t)

			// R[i] = LSB(64, AES(K, A|R[i]))
			copy(R[i-1], output[8:])
		}
	}

	// Assemble the wrapped key
	wrappedKey := make([]byte, (n+1)*8)
	copy(wrappedKey[:8], A)
	for i := 0; i < n; i++ {
		copy(wrappedKey[8*(i+1):], R[i])
	}

	return wrappedKey, nil
}
