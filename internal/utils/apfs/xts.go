//
package apfs

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/xts"
)

// NewAESXTSCipher creates a new AES-XTS cipher using the golang.org/x/crypto/xts package
func NewAESXTSCipher(key []byte) (cipher.BlockMode, error) {
	// AES-XTS requires two keys of equal length
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, errors.New("AES-XTS key must be 256, 384 or 512 bits (two AES keys)")
	}
	
	// Split the key into two equal parts
	keySize := len(key) / 2
	
	// Create the AES ciphers for both keys
	c1, err := aes.NewCipher(key[:keySize])
	if err != nil {
		return nil, err
	}
	
	c2, err := aes.NewCipher(key[keySize:])
	if err != nil {
		return nil, err
	}
	
	// Create XTS cipher with the two keys
	xtsMode, err := xts.NewCipher(c1, c2)
	if err != nil {
		return nil, err
	}
	
	return xtsMode, nil
}

// EncryptBlock encrypts a block of data using AES-XTS
func EncryptBlock(data []byte, physBlockNum, cryptoID uint64, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("input length must be a multiple of the block size (16 bytes)")
	}
	
	// Create the XTS cipher
	cipher, err := NewAESXTSCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-XTS cipher: %w", err)
	}
	
	// Create tweak value from the crypto ID and block number
	tweak := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweak, cryptoID)
	binary.LittleEndian.PutUint64(tweak[8:], physBlockNum)
	
	// Encrypt the data
	encrypted := make([]byte, len(data))
	cipher.Encrypt(encrypted, data, tweak)
	
	return encrypted, nil
}

// DecryptBlock decrypts a block of data using AES-XTS
func DecryptBlock(data []byte, physBlockNum, cryptoID uint64, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("input length must be a multiple of the block size (16 bytes)")
	}
	
	// Create the XTS cipher
	cipher, err := NewAESXTSCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-XTS cipher: %w", err)
	}
	
	// Create tweak value from the crypto ID and block number
	tweak := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweak, cryptoID)
	binary.LittleEndian.PutUint64(tweak[8:], physBlockNum)
	
	// Decrypt the data
	decrypted := make([]byte, len(data))
	cipher.Decrypt(decrypted, data, tweak)
	
	return decrypted, nil
}

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
	if !byteArrayEqual(A, fixedIV) {
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
func WrapKey(wrappingKey, keyToWrap []byte) ([]byte, error) {
	if len(wrappingKey) != 16 && len(wrappingKey) != 24 && len(wrappingKey) != 32 {
		return nil, errors.New("invalid wrapping key size")
	}
	
	// Ensure the input key length is a multiple of 8 bytes
	if len(keyToWrap) == 0 || len(keyToWrap)%8 != 0 {
		return nil, errors.New("key to wrap must be a multiple of 8 bytes")
	}
	
	// Create AES cipher with wrapping key
	c, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	
	// RFC 3394 key wrapping
	n := len(keyToWrap) / 8
	
	// Initialize variables
	A := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6} // Initial value
	
	// Set up the R array - blocks of plaintext
	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], keyToWrap[i*8:(i+1)*8])
	}
	
	// Wrapping process
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// Concatenate A and R[i]
			block := make([]byte, 16)
			copy(block[:8], A)
			copy(block[8:], R[i-1])
			
			// AES encrypt
			output := make([]byte, 16)
			c.Encrypt(output, block)
			
			// Calculate t value
			t := uint64(n*j + i)
			
			// Extract new A and R[i] values
			copy(A, output[:8])
			
			// XOR A with t
			value := binary.BigEndian.Uint64(A)
			value ^= t
			binary.BigEndian.PutUint64(A, value)
			
			copy(R[i-1], output[8:])
		}
	}
	
	// Assemble final output
	wrappedKey := make([]byte, (n+1)*8)
	copy(wrappedKey[:8], A)
	for i := 0; i < n; i++ {
		copy(wrappedKey[8*(i+1):8*(i+2)], R[i])
	}
	
	return wrappedKey, nil
}

// byteArrayEqual compares two byte arrays
func byteArrayEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
