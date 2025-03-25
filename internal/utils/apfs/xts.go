
package apfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/xts"
)

// AESXTSCipher implements AES-XTS encryption/decryption using Go's crypto libraries
type AESXTSCipher struct {
	cipher cipher.BlockMode
	blockSize int
}

// NewAESXTSCipher creates a new AES-XTS cipher
func NewAESXTSCipher(key []byte) (*AESXTSCipher, error) {
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
	xtsCipher, err := xts.NewCipher(c1, c2)
	if err != nil {
		return nil, err
	}
	
	return &AESXTSCipher{
		cipher: xtsCipher,
		blockSize: 16, // AES block size is always 16 bytes
	}, nil
}

// Encrypt encrypts data using AES-XTS
func (c *AESXTSCipher) Encrypt(dst, src []byte, tweak []byte) error {
	if len(dst) < len(src) {
		return errors.New("output buffer too small")
	}
	
	if len(src) == 0 || len(src)%c.blockSize != 0 {
		return errors.New("input length must be a multiple of the block size")
	}
	
	if len(tweak) < c.blockSize {
		return errors.New("tweak must be at least block size bytes")
	}
	
	// Use the XTS cipher to encrypt the data
	c.cipher.Encrypt(dst, src, tweak[:16])
	
	return nil
}

// Decrypt decrypts data using AES-XTS
func (c *AESXTSCipher) Decrypt(dst, src []byte, tweak []byte) error {
	if len(dst) < len(src) {
		return errors.New("output buffer too small")
	}
	
	if len(src) == 0 || len(src)%c.blockSize != 0 {
		return errors.New("input length must be a multiple of the block size")
	}
	
	if len(tweak) < c.blockSize {
		return errors.New("tweak must be at least block size bytes")
	}
	
	// Use the XTS cipher to decrypt the data
	c.cipher.Decrypt(dst, src, tweak[:16])
	
	return nil
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

// EncryptionContext manages encryption/decryption operations
type EncryptionContext struct {
	containerUUID        [16]byte
	volumeUUID           [16]byte
	volumeEncryptionKey  []byte
	usesSoftwareEncryption bool
	isDecrypted          bool
}

// NewEncryptionContext creates a new encryption context
func NewEncryptionContext(volumeUUID, containerUUID [16]byte) *EncryptionContext {
	return &EncryptionContext{
		volumeUUID:            volumeUUID,
		containerUUID:         containerUUID,
		usesSoftwareEncryption: true,
		isDecrypted:           false,
	}
}

// IsDecrypted returns whether the volume has been decrypted
func (ec *EncryptionContext) IsDecrypted() bool {
	return ec.isDecrypted
}

// SetVolumeEncryptionKey sets the volume encryption key
func (ec *EncryptionContext) SetVolumeEncryptionKey(key []byte) {
	ec.volumeEncryptionKey = key
	ec.isDecrypted = true
}

// UnlockWithPassword unlocks the volume with a password
func (ec *EncryptionContext) UnlockWithPassword(password string, containerKeybag, volumeKeybag *KBLocker) error {
	if containerKeybag == nil || volumeKeybag == nil {
		return errors.New("keybags are required for unlocking")
	}
	
	// Find the volume key entry in the container keybag
	volumeKeyEntry := containerKeybag.FindEntry(ec.volumeUUID, KBTagVolumeKey)
	if volumeKeyEntry == nil {
		return errors.New("volume key not found in container keybag")
	}
	
	// Find the user's KEK in the volume keybag
	var kekEntry *KeybagEntry
	for i := range volumeKeybag.Entries {
		if volumeKeybag.Entries[i].Tag == KBTagVolumeUnlockRecords {
			kekEntry = &volumeKeybag.Entries[i]
			break
		}
	}
	
	if kekEntry == nil {
		return errors.New("no unlock records found in volume keybag")
	}
	
	// Derive a key from the password using SHA-256
	// In a real implementation, this would use PBKDF2 with salt and iterations
	passDerivedKey := make([]byte, 32)
	h := sha256.New()
	h.Write([]byte(password))
	copy(passDerivedKey, h.Sum(nil))
	
	// Use the derived key to unwrap the KEK
	kek, err := UnwrapKey(passDerivedKey, kekEntry.KeyData)
	if err != nil {
		return fmt.Errorf("failed to unwrap KEK: %w", err)
	}
	
	// Use the KEK to unwrap the VEK
	vek, err := UnwrapKey(kek, volumeKeyEntry.KeyData)
	if err != nil {
		return fmt.Errorf("failed to unwrap VEK: %w", err)
	}
	
	// Store the VEK in the encryption context
	ec.volumeEncryptionKey = vek
	ec.isDecrypted = true
	
	return nil
}

// DecryptBlock decrypts a block of data using AES-XTS
func (ec *EncryptionContext) DecryptBlock(data []byte, physBlockNum, cryptoID uint64) ([]byte, error) {
	if !ec.isDecrypted {
		return nil, errors.New("volume not decrypted")
	}
	
	// Create the XTS cipher with VEK
	cipher, err := NewAESXTSCipher(ec.volumeEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-XTS cipher: %w", err)
	}
	
	// Create tweak value from the crypto ID and block number
	tweak := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweak, cryptoID)
	binary.LittleEndian.PutUint64(tweak[8:], physBlockNum)
	
	// Decrypt the data
	decrypted := make([]byte, len(data))
	err = cipher.Decrypt(decrypted, data, tweak)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt block: %w", err)
	}
	
	return decrypted, nil
}

// EncryptBlock encrypts a block of data using AES-XTS
func (ec *EncryptionContext) EncryptBlock(data []byte, physBlockNum, cryptoID uint64) ([]byte, error) {
	if !ec.isDecrypted {
		return nil, errors.New("volume not decrypted")
	}
	
	// Create the XTS cipher with VEK
	cipher, err := NewAESXTSCipher(ec.volumeEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-XTS cipher: %w", err)
	}
	
	// Create tweak value from the crypto ID and block number
	tweak := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweak, cryptoID)
	binary.LittleEndian.PutUint64(tweak[8:], physBlockNum)
	
	// Encrypt the data
	encrypted := make([]byte, len(data))
	err = cipher.Encrypt(encrypted, data, tweak)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt block: %w", err)
	}
	
	return encrypted, nil
}
