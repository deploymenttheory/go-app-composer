package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// GenerateRandomKey generates a random key of the specified size
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// DecodeRecoveryKey decodes a recovery key string into a key
// Recovery keys are typically formatted as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
// where each X is a hex digit
func DecodeRecoveryKey(recoveryKey string) ([]byte, error) {
	// Remove any hyphens or spaces
	recoveryKey = strings.ReplaceAll(recoveryKey, "-", "")
	recoveryKey = strings.ReplaceAll(recoveryKey, " ", "")

	// Check if the key is a valid length after removing formatting
	// Accept both 32-character (16 bytes) and 64-character (32 bytes) keys
	if len(recoveryKey) != 32 && len(recoveryKey) != 64 {
		return nil, errors.New("invalid recovery key length")
	}

	// Decode the hex string
	key, err := hex.DecodeString(recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recovery key: %w", err)
	}

	return key, nil
}

// DeriveKeyFromPassword derives a key from a password using SHA-256
// Note: In a production environment, use a proper KDF like PBKDF2 with a salt
func DeriveKeyFromPassword(password string) []byte {
	key := make([]byte, 32)
	h := sha256.New()
	h.Write([]byte(password))
	copy(key, h.Sum(nil))
	return key
}

// ValidateVolumeEncryptionKey validates that a volume encryption key can be used for encryption
func ValidateVolumeEncryptionKey(key []byte) error {
	// Check key length
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return errors.New("volume encryption key must be 256, 384, or 512 bits")
	}

	// Try to create a cipher with the key
	_, err := NewAESXTSCipher(key)
	return err
}

// IsVolumeEncrypted checks if a volume is encrypted based on its flags
func IsVolumeEncrypted(volumeFlags uint64) bool {
	return (volumeFlags & APFSFSUnencrypted) == 0
}

// IsSoftwareEncryption checks if a container uses software encryption
func IsSoftwareEncryption(containerFlags uint64) bool {
	// Check if the NX_CRYPTO_SW flag is set
	return (containerFlags & 0x00000004) != 0
}

// IsOneKeyVolume checks if a volume uses the volume encryption key for all files
func IsOneKeyVolume(volumeFlags uint64) bool {
	return (volumeFlags & APFSFSOnekey) != 0
}

// IsEmptyUUID checks if a UUID is all zeros
func IsEmptyUUID(uuid [16]byte) bool {
	emptyUUID := [16]byte{}
	return bytes.Equal(uuid[:], emptyUUID[:])
}

// GenerateKeybagEntriesForVolume generates the necessary keybag entries for a volume
// This is a simplified implementation for demonstration purposes
func GenerateKeybagEntriesForVolume(volumeUUID [16]byte, password string) (
	volumeKey []byte, containerEntry KeybagEntry, volumeEntry KeybagEntry, err error) {

	// Generate a random volume encryption key (VEK)
	volumeKey, err = GenerateRandomKey(32)
	if err != nil {
		return nil, KeybagEntry{}, KeybagEntry{}, err
	}

	// Derive a key from the password (simplified, should use PBKDF2 with salt)
	passwordKey := DeriveKeyFromPassword(password)

	// Generate a random key encryption key (KEK)
	kek, err := GenerateRandomKey(32)
	if err != nil {
		return nil, KeybagEntry{}, KeybagEntry{}, err
	}

	// Wrap the KEK with the password-derived key
	wrappedKEK, err := WrapKey(passwordKey, kek)
	if err != nil {
		return nil, KeybagEntry{}, KeybagEntry{}, err
	}

	// Wrap the VEK with the KEK
	wrappedVEK, err := WrapKey(kek, volumeKey)
	if err != nil {
		return nil, KeybagEntry{}, KeybagEntry{}, err
	}

	// Create container keybag entry (VEK)
	containerEntry = NewKeybagEntry(volumeUUID, KBTagVolumeKey, wrappedVEK)

	// Create volume keybag entry (KEK)
	// In a real implementation, the UUID would be the user's UUID
	userUUID := [16]byte{}
	volumeEntry = NewKeybagEntry(userUUID, KBTagVolumeUnlockRecords, wrappedKEK)

	return volumeKey, containerEntry, volumeEntry, nil
}

// ParseFixedSizeUUID parses a string UUID into a 16-byte array
func ParseFixedSizeUUID(uuidStr string) ([16]byte, error) {
	var result [16]byte

	// Remove hyphens
	uuidStr = strings.ReplaceAll(uuidStr, "-", "")

	// Check length
	if len(uuidStr) != 32 {
		return result, errors.New("invalid UUID length")
	}

	// Parse hex string
	uuidBytes, err := hex.DecodeString(uuidStr)
	if err != nil {
		return result, err
	}

	// Copy to fixed size array
	copy(result[:], uuidBytes)

	return result, nil
}
