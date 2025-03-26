package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAESXTSCipher(t *testing.T) {
	// Test key sizes
	validKeySizes := []int{32, 48, 64} // 256, 384, 512 bits

	for _, keySize := range validKeySizes {
		// Generate a random key
		key := make([]byte, keySize)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}

		// Create cipher
		cipher, err := NewAESXTSCipher(key)
		if err != nil {
			t.Fatalf("Failed to create AES-XTS cipher with %d-byte key: %v", keySize, err)
		}

		// Test data (must be a multiple of block size)
		data := make([]byte, 64)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("Failed to generate random data: %v", err)
		}

		// Generate tweak
		tweak := CreateTweak(123, 456)

		// Encrypt
		encrypted := make([]byte, len(data))
		err = cipher.Encrypt(encrypted, data, tweak)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Verify that encrypted data is different
		if bytes.Equal(data, encrypted) {
			t.Error("Encrypted data matches original data")
		}

		// Decrypt
		decrypted := make([]byte, len(encrypted))
		err = cipher.Decrypt(decrypted, encrypted, tweak)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Verify decryption
		if !bytes.Equal(data, decrypted) {
			t.Error("Decrypted data does not match original data")
		}
	}

	// Test invalid key size
	_, err := NewAESXTSCipher(make([]byte, 24))
	if err == nil {
		t.Error("Expected error for invalid key size, got nil")
	}
}

func TestKeyWrapping(t *testing.T) {
	// Generate a random wrapping key
	wrappingKey := make([]byte, 32)
	if _, err := rand.Read(wrappingKey); err != nil {
		t.Fatalf("Failed to generate random wrapping key: %v", err)
	}

	// Generate a random key to wrap
	keyToWrap := make([]byte, 32)
	if _, err := rand.Read(keyToWrap); err != nil {
		t.Fatalf("Failed to generate random key to wrap: %v", err)
	}

	// Wrap the key
	wrappedKey, err := WrapKey(wrappingKey, keyToWrap)
	if err != nil {
		t.Fatalf("Key wrapping failed: %v", err)
	}

	// Verify that wrapped key is different
	if bytes.Equal(keyToWrap, wrappedKey) {
		t.Error("Wrapped key matches original key")
	}

	// Unwrap the key
	unwrappedKey, err := UnwrapKey(wrappingKey, wrappedKey)
	if err != nil {
		t.Fatalf("Key unwrapping failed: %v", err)
	}

	// Verify unwrapping
	if !bytes.Equal(keyToWrap, unwrappedKey) {
		t.Errorf("Unwrapped key does not match original key:\nOriginal: %s\nUnwrapped: %s",
			hex.EncodeToString(keyToWrap), hex.EncodeToString(unwrappedKey))
	}

	// Test unwrapping with wrong key
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("Failed to generate random wrong key: %v", err)
	}

	_, err = UnwrapKey(wrongKey, wrappedKey)
	if err == nil {
		t.Error("Expected error when unwrapping with wrong key, got nil")
	}
}

func TestKeybag(t *testing.T) {
	// Create a keybag
	keybag := NewKBLocker()

	// Generate a test UUID
	testUUID := [16]byte{}
	if _, err := rand.Read(testUUID[:]); err != nil {
		t.Fatalf("Failed to generate random UUID: %v", err)
	}

	// Add an entry
	testData := []byte("test key data")
	entry := NewKeybagEntry(testUUID, KBTagVolumeKey, testData)
	keybag.AddEntry(entry)

	// Find the entry
	foundEntry := keybag.FindEntry(testUUID, KBTagVolumeKey)
	if foundEntry == nil {
		t.Fatal("Failed to find entry in keybag")
	}

	// Verify entry data
	if !bytes.Equal(foundEntry.KeyData, testData) {
		t.Error("Found entry data does not match original")
	}

	// Serialize keybag
	serialized, err := keybag.Serialize()
	if err != nil {
		t.Fatalf("Keybag serialization failed: %v", err)
	}

	// Create a new keybag and parse the serialized data
	parsedKeybag := NewKBLocker()
	err = parsedKeybag.Parse(serialized)
	if err != nil {
		t.Fatalf("Keybag parsing failed: %v", err)
	}

	// Verify parsed keybag
	if parsedKeybag.NKeys != keybag.NKeys {
		t.Errorf("Parsed keybag has %d keys, expected %d", parsedKeybag.NKeys, keybag.NKeys)
	}

	// Find entry in parsed keybag
	parsedEntry := parsedKeybag.FindEntry(testUUID, KBTagVolumeKey)
	if parsedEntry == nil {
		t.Fatal("Failed to find entry in parsed keybag")
	}

	// Verify parsed entry data
	if !bytes.Equal(parsedEntry.KeyData, testData) {
		t.Error("Parsed entry data does not match original")
	}

	// Remove entry
	removed := keybag.RemoveEntry(testUUID, KBTagVolumeKey)
	if !removed {
		t.Error("Failed to remove entry from keybag")
	}

	// Verify entry was removed
	if keybag.FindEntry(testUUID, KBTagVolumeKey) != nil {
		t.Error("Entry still exists after removal")
	}
}

func TestEncryptionContext(t *testing.T) {
	// Generate UUIDs
	containerUUID := [16]byte{}
	volumeUUID := [16]byte{}
	if _, err := rand.Read(containerUUID[:]); err != nil {
		t.Fatalf("Failed to generate random container UUID: %v", err)
	}
	if _, err := rand.Read(volumeUUID[:]); err != nil {
		t.Fatalf("Failed to generate random volume UUID: %v", err)
	}

	// Create encryption context
	context := NewEncryptionContext(volumeUUID, containerUUID)

	// Test without key
	if context.IsDecrypted {
		t.Error("Context should not be decrypted")
	}

	// Test block encryption with no key
	testData := make([]byte, 4096)
	if _, err := rand.Read(testData); err != nil {
		t.Fatalf("Failed to generate random test data: %v", err)
	}

	_, err := context.EncryptBlock(testData, 123, 456)
	if err == nil {
		t.Error("Expected error when encrypting without key, got nil")
	}

	// Set key
	vek := make([]byte, 32)
	if _, err := rand.Read(vek); err != nil {
		t.Fatalf("Failed to generate random VEK: %v", err)
	}
	context.SetVolumeEncryptionKey(vek)

	// Test with key
	if !context.IsDecrypted {
		t.Error("Context should be decrypted")
	}

	// Test block encryption with key
	encrypted, err := context.EncryptBlock(testData, 123, 456)
	if err != nil {
		t.Fatalf("Block encryption failed: %v", err)
	}

	// Verify that encrypted data is different
	if bytes.Equal(testData, encrypted) {
		t.Error("Encrypted data matches original data")
	}

	// Test block decryption
	decrypted, err := context.DecryptBlock(encrypted, 123, 456)
	if err != nil {
		t.Fatalf("Block decryption failed: %v", err)
	}

	// Verify decryption
	if !bytes.Equal(testData, decrypted) {
		t.Error("Decrypted data does not match original data")
	}
}

func TestUtilityFunctions(t *testing.T) {
	// Test random key generation
	key, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Generated key has length %d, expected 32", len(key))
	}

	// Test recovery key decoding
	testRecoveryKey := "1234-5678-90AB-CDEF-1234-5678-90AB-CDEF"
	decoded, err := DecodeRecoveryKey(testRecoveryKey)
	if err != nil {
		t.Fatalf("Recovery key decoding failed: %v", err)
	}
	expected, _ := hex.DecodeString("1234567890ABCDEF1234567890ABCDEF")
	if !bytes.Equal(decoded, expected) {
		t.Errorf("Decoded recovery key does not match expected")
	}

	// Test key derivation from password
	password := "test password"
	derivedKey := DeriveKeyFromPassword(password)
	if len(derivedKey) != 32 {
		t.Errorf("Derived key has length %d, expected 32", len(derivedKey))
	}

	// Derive key again from same password
	derivedKey2 := DeriveKeyFromPassword(password)
	if !bytes.Equal(derivedKey, derivedKey2) {
		t.Error("Key derivation from same password yields different keys")
	}

	// Test encryption flag checking
	if !IsVolumeEncrypted(0) {
		t.Error("Volume with flags 0 should be considered encrypted")
	}
	if IsVolumeEncrypted(APFSFSUnencrypted) {
		t.Error("Volume with APFSFSUnencrypted flag should not be considered encrypted")
	}

	// Test UUID parsing
	testUUIDStr := "550e8400-e29b-41d4-a716-446655440000"
	parsedUUID, err := ParseFixedSizeUUID(testUUIDStr)
	if err != nil {
		t.Fatalf("UUID parsing failed: %v", err)
	}
	expectedUUID, _ := hex.DecodeString("550e8400e29b41d4a716446655440000")
	var expectedFixedUUID [16]byte
	copy(expectedFixedUUID[:], expectedUUID)
	if parsedUUID != expectedFixedUUID {
		t.Error("Parsed UUID does not match expected")
	}
}

func TestKeybagGeneration(t *testing.T) {
	// Generate a test volume UUID
	volumeUUID := [16]byte{}
	if _, err := rand.Read(volumeUUID[:]); err != nil {
		t.Fatalf("Failed to generate random volume UUID: %v", err)
	}

	// Generate keybag entries
	volumeKey, containerEntry, volumeEntry, err := GenerateKeybagEntriesForVolume(volumeUUID, "test password")
	if err != nil {
		t.Fatalf("Keybag generation failed: %v", err)
	}

	// Verify volume key
	if len(volumeKey) != 32 {
		t.Errorf("Volume key has length %d, expected 32", len(volumeKey))
	}

	// Verify container entry
	if !bytes.Equal(containerEntry.UUID[:], volumeUUID[:]) {
		t.Error("Container entry UUID does not match volume UUID")
	}
	if containerEntry.Tag != KBTagVolumeKey {
		t.Errorf("Container entry tag is %d, expected %d", containerEntry.Tag, KBTagVolumeKey)
	}

	// Verify volume entry
	if volumeEntry.Tag != KBTagVolumeUnlockRecords {
		t.Errorf("Volume entry tag is %d, expected %d", volumeEntry.Tag, KBTagVolumeUnlockRecords)
	}
}

func TestRecoveryKeyFormats(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{"Standard format with hyphens (32 chars)", "1234-5678-90AB-CDEF-1234-5678-90AB-CDEF", false},
		{"No hyphens (32 chars)", "1234567890ABCDEF1234567890ABCDEF", false},
		{"With spaces (32 chars)", "1234 5678 90AB CDEF 1234 5678 90AB CDEF", false},
		{"Mixed format (32 chars)", "1234-5678 90AB-CDEF 1234-5678 90AB-CDEF", false},
		{"Standard format with hyphens (64 chars)", "1234-5678-90AB-CDEF-1234-5678-90AB-CDEF-1234-5678-90AB-CDEF-1234-5678-90AB-CDEF", false},
		{"Invalid characters", "1234-5678-90AB-CDEG-1234-5678-90AB-CDEF", true}, // G is not a hex digit
		{"Invalid length", "1234-5678-90AB", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeRecoveryKey(tc.input)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				} else {
					// Check that the output is a valid length
					expectedLen := len(tc.input) / 2
					if strings.Contains(tc.input, "-") || strings.Contains(tc.input, " ") {
						// Adjust for formatting characters
						expectedLen = (len(strings.ReplaceAll(strings.ReplaceAll(tc.input, "-", ""), " ", "")) + 1) / 2
					}
					if len(decoded) != expectedLen {
						t.Errorf("Expected decoded length %d, got %d", expectedLen, len(decoded))
					}
				}
			}
		})
	}
}
