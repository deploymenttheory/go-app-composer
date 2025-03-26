package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// NewEncryptionContext creates a new encryption context
func NewEncryptionContext(volumeUUID, containerUUID [16]byte) *EncryptionContext {
	return &EncryptionContext{
		VolumeUUID:             volumeUUID,
		ContainerUUID:          containerUUID,
		UsesSoftwareEncryption: true,
		IsDecrypted:            false,
	}
}

// SetVolumeEncryptionKey sets the volume encryption key
func (ec *EncryptionContext) SetVolumeEncryptionKey(key []byte) {
	ec.VolumeEncryptionKey = key
	ec.IsDecrypted = true
}

// UnlockWithPassword unlocks the volume with a password
func (ec *EncryptionContext) UnlockWithPassword(password string, containerKeybag, volumeKeybag *KBLocker) error {
	if containerKeybag == nil || volumeKeybag == nil {
		return errors.New("keybags are required for unlocking")
	}

	// Find the volume key entry in the container keybag
	volumeKeyEntry := containerKeybag.FindEntry(ec.VolumeUUID, KBTagVolumeKey)
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
	ec.VolumeEncryptionKey = vek
	ec.IsDecrypted = true

	return nil
}

// UnlockWithRecoveryKey unlocks the volume with a recovery key
func (ec *EncryptionContext) UnlockWithRecoveryKey(recoveryKey string, containerKeybag, volumeKeybag *KBLocker) error {
	if containerKeybag == nil || volumeKeybag == nil {
		return errors.New("keybags are required for unlocking")
	}

	// Find the recovery key entry in the volume keybag
	var recoveryKeyUUID [16]byte
	copy(recoveryKeyUUID[:], []byte(APFSFVPersonalRecoveryKeyUUID))

	recoveryEntry := volumeKeybag.FindEntry(recoveryKeyUUID, KBTagVolumeUnlockRecords)
	if recoveryEntry == nil {
		return errors.New("recovery key entry not found in volume keybag")
	}

	// Find the volume key entry in the container keybag
	volumeKeyEntry := containerKeybag.FindEntry(ec.VolumeUUID, KBTagVolumeKey)
	if volumeKeyEntry == nil {
		return errors.New("volume key not found in container keybag")
	}

	// Derive a key from the recovery key
	// In a real implementation, the recovery key is typically a 32-character string
	// that's decoded to create the wrapping key
	recoveryDerivedKey := make([]byte, 32)
	h := sha256.New()
	h.Write([]byte(recoveryKey))
	copy(recoveryDerivedKey, h.Sum(nil))

	// Use the derived key to unwrap the KEK
	kek, err := UnwrapKey(recoveryDerivedKey, recoveryEntry.KeyData)
	if err != nil {
		return fmt.Errorf("failed to unwrap KEK with recovery key: %w", err)
	}

	// Use the KEK to unwrap the VEK
	vek, err := UnwrapKey(kek, volumeKeyEntry.KeyData)
	if err != nil {
		return fmt.Errorf("failed to unwrap VEK: %w", err)
	}

	// Store the VEK in the encryption context
	ec.VolumeEncryptionKey = vek
	ec.IsDecrypted = true

	return nil
}

// DecryptBlock decrypts a block of data using AES-XTS
func (ec *EncryptionContext) DecryptBlock(data []byte, physBlockNum, cryptoID uint64) ([]byte, error) {
	if !ec.IsDecrypted {
		return nil, errors.New("volume not decrypted")
	}

	// Create the XTS cipher with VEK
	cipher, err := NewAESXTSCipher(ec.VolumeEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-XTS cipher: %w", err)
	}

	// Create tweak value
	tweak := CreateTweak(cryptoID, physBlockNum)

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
	if !ec.IsDecrypted {
		return nil, errors.New("volume not decrypted")
	}

	// Create the XTS cipher with VEK
	cipher, err := NewAESXTSCipher(ec.VolumeEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-XTS cipher: %w", err)
	}

	// Create tweak value
	tweak := CreateTweak(cryptoID, physBlockNum)

	// Encrypt the data
	encrypted := make([]byte, len(data))
	err = cipher.Encrypt(encrypted, data, tweak)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt block: %w", err)
	}

	return encrypted, nil
}
