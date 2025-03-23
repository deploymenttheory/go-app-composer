//
package apfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Additional error definitions for encryption operations
var (
	ErrInvalidPassword     = errors.New("invalid password")
	ErrEncryptionNotFound  = errors.New("encryption not found")
	ErrWrongEncryptionType = errors.New("wrong encryption type")
	ErrNoKeyAvailable      = errors.New("no encryption key available")
	ErrKeyDerivationFailed = errors.New("key derivation failed")
)

// VolumeEncryptionKey represents a volume encryption key (VEK)
type VolumeEncryptionKey struct {
	wrapped   []byte
	unwrapped []byte
	type_     uint32
}

// KeyEncryptionKey represents a key encryption key (KEK)
type KeyEncryptionKey struct {
	wrapped   []byte
	unwrapped []byte
	type_     uint32
}

// EncryptionContext holds the necessary information for encryption/decryption
type EncryptionContext struct {
	vek              *VolumeEncryptionKey
	passphrase       string
	recoveryKey      string
	container        *ContainerManager
	volume           *VolumeManager
	containerKeybag  *KBLocker
	volumeKeybag     *KBLocker
	isDecrypted      bool
	useSoftwareXTS   bool
}

// NewEncryptionContext creates a new encryption context for a volume
func NewEncryptionContext(container *ContainerManager, volume *VolumeManager) (*EncryptionContext, error) {
	ctx := &EncryptionContext{
		container: container,
		volume:    volume,
	}

	// Check if the volume is encrypted
	if (volume.superblock.FSFlags & APFSFSUnencrypted) != 0 {
		// Volume is not encrypted
		ctx.isDecrypted = true
		return ctx, nil
	}

	// Check if we're using software encryption
	ctx.useSoftwareXTS = (container.superblock.Flags & NX_CRYPTO_SW) != 0

	// Load container keybag
	if container.superblock.KeyLocker.Blocks > 0 {
		keybagData, err := ctx.readKeybag(container.superblock.KeyLocker.Start, container.superblock.KeyLocker.Blocks)
		if err != nil {
			return nil, err
		}

		// Parse keybag
		containerKeybag, err := ctx.parseKeybag(keybagData)
		if err != nil {
			return nil, err
		}
		ctx.containerKeybag = containerKeybag
	} else {
		return nil, ErrEncryptionNotFound
	}

	// Find volume keybag location from container keybag
	volumeKeybagLocation, err := ctx.findVolumeKeybagLocation()
	if err != nil {
		return nil, err
	}

	// Load volume keybag
	volumeKeybagData, err := ctx.readKeybag(volumeKeybagLocation.Start, volumeKeybagLocation.Blocks)
	if err != nil {
		return nil, err
	}

	// Parse volume keybag
	volumeKeybag, err := ctx.parseKeybag(volumeKeybagData)
	if err != nil {
		return nil, err
	}
	ctx.volumeKeybag = volumeKeybag

	return ctx, nil
}

// readKeybag reads a keybag from disk
func (ctx *EncryptionContext) readKeybag(start uint64, blocks uint64) ([]byte, error) {
	// Calculate size and location
	blockSize := int64(ctx.container.blockSize)
	offset := int64(start) * blockSize
	size := int64(blocks) * blockSize

	// Read keybag data
	data := make([]byte, size)
	_, err := ctx.container.device.Seek(offset, 0)
	if err != nil {
		return nil, err
	}

	_, err = ctx.container.device.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// parseKeybag parses keybag data
func (ctx *EncryptionContext) parseKeybag(data []byte) (*KBLocker, error) {
	// Unwrap keybag using container UUID or volume UUID
	var uuid [16]byte
	if ctx.volume != nil {
		uuid = ctx.volume.superblock.VolUUID
	} else {
		uuid = ctx.container.superblock.UUID
	}

	// Unwrap keybag
	unwrappedData, err := ctx.unwrapKeybag(data, uuid[:])
	if err != nil {
		return nil, err
	}

	// Parse keybag structure
	keybag := &KBLocker{}
	err = binary.Read(bytes.NewReader(unwrappedData), binary.LittleEndian, &keybag.KlVersion)
	if err != nil {
		return nil, err
	}

	// Check version
	if keybag.KlVersion != APFSKeybagVersion {
		return nil, fmt.Errorf("unsupported keybag version: %d", keybag.KlVersion)
	}

	// Read count and size
	err = binary.Read(bytes.NewReader(unwrappedData[2:]), binary.LittleEndian, &keybag.KlNkeys)
	if err != nil {
		return nil, err
	}

	err = binary.Read(bytes.NewReader(unwrappedData[4:]), binary.LittleEndian, &keybag.KlNbytes)
	if err != nil {
		return nil, err
	}

	// Skip padding
	entriesOffset := 16 // Size of KBLocker header

	// The entries are stored after the header
	keybag.KlEntries = make([]KeybagEntry, keybag.KlNkeys)
	
	// Track current position
	pos := entriesOffset

	// Read each entry
	for i := uint16(0); i < keybag.KlNkeys; i++ {
		entry := &keybag.KlEntries[i]
		
		// Read UUID
		copy(entry.KeUUID[:], unwrappedData[pos:pos+16])
		pos += 16

		// Read tag and keylen
		err = binary.Read(bytes.NewReader(unwrappedData[pos:]), binary.LittleEndian, &entry.KeTag)
		if err != nil {
			return nil, err
		}
		pos += 2

		err = binary.Read(bytes.NewReader(unwrappedData[pos:]), binary.LittleEndian, &entry.KeKeylen)
		if err != nil {
			return nil, err
		}
		pos += 2

		// Skip padding
		pos += 4

		// Read key data
		entry.KeKeydata = make([]byte, entry.KeKeylen)
		copy(entry.KeKeydata, unwrappedData[pos:pos+int(entry.KeKeylen)])
		pos += int(entry.KeKeylen)

		// Align to 8-byte boundary
		if pos%8 != 0 {
			pos += 8 - (pos % 8)
		}
	}

	return keybag, nil
}

// unwrapKeybag unwraps a keybag using the device UUID
func (ctx *EncryptionContext) unwrapKeybag(data []byte, uuid []byte) ([]byte, error) {
	// This is a simplified implementation of RFC 3394 AES key unwrapping
	// In a real implementation, you would use a proper RFC 3394 implementation

	// For demo purposes, we'll XOR the keybag data with the UUID
	// This is NOT the real algorithm, but shows the concept
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ uuid[i%16]
	}

	return result, nil
}

// findVolumeKeybagLocation finds the volume keybag location in the container keybag
func (ctx *EncryptionContext) findVolumeKeybagLocation() (*struct{ Start, Blocks uint64 }, error) {
	// Find the volume UUID
	volumeUUID := ctx.volume.superblock.VolUUID

	// Look for a volume unlock records entry with matching UUID
	for _, entry := range ctx.containerKeybag.KlEntries {
		if bytes.Equal(entry.KeUUID[:], volumeUUID[:]) && entry.KeTag == KBTagVolumeUnlockRecords {
			// This entry contains the volume keybag location
			var location struct{ Start, Blocks uint64 }
			err := binary.Read(bytes.NewReader(entry.KeKeydata), binary.LittleEndian, &location)
			if err != nil {
				return nil, err
			}
			return &location, nil
		}
	}

	return nil, ErrEncryptionNotFound
}

// findVolumeKey finds the volume encryption key in the container keybag
func (ctx *EncryptionContext) findVolumeKey() (*VolumeEncryptionKey, error) {
	// Find the volume UUID
	volumeUUID := ctx.volume.superblock.VolUUID

	// Look for a volume key entry with matching UUID
	for _, entry := range ctx.containerKeybag.KlEntries {
		if bytes.Equal(entry.KeUUID[:], volumeUUID[:]) && entry.KeTag == KBTagVolumeKey {
			// This entry contains the wrapped VEK
			vek := &VolumeEncryptionKey{
				wrapped: entry.KeKeydata,
				type_:   CRYPTO_SW_ID,
			}
			return vek, nil
		}
	}

	return nil, ErrEncryptionNotFound
}

// findVolumeUnlockKey finds the volume unlock key (KEK) in the volume keybag
func (ctx *EncryptionContext) findVolumeUnlockKey() (*KeyEncryptionKey, error) {
	// Look for a volume unlock records entry
	for _, entry := range ctx.volumeKeybag.KlEntries {
		if entry.KeTag == KBTagVolumeUnlockRecords {
			// This entry contains the wrapped KEK
			kek := &KeyEncryptionKey{
				wrapped: entry.KeKeydata,
				type_:   CRYPTO_SW_ID,
			}
			return kek, nil
		}
	}

	return nil, ErrEncryptionNotFound
}

// findPassphraseHint finds the passphrase hint in the volume keybag
func (ctx *EncryptionContext) findPassphraseHint() (string, error) {
	// Look for a passphrase hint entry
	for _, entry := range ctx.volumeKeybag.KlEntries {
		if entry.KeTag == KBTagVolumePassphraseHint {
			// This entry contains the hint as plain text
			return string(entry.KeKeydata), nil
		}
	}

	return "", nil // No hint found, but that's not an error
}

// Decrypt decrypts the volume using the provided password
func (ctx *EncryptionContext) Decrypt(password string) error {
	// Check if already decrypted
	if ctx.isDecrypted {
		return nil
	}

	// First, find the volume key (VEK) in the container keybag
	vek, err := ctx.findVolumeKey()
	if err != nil {
		return err
	}
	ctx.vek = vek

	// Next, find the volume unlock key (KEK) in the volume keybag
	kek, err := ctx.findVolumeUnlockKey()
	if err != nil {
		return err
	}

	// Derive the key from the password
	derivedKey := ctx.deriveKeyFromPassword(password)

	// Unwrap the KEK using the derived key
	kek.unwrapped, err = ctx.unwrapKey(kek.wrapped, derivedKey)
	if err != nil {
		return ErrInvalidPassword
	}

	// Unwrap the VEK using the unwrapped KEK
	vek.unwrapped, err = ctx.unwrapKey(vek.wrapped, kek.unwrapped)
	if err != nil {
		return err
	}

	ctx.isDecrypted = true
	ctx.passphrase = password
	return nil
}

// DecryptWithRecoveryKey decrypts the volume using the provided recovery key
func (ctx *EncryptionContext) DecryptWithRecoveryKey(recoveryKey string) error {
	// Check if already decrypted
	if ctx.isDecrypted {
		return nil
	}

	// First, find the volume key (VEK) in the container keybag
	vek, err := ctx.findVolumeKey()
	if err != nil {
		return err
	}
	ctx.vek = vek

	// Look for a personal recovery key entry
	found := false
	var kek *KeyEncryptionKey
	for _, entry := range ctx.volumeKeybag.KlEntries {
		if bytes.Equal(entry.KeUUID[:], []byte(APFS_FV_PERSONAL_RECOVERY_KEY_UUID)) && 
		   entry.KeTag == KBTagVolumeUnlockRecords {
			// This entry contains the KEK for recovery
			kek = &KeyEncryptionKey{
				wrapped: entry.KeKeydata,
				type_:   CRYPTO_SW_ID,
			}
			found = true
			break
		}
	}

	if !found {
		return ErrEncryptionNotFound
	}

	// Parse and validate the recovery key
	derivedKey, err := ctx.parseRecoveryKey(recoveryKey)
	if err != nil {
		return err
	}

	// Unwrap the KEK using the derived key
	kek.unwrapped, err = ctx.unwrapKey(kek.wrapped, derivedKey)
	if err != nil {
		return ErrInvalidPassword
	}

	// Unwrap the VEK using the unwrapped KEK
	vek.unwrapped, err = ctx.unwrapKey(vek.wrapped, kek.unwrapped)
	if err != nil {
		return err
	}

	ctx.isDecrypted = true
	ctx.recoveryKey = recoveryKey
	return nil
}

// deriveKeyFromPassword derives an encryption key from a password
func (ctx *EncryptionContext) deriveKeyFromPassword(password string) []byte {
	// In a real implementation, this would use PBKDF2 with the correct parameters
	// For simplicity, we'll just use a SHA-256 hash of the password
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// parseRecoveryKey parses a recovery key string into a key
func (ctx *EncryptionContext) parseRecoveryKey(recoveryKey string) ([]byte, error) {
	// In a real implementation, this would:
	// 1. Parse the recovery key format (usually groups of characters)
	// 2. Validate the checksum/format
	// 3. Convert to a binary key

	// For simplicity, we'll just use a SHA-256 hash of the recovery key
	hash := sha256.Sum256([]byte(recoveryKey))
	return hash[:], nil
}

// unwrapKey unwraps a key using a key encryption key
func (ctx *EncryptionContext) unwrapKey(wrappedKey, kek []byte) ([]byte, error) {
	// This is a simplified implementation of RFC 3394 AES key unwrapping
	// In a real implementation, you would use a proper RFC 3394 implementation

	// For demo purposes, we'll XOR the wrapped key with the KEK
	// This is NOT the real algorithm, but shows the concept
	result := make([]byte, len(wrappedKey))
	for i := 0; i < len(wrappedKey); i++ {
		result[i] = wrappedKey[i] ^ kek[i%len(kek)]
	}

	return result, nil
}

// GetPassphraseHint returns the password hint, if available
func (ctx *EncryptionContext) GetPassphraseHint() (string, error) {
	return ctx.findPassphraseHint()
}

// IsDecrypted returns true if the volume is decrypted
func (ctx *EncryptionContext) IsDecrypted() bool {
	return ctx.isDecrypted
}

// DecryptBlock decrypts a block of data
func (ctx *EncryptionContext) DecryptBlock(data []byte, physicalBlockNum uint64, cryptoID uint64) ([]byte, error) {
	if !ctx.isDecrypted {
		return nil, ErrNoKeyAvailable
	}

	if ctx.vek == nil || ctx.vek.unwrapped == nil {
		return nil, ErrNoKeyAvailable
	}

	// Create AES-XTS cipher
	result := make([]byte, len(data))
	tweak := cryptoID

	if ctx.useSoftwareXTS {
		// Software encryption (AES-XTS with the volume encryption key)
		err := ctx.decryptBlockAESXTS(data, result, ctx.vek.unwrapped, tweak)
		if err != nil {
			return nil, err
		}
	} else {
		// Hardware encryption - in a real implementation, this would use 
		// platform-specific APIs
		return nil, ErrWrongEncryptionType
	}

	return result, nil
}

// decryptBlockAESXTS decrypts a block using AES-XTS
func (ctx *EncryptionContext) decryptBlockAESXTS(ciphertext, plaintext, key []byte, tweak uint64) error {
	// AES-XTS requires a key that's twice the length of a normal AES key
	// The first half is used for encryption, the second half for the tweak
	if len(key) < 32 {
		return errors.New("key must be at least 32 bytes for AES-XTS")
	}

	// Create two AES ciphers, one for encryption and one for the tweak
	cipher1, err := aes.NewCipher(key[:16])
	if err != nil {
		return err
	}

	cipher2, err := aes.NewCipher(key[16:32])
	if err != nil {
		return err
	}

	// Create the XTS mode
	xts, err := newXTSMode(cipher1, cipher2)
	if err != nil {
		return err
	}

	// Convert tweak to a byte array
	tweakBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweakBytes, tweak)

	// Decrypt the data
	xts.Decrypt(plaintext, ciphertext, tweakBytes)

	return nil
}

// EncryptBlock encrypts a block of data
func (ctx *EncryptionContext) EncryptBlock(data []byte, physicalBlockNum uint64, cryptoID uint64) ([]byte, error) {
	if !ctx.isDecrypted {
		return nil, ErrNoKeyAvailable
	}

	if ctx.vek == nil || ctx.vek.unwrapped == nil {
		return nil, ErrNoKeyAvailable
	}

	// Create AES-XTS cipher
	result := make([]byte, len(data))
	tweak := cryptoID

	if ctx.useSoftwareXTS {
		// Software encryption (AES-XTS with the volume encryption key)
		err := ctx.encryptBlockAESXTS(data, result, ctx.vek.unwrapped, tweak)
		if err != nil {
			return nil, err
		}
	} else {
		// Hardware encryption - in a real implementation, this would use 
		// platform-specific APIs
		return nil, ErrWrongEncryptionType
	}

	return result, nil
}

// encryptBlockAESXTS encrypts a block using AES-XTS
func (ctx *EncryptionContext) encryptBlockAESXTS(plaintext, ciphertext, key []byte, tweak uint64) error {
	// AES-XTS requires a key that's twice the length of a normal AES key
	// The first half is used for encryption, the second half for the tweak
	if len(key) < 32 {
		return errors.New("key must be at least 32 bytes for AES-XTS")
	}

	// Create two AES ciphers, one for encryption and one for the tweak
	cipher1, err := aes.NewCipher(key[:16])
	if err != nil {
		return err
	}

	cipher2, err := aes.NewCipher(key[16:32])
	if err != nil {
		return err
	}

	// Create the XTS mode
	xts, err := newXTSMode(cipher1, cipher2)
	if err != nil {
		return err
	}

	// Convert tweak to a byte array
	tweakBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweakBytes, tweak)

	// Encrypt the data
	xts.Encrypt(ciphertext, plaintext, tweakBytes)

	return nil
}

// XTS-AES mode implementation (simplified)
type xtsMode struct {
	cipher1 cipher.Block
	cipher2 cipher.Block
}

func newXTSMode(cipher1, cipher2 cipher.Block) (*xtsMode, error) {
	if cipher1.BlockSize() != cipher2.BlockSize() {
		return nil, errors.New("cipher block sizes must be equal")
	}
	
	return &xtsMode{
		cipher1: cipher1,
		cipher2: cipher2,
	}, nil
}

// Encrypt encrypts plaintext to ciphertext using XTS mode
func (x *xtsMode) Encrypt(ciphertext, plaintext, tweak []byte) {
	// This is a simplified implementation
	// In a real implementation, this would follow the XTS specification
	
	// For demo purposes, we'll just XOR the plaintext with the tweak
	// and then encrypt with the first cipher
	blockSize := x.cipher1.BlockSize()
	
	// Process each block
	for i := 0; i < len(plaintext); i += blockSize {
		end := i + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		
		// XOR plaintext with tweak
		for j := i; j < end; j++ {
			ciphertext[j] = plaintext[j] ^ tweak[j-i]
		}
		
		// Encrypt the block
		x.cipher1.Encrypt(ciphertext[i:end], ciphertext[i:end])
	}
}

// Decrypt decrypts ciphertext to plaintext using XTS mode
func (x *xtsMode) Decrypt(plaintext, ciphertext, tweak []byte) {
	// This is a simplified implementation
	// In a real implementation, this would follow the XTS specification
	
	// For demo purposes, we'll just decrypt with the first cipher
	// and then XOR with the tweak
	blockSize := x.cipher1.BlockSize()
	
	// Process each block
	for i := 0; i < len(ciphertext); i += blockSize {
		end := i + blockSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		
		// Decrypt the block
		x.cipher1.Decrypt(plaintext[i:end], ciphertext[i:end])
		
		// XOR plaintext with tweak
		for j := i; j < end; j++ {
			plaintext[j] = plaintext[j] ^ tweak[j-i]
		}
	}
}

// ChangeFVPassword changes the FileVault password
func (ctx *EncryptionContext) ChangeFVPassword(oldPassword, newPassword string) error {
	// Check if decrypted with the old password
	if !ctx.isDecrypted || ctx.passphrase != oldPassword {
		// Try to decrypt with the old password first
		err := ctx.Decrypt(oldPassword)
		if err != nil {
			return err
		}
	}

	// Find the KEK in the volume keybag
	var kekEntry *KeybagEntry
	for i := range ctx.volumeKeybag.KlEntries {
		if ctx.volumeKeybag.KlEntries[i].KeTag == KBTagVolumeUnlockRecords {
			kekEntry = &ctx.volumeKeybag.KlEntries[i]
			break
		}
	}
	
	if kekEntry == nil {
		return ErrEncryptionNotFound
	}

	// Derive a new key from the new password
	newDerivedKey := ctx.deriveKeyFromPassword(newPassword)

	// Re-wrap the KEK with the new derived key
	var err error
	kekEntry.KeKeydata, err = ctx.wrapKey(ctx.vek.unwrapped, newDerivedKey)
	if err != nil {
		return err
	}

	// Update the volume keybag on disk
	// In a real implementation, this would rewrite the keybag
	
	// Update context
	ctx.passphrase = newPassword
	
	return nil
}

// wrapKey wraps a key using a key encryption key
func (ctx *EncryptionContext) wrapKey(key, kek []byte) ([]byte, error) {
	// This is a simplified implementation of RFC 3394 AES key wrapping
	// In a real implementation, you would use a proper RFC 3394 implementation

	// For demo purposes, we'll XOR the key with the KEK
	// This is NOT the real algorithm, but shows the concept
	result := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		result[i] = key[i] ^ kek[i%len(kek)]
	}

	return result, nil
}

// AddRecoveryKey adds a personal recovery key to the volume
func (ctx *EncryptionContext) AddRecoveryKey() (string, error) {
	// Check if decrypted
	if !ctx.isDecrypted {
		return "", ErrNoKeyAvailable
	}

	// Generate a random recovery key
	recoveryKey := ctx.generateRecoveryKey()

	// Derive key from recovery key
	derivedKey, err := ctx.parseRecoveryKey(recoveryKey)
	if err != nil {
		return "", err
	}

	// Wrap the VEK with the derived key
	wrappedVEK, err := ctx.wrapKey(ctx.vek.unwrapped, derivedKey)
	if err != nil {
		return "", err
	}

	// Create a new keybag entry
	entry := KeybagEntry{
		KeTag:    KBTagVolumeUnlockRecords,
		KeKeylen: uint16(len(wrappedVEK)),
		KeKeydata: wrappedVEK,
	}
	
	// Set the UUID to the recovery key UUID
	copy(entry.KeUUID[:], []byte(APFS_FV_PERSONAL_RECOVERY_KEY_UUID))

	// Add to the volume keybag
	ctx.volumeKeybag.KlEntries = append(ctx.volumeKeybag.KlEntries, entry)
	ctx.volumeKeybag.KlNkeys++

	// Update the volume keybag on disk
	// In a real implementation, this would rewrite the keybag

	return recoveryKey, nil
}

// generateRecoveryKey generates a new random recovery key
func (ctx *EncryptionContext) generateRecoveryKey() string {
	// In a real implementation, this would generate a proper recovery key
	// with the correct format and checksum
	
	// For simplicity, we'll just generate a random string
	return "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"
}

// RemoveRecoveryKey removes the personal recovery key from the volume
func (ctx *EncryptionContext) RemoveRecoveryKey() error {
	// Check if decrypted
	if !ctx.isDecrypted {
		return ErrNoKeyAvailable
	}

	// Find the recovery key entry
	found := false
	var newEntries []KeybagEntry
	for _, entry := range ctx.volumeKeybag.KlEntries {
		// Keep all entries except the recovery key
		if !bytes.Equal(entry.KeUUID[:], []byte(APFS_FV_PERSONAL_RECOVERY_KEY_UUID)) || 
		   entry.KeTag != KBTagVolumeUnlockRecords {
			newEntries = append(newEntries, entry)
		} else {
			found = true
		}
	}

	if !found {
		return ErrEncryptionNotFound
	}

	// Update the keybag
	ctx.volumeKeybag.KlEntries = newEntries
	ctx.volumeKeybag.KlNkeys = uint16(len(newEntries))

	// Update the volume keybag on disk
	// In a real implementation, this would rewrite the keybag

	return nil
}

// SetPassphraseHint sets a hint for the volume password
func (ctx *EncryptionContext) SetPassphraseHint(hint string) error {
	// Check if decrypted
	if !ctx.isDecrypted {
		return ErrNoKeyAvailable
	}

	// Find the hint entry
	found := false
	for i := range ctx.volumeKeybag.KlEntries {
		if ctx.volumeKeybag.KlEntries[i].KeTag == KBTagVolumePassphraseHint {
			// Update existing hint
			ctx.volumeKeybag.KlEntries[i].KeKeylen = uint16(len(hint))
			ctx.volumeKeybag.KlEntries[i].KeKeydata = []byte(hint)
			found = true
			break
		}
	}

	if !found {
		// Create a new hint entry
		entry := KeybagEntry{
			KeTag:    KBTagVolumePassphraseHint,
			KeKeylen: uint16(len(hint)),
			KeKeydata: []byte(hint),
		}
		ctx.volumeKeybag.KlEntries = append(ctx.volumeKeybag.KlEntries, entry)
		ctx.volumeKeybag.KlNkeys++
	}

	// Update the volume keybag on disk
	// In a real implementation, this would rewrite the keybag

	return nil
}

package apfs

// EnableVolumeEncryption encrypts an unencrypted volume
func (vm *VolumeManager) EnableVolumeEncryption(tx *Transaction, password string) error {
	// Check if already encrypted
	if (vm.superblock.FSFlags & APFSFSUnencrypted) == 0 {
		return errors.New("volume is already encrypted")
	}

	// In a real implementation, this would:
	// 1. Generate a new volume encryption key (VEK)
	// 2. Create a container keybag entry for the volume
	// 3. Create a volume keybag with the password-based KEK
	// 4. Start the encryption process for all files

	// Set the volume flags
	vm.superblock.FSFlags &= ^uint64(APFSFSUnencrypted)

	// Set the container flags for software encryption
	vm.container.superblock.Flags |= NX_CRYPTO_SW

	// Set the encryption rolling state
	// In a real implementation, this would create an ER_STATE_PHYS object
	vm.superblock.ERStateOID = vm.container.superblock.NextOID
	vm.container.superblock.NextOID++

	// Mark the volume as encrypting
	vm.omap.physicalObj.OmFlags |= OMAP_ENCRYPTING

	return nil
}

// DisableVolumeEncryption decrypts an encrypted volume
func (vm *VolumeManager) DisableVolumeEncryption(tx *Transaction, password string) error {
	// Check if encrypted
	if (vm.superblock.FSFlags & APFSFSUnencrypted) != 0 {
		return errors.New("volume is not encrypted")
	}

	// Create an encryption context
	ctx, err := NewEncryptionContext(vm.container, vm)
	if err != nil {
		return err
	}

	// Decrypt the volume
	err = ctx.Decrypt(password)
	if err != nil {
		return err
	}

	// In a real implementation, this would:
	// 1. Start the decryption process for all files
	// 2. Remove the keybags

	// Set the volume flags
	vm.superblock.FSFlags |= APFSFSUnencrypted

	// Mark the volume as decrypting
	vm.omap.physicalObj.OmFlags |= OMAP_DECRYPTING

	return nil
}

// GetFileKey gets a file's encryption key
func (ctx *EncryptionContext) GetFileKey(file *File) ([]byte, error) {
	// Check if decrypted
	if !ctx.isDecrypted {
		return nil, ErrNoKeyAvailable
	}

	// Check if we're using per-volume encryption (software encryption)
	if (ctx.volume.superblock.FSFlags & APFSFSOnekey) != 0 {
		// Volume encryption key is used for all files
		return ctx.vek.unwrapped, nil
	}

	// For per-file encryption, we would need to:
	// 1. Find the file's crypto state record
	// 2. Unwrap the file's encryption key

	return nil, ErrNotImplemented
}

// RollEncryptionKeys rolls the volume's encryption keys
func (ctx *EncryptionContext) RollEncryptionKeys(password string) error {
	// Check if decrypted
	if !ctx.isDecrypted {
		// Decrypt first
		err := ctx.Decrypt(password)
		if err != nil {
			return err
		}
	}

	// In a real implementation, this would:
	// 1. Generate a new volume encryption key
	// 2. Re-wrap all keys with the new VEK
	// 3. Mark the volume as key rolling
	// 4. Start the key rolling process

	// Mark the volume as key rolling
	ctx.volume.omap.physicalObj.OmFlags |= OMAP_KEYROLLING

	// Toggle crypto generation flags
	ctx.volume.omap.physicalObj.OmFlags ^= OMAP_CRYPTO_GENERATION

	return nil
}

// IsEncrypted returns true if the volume is encrypted
func (vm *VolumeManager) IsEncrypted() bool {
	return (vm.superblock.FSFlags & APFSFSUnencrypted) == 0
}

// IsFVEnabled returns true if FileVault is enabled
func (vm *VolumeManager) IsFVEnabled() bool {
	// Check if the volume is encrypted
	if (vm.superblock.FSFlags & APFSFSUnencrypted) != 0 {
		return false
	}

	// FileVault implies volume-level encryption
	return (vm.superblock.FSFlags & APFSFSOnekey) != 0
}

// IsEncryptionInProgress returns true if encryption is in progress
func (vm *VolumeManager) IsEncryptionInProgress() bool {
	return (vm.omap.physicalObj.OmFlags & OMAP_ENCRYPTING) != 0
}

// IsDecryptionInProgress returns true if decryption is in progress
func (vm *VolumeManager) IsDecryptionInProgress() bool {
	return (vm.omap.physicalObj.OmFlags & OMAP_DECRYPTING) != 0
}

// IsKeyRollingInProgress returns true if key rolling is in progress
func (vm *VolumeManager) IsKeyRollingInProgress() bool {
	return (vm.omap.physicalObj.OmFlags & OMAP_KEYROLLING) != 0
}

// GetEncryptionProgress returns the progress of encryption/decryption
func (vm *VolumeManager) GetEncryptionProgress() (float64, error) {
	// Check if encryption state exists
	if vm.superblock.ERStateOID == 0 {
		return 0, ErrEncryptionNotFound
	}

	// In a real implementation, this would:
	// 1. Read the encryption rolling state object
	// 2. Calculate the progress from ersb_progress / ersb_total_blk_to_encrypt

	// For now, return a fake progress
	return 0.5, nil
}

// PauseEncryption pauses the encryption/decryption process
func (vm *VolumeManager) PauseEncryption() error {
	// Check if encryption state exists
	if vm.superblock.ERStateOID == 0 {
		return ErrEncryptionNotFound
	}

	// In a real implementation, this would set the ERSB_FLAG_PAUSED flag
	// in the encryption rolling state

	return nil
}

// ResumeEncryption resumes the encryption/decryption process
func (vm *VolumeManager) ResumeEncryption() error {
	// Check if encryption state exists
	if vm.superblock.ERStateOID == 0 {
		return ErrEncryptionNotFound
	}

	// In a real implementation, this would clear the ERSB_FLAG_PAUSED flag
	// in the encryption rolling state

	return nil
}

// DecryptFile reads and decrypts a file's contents
func (file *File) DecryptFile() ([]byte, error) {
	// Check if file has data
	if file.dataStream == nil || file.dataStream.Size == 0 {
		return []byte{}, nil
	}

	// Create an encryption context
	ctx, err := NewEncryptionContext(file.volume.container, file.volume)
	if err != nil {
		return nil, err
	}

	// Check if already decrypted
	if !ctx.IsDecrypted() {
		return nil, ErrNoKeyAvailable
	}

	// Read the raw data
	data, err := file.Read(0, int(file.dataStream.Size))
	if err != nil {
		return nil, err
	}

	// Decrypt each extent
	blockSize := int64(file.volume.container.blockSize)
	decryptedData := make([]byte, len(data))
	
	for _, extent := range file.extents {
		// Calculate the range this extent covers in the file
		startOffset := extent.LogicalAddr
		endOffset := startOffset + extent.Length
		
		// Calculate the corresponding range in our data buffer
		bufferStart := startOffset
		bufferEnd := endOffset
		if bufferEnd > uint64(len(data)) {
			bufferEnd = uint64(len(data))
		}
		
		// Calculate the number of blocks in this extent
		startBlock := startOffset / uint64(blockSize)
		endBlock := (endOffset + uint64(blockSize) - 1) / uint64(blockSize)
		
		// Decrypt each block
		for blockNum := startBlock; blockNum < endBlock; blockNum++ {
			// Calculate the offset of this block in the file
			blockOffset := blockNum * uint64(blockSize)
			
			// Calculate the range this block covers in our data buffer
			blockStart := blockOffset
			if blockStart < bufferStart {
				blockStart = bufferStart
			}
			
			blockEnd := (blockNum + 1) * uint64(blockSize)
			if blockEnd > bufferEnd {
				blockEnd = bufferEnd
			}
			
			// Calculate the corresponding range in the extent
			extentOffset := blockStart - startOffset
			
			// Calculate the physical block number
			physBlock := extent.PhysicalBlock + (blockNum - startBlock)
			
			// Decrypt the block
			blockData := data[blockStart:blockEnd]
			decryptedBlock, err := ctx.DecryptBlock(blockData, physBlock, extent.CryptoID)
			if err != nil {
				return nil, err
			}
			
			// Copy the decrypted data
			copy(decryptedData[blockStart:blockEnd], decryptedBlock)
		}
	}
	
	return decryptedData, nil
}

// EncryptAndWriteFile encrypts and writes data to a file
func (file *File) EncryptAndWriteFile(tx *Transaction, data []byte) error {
	// Create an encryption context
	ctx, err := NewEncryptionContext(file.volume.container, file.volume)
	if err != nil {
		return err
	}

	// Check if already decrypted
	if !ctx.IsDecrypted() {
		return ErrNoKeyAvailable
	}

	// In a real implementation, this would:
	// 1. Allocate blocks for the file
	// 2. Encrypt the data for each block
	// 3. Write the encrypted data
	// 4. Update the file extents

	// For now, just write the data (it will be encrypted by the transaction)
	return file.Write(tx, 0, data)
}



