// encryption.go

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

// JCryptoKey represents the key half of a per-file encryption state record (j_crypto_key_t)
type JCryptoKey struct {
	Hdr JKey // The record's header
}

// Serialize converts the crypto key to bytes
func (key *JCryptoKey) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, key.Hdr)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses a crypto key from bytes
func (key *JCryptoKey) Parse(data []byte) error {
	if len(data) < binary.Size(JKey{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, &key.Hdr)
}

// JCryptoVal represents the value half of a per-file encryption state record (j_crypto_val_t)
type JCryptoVal struct {
	Refcnt uint32             // Reference count
	State  WrappedCryptoState // Encryption state
}

// Serialize converts the crypto value to bytes
func (val *JCryptoVal) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, val.Refcnt)
	if err != nil {
		return nil, err
	}

	stateBytes, err := val.State.Serialize()
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(stateBytes)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Parse parses a crypto value from bytes
func (val *JCryptoVal) Parse(data []byte) error {
	if len(data) < 4 {
		return ErrStructTooShort
	}

	val.Refcnt = binary.LittleEndian.Uint32(data[:4])

	if len(data) > 4 {
		return val.State.Parse(data[4:])
	}

	return nil
}

// WrappedCryptoState represents a wrapped key used for per-file encryption (wrapped_crypto_state_t)
type WrappedCryptoState struct {
	MajorVersion    uint16 // Major version for this structure's layout
	MinorVersion    uint16 // Minor version for this structure's layout
	Flags           uint32 // Crypto flags
	PersistentClass uint32 // Protection class
	KeyOSVersion    uint32 // OS version that created this structure
	KeyRevision     uint16 // Key revision
	KeyLen          uint16 // Size in bytes of the wrapped key data
	PersistentKey   []byte // Wrapped key data (variable length)
}

// Serialize converts the wrapped crypto state to bytes
func (wcs *WrappedCryptoState) Serialize() ([]byte, error) {
	size := 16 + len(wcs.PersistentKey) // Fixed fields + key
	buf := make([]byte, size)

	binary.LittleEndian.PutUint16(buf[0:2], wcs.MajorVersion)
	binary.LittleEndian.PutUint16(buf[2:4], wcs.MinorVersion)
	binary.LittleEndian.PutUint32(buf[4:8], wcs.Flags)
	binary.LittleEndian.PutUint32(buf[8:12], wcs.PersistentClass)
	binary.LittleEndian.PutUint32(buf[12:16], wcs.KeyOSVersion)

	if len(wcs.PersistentKey) > 0 {
		copy(buf[16:], wcs.PersistentKey)
	}

	return buf, nil
}

// Parse parses a wrapped crypto state from bytes
func (wcs *WrappedCryptoState) Parse(data []byte) error {
	if len(data) < 16 {
		return ErrStructTooShort
	}

	wcs.MajorVersion = binary.LittleEndian.Uint16(data[0:2])
	wcs.MinorVersion = binary.LittleEndian.Uint16(data[2:4])
	wcs.Flags = binary.LittleEndian.Uint32(data[4:8])
	wcs.PersistentClass = binary.LittleEndian.Uint32(data[8:12])
	wcs.KeyOSVersion = binary.LittleEndian.Uint32(data[12:16])

	if len(data) > 16 {
		wcs.KeyLen = uint16(len(data) - 16)
		wcs.PersistentKey = make([]byte, wcs.KeyLen)
		copy(wcs.PersistentKey, data[16:])
	}

	return nil
}

// GetProtectionClass returns the protection class for this crypto state
func (wcs *WrappedCryptoState) GetProtectionClass() uint32 {
	return wcs.PersistentClass & CPEffectiveClassMask
}

// WrappedMetaCryptoState represents information about how the VEK is used
// to encrypt a file (wrapped_meta_crypto_state_t)
type WrappedMetaCryptoState struct {
	MajorVersion    uint16 // Major version for this structure's layout
	MinorVersion    uint16 // Minor version for this structure's layout
	Flags           uint32 // Crypto flags
	PersistentClass uint32 // Protection class
	KeyOSVersion    uint32 // OS version that created this structure
	KeyRevision     uint16 // Key revision
	Unused          uint16 // Reserved
}

// Serialize converts the wrapped meta crypto state to bytes
func (wmcs *WrappedMetaCryptoState) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, wmcs)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses a wrapped meta crypto state from bytes
func (wmcs *WrappedMetaCryptoState) Parse(data []byte) error {
	if len(data) < binary.Size(WrappedMetaCryptoState{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, wmcs)
}

// GetProtectionClass returns the protection class for this meta crypto state
func (wmcs *WrappedMetaCryptoState) GetProtectionClass() uint32 {
	return wmcs.PersistentClass & CPEffectiveClassMask
}

// KeybagEntry represents an entry in a keybag (keybag_entry_t)
type KeybagEntry struct {
	UUID    [16]byte // UUID associated with this entry
	Tag     uint16   // Tag describing the kind of data
	KeyLen  uint16   // Length of the key data
	Padding [4]byte  // Reserved
	KeyData []byte   // Key data (variable length)
}

// Serialize converts the keybag entry to bytes
func (ke *KeybagEntry) Serialize() ([]byte, error) {
	size := 24 + len(ke.KeyData) // Fixed fields + key data
	buf := make([]byte, size)

	copy(buf[:16], ke.UUID[:])
	binary.LittleEndian.PutUint16(buf[16:18], ke.Tag)
	binary.LittleEndian.PutUint16(buf[18:20], uint16(len(ke.KeyData)))
	copy(buf[20:24], ke.Padding[:])

	if len(ke.KeyData) > 0 {
		copy(buf[24:], ke.KeyData)
	}

	return buf, nil
}

// Parse parses a keybag entry from bytes
func (ke *KeybagEntry) Parse(data []byte) error {
	if len(data) < 24 {
		return ErrStructTooShort
	}

	copy(ke.UUID[:], data[:16])

	ke.Tag = binary.LittleEndian.Uint16(data[16:18])
	ke.KeyLen = binary.LittleEndian.Uint16(data[18:20])
	copy(ke.Padding[:], data[20:24])

	if ke.KeyLen > 0 && len(data) >= 24+int(ke.KeyLen) {
		ke.KeyData = make([]byte, ke.KeyLen)
		copy(ke.KeyData, data[24:24+ke.KeyLen])
	}

	return nil
}

// String returns a string representation of the keybag entry
func (ke *KeybagEntry) String() string {
	return fmt.Sprintf("KeybagEntry{UUID: %x, Tag: %d, KeyLen: %d}",
		ke.UUID, ke.Tag, ke.KeyLen)
}

// KBLocker represents a keybag (kb_locker_t)
type KBLocker struct {
	Version uint16        // Keybag version
	NKeys   uint16        // Number of entries in the keybag
	NBytes  uint32        // Size in bytes of the data stored in the entries
	Padding [8]byte       // Reserved
	Entries []KeybagEntry // The entries
}

// Serialize converts the keybag to bytes
func (kbl *KBLocker) Serialize() ([]byte, error) {
	// Calculate total size needed
	size := 16 // Fixed fields
	for _, entry := range kbl.Entries {
		size += 24 + len(entry.KeyData)
	}

	buf := make([]byte, size)

	binary.LittleEndian.PutUint16(buf[0:2], kbl.Version)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(kbl.Entries)))
	binary.LittleEndian.PutUint32(buf[4:8], kbl.NBytes)
	copy(buf[8:16], kbl.Padding[:])

	offset := 16
	for _, entry := range kbl.Entries {
		entryBytes, err := entry.Serialize()
		if err != nil {
			return nil, err
		}

		copy(buf[offset:offset+len(entryBytes)], entryBytes)
		offset += len(entryBytes)
	}

	return buf, nil
}

// Parse parses a keybag from bytes
func (kbl *KBLocker) Parse(data []byte) error {
	if len(data) < 16 {
		return ErrStructTooShort
	}

	kbl.Version = binary.LittleEndian.Uint16(data[0:2])
	kbl.NKeys = binary.LittleEndian.Uint16(data[2:4])
	kbl.NBytes = binary.LittleEndian.Uint32(data[4:8])
	copy(kbl.Padding[:], data[8:16])

	if kbl.NKeys > 0 {
		kbl.Entries = make([]KeybagEntry, 0, kbl.NKeys)
		offset := 16

		for i := uint16(0); i < kbl.NKeys; i++ {
			if offset >= len(data) {
				return ErrStructTooShort
			}

			entry := KeybagEntry{}
			err := entry.Parse(data[offset:])
			if err != nil {
				return err
			}

			kbl.Entries = append(kbl.Entries, entry)
			offset += 24 + int(entry.KeyLen)
		}
	}

	return nil
}

// FindEntry finds a keybag entry by UUID and tag
func (kbl *KBLocker) FindEntry(uuid [16]byte, tag uint16) *KeybagEntry {
	for i := range kbl.Entries {
		if bytes.Equal(kbl.Entries[i].UUID[:], uuid[:]) && kbl.Entries[i].Tag == tag {
			return &kbl.Entries[i]
		}
	}
	return nil
}

// String returns a string representation of the keybag
func (kbl *KBLocker) String() string {
	return fmt.Sprintf("KBLocker{Version: %d, NKeys: %d, NBytes: %d}",
		kbl.Version, kbl.NKeys, kbl.NBytes)
}

// MediaKeybag represents a keybag in a container (media_keybag_t)
type MediaKeybag struct {
	Obj    ObjectPhys // Object header
	Locker KBLocker   // Keybag
}

// Serialize converts the media keybag to bytes
func (mk *MediaKeybag) Serialize() ([]byte, error) {
	objBytes, err := mk.Obj.Serialize()
	if err != nil {
		return nil, err
	}

	lockerBytes, err := mk.Locker.Serialize()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, len(objBytes)+len(lockerBytes))
	copy(buf, objBytes)
	copy(buf[len(objBytes):], lockerBytes)

	return buf, nil
}

// Parse parses a media keybag from bytes
func (mk *MediaKeybag) Parse(data []byte) error {
	if len(data) < binary.Size(ObjectPhys{}) {
		return ErrStructTooShort
	}

	err := mk.Obj.Parse(data)
	if err != nil {
		return err
	}

	return mk.Locker.Parse(data[binary.Size(ObjectPhys{}):])
}

// String returns a string representation of the media keybag
func (mk *MediaKeybag) String() string {
	return fmt.Sprintf("MediaKeybag{Obj: %s, Locker: %s}",
		mk.Obj.String(), mk.Locker.String())
}

// EncryptionContext manages encryption/decryption operations
type EncryptionContext struct {
	containerUUID          [16]byte
	volumeUUID             [16]byte
	volumeEncryptionKey    []byte
	usesSoftwareEncryption bool
	isDecrypted            bool
}

// NewEncryptionContext creates a new encryption context
func NewEncryptionContext(volumeUUID, containerUUID [16]byte) *EncryptionContext {
	return &EncryptionContext{
		volumeUUID:             volumeUUID,
		containerUUID:          containerUUID,
		usesSoftwareEncryption: true,
		isDecrypted:            false,
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
	volumeKeyEntry := containerKeybag.FindEntry(ec.volumeUUID, KBTagVolumeKey)
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

// AESXTSCipher implements AES-XTS encryption/decryption
type AESXTSCipher struct {
	key1Cipher cipher.Block
	key2Cipher cipher.Block
	blockSize  int
}

// NewAESXTSCipher creates a new AES-XTS cipher
func NewAESXTSCipher(key []byte) (*AESXTSCipher, error) {
	// AES-XTS requires two keys of equal length
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, errors.New("AES-XTS key must be 256, 384 or 512 bits (two AES keys)")
	}

	// Split the key into two equal parts
	keySize := len(key) / 2
	key1 := key[:keySize]
	key2 := key[keySize:]

	// Create the AES ciphers
	key1Cipher, err := aes.NewCipher(key1)
	if err != nil {
		return nil, err
	}

	key2Cipher, err := aes.NewCipher(key2)
	if err != nil {
		return nil, err
	}

	return &AESXTSCipher{
		key1Cipher: key1Cipher,
		key2Cipher: key2Cipher,
		blockSize:  key1Cipher.BlockSize(),
	}, nil
}

// multiplyByX multiplies a value by x in GF(2^128)
func multiplyByX(block []byte) {
	carry := (block[0] & 0x80) != 0

	// Shift left by 1
	for i := 0; i < len(block)-1; i++ {
		block[i] = (block[i] << 1) | (block[i+1] >> 7)
	}
	block[len(block)-1] <<= 1

	// If there was a carry, XOR with the reduction polynomial
	if carry {
		block[len(block)-1] ^= 0x87
	}
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

	// Create a work buffer for the tweak
	T := make([]byte, c.blockSize)
	copy(T, tweak[:c.blockSize])

	// Encrypt the tweak with key2
	c.key2Cipher.Encrypt(T, T)

	// Process each block
	for i := 0; i < len(src); i += c.blockSize {
		// Get the current block
		block := src[i : i+c.blockSize]

		// XOR the plaintext with the encrypted tweak
		tmp := make([]byte, c.blockSize)
		for j := 0; j < c.blockSize; j++ {
			tmp[j] = block[j] ^ T[j]
		}

		// Encrypt the result with the first key
		c.key1Cipher.Encrypt(tmp, tmp)

		// XOR with the encrypted tweak again
		for j := 0; j < c.blockSize; j++ {
			dst[i+j] = tmp[j] ^ T[j]
		}

		// Multiply T by x in GF(2^128) for the next block
		if i+c.blockSize < len(src) {
			multiplyByX(T)
		}
	}

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

	// Create a work buffer for the tweak
	T := make([]byte, c.blockSize)
	copy(T, tweak[:c.blockSize])

	// Encrypt the tweak with key2
	c.key2Cipher.Encrypt(T, T)

	// Process each block
	for i := 0; i < len(src); i += c.blockSize {
		// Get the current block
		block := src[i : i+c.blockSize]

		// XOR the ciphertext with the encrypted tweak
		tmp := make([]byte, c.blockSize)
		for j := 0; j < c.blockSize; j++ {
			tmp[j] = block[j] ^ T[j]
		}

		// Decrypt the result with the first key
		c.key1Cipher.Decrypt(tmp, tmp)

		// XOR with the encrypted tweak again
		for j := 0; j < c.blockSize; j++ {
			dst[i+j] = tmp[j] ^ T[j]
		}

		// Multiply T by x in GF(2^128) for the next block
		if i+c.blockSize < len(src) {
			multiplyByX(T)
		}
	}

	return nil
}
