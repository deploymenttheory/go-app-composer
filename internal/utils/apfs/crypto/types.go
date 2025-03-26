// Package crypto provides cryptographic operations for APFS
package crypto

import "golang.org/x/crypto/xts"

// AESXTSCipher implements AES-XTS encryption/decryption operations
type AESXTSCipher struct {
	Cipher    *xts.Cipher // Should be *xts.Cipher, not cipher.BlockMode
	BlockSize int
}

// EncryptionContext manages encryption/decryption operations
type EncryptionContext struct {
	ContainerUUID          [16]byte
	VolumeUUID             [16]byte
	VolumeEncryptionKey    []byte
	UsesSoftwareEncryption bool
	IsDecrypted            bool
}

// KBLocker represents a keybag (kb_locker_t)
type KBLocker struct {
	Version uint16        // Keybag version
	NKeys   uint16        // Number of entries in the keybag
	NBytes  uint32        // Size in bytes of the data stored in the entries
	Padding [8]byte       // Reserved
	Entries []KeybagEntry // The entries
}

// KeybagEntry represents an entry in a keybag (keybag_entry_t)
type KeybagEntry struct {
	UUID    [16]byte // UUID associated with this entry
	Tag     uint16   // Tag describing the kind of data
	KeyLen  uint16   // Length of the key data
	Padding [4]byte  // Reserved
	KeyData []byte   // Key data (variable length)
}

// KeybagTags define what kind of information is stored by a keybag entry
const (
	KBTagUnknown              uint16 = 0
	KBTagReserved1            uint16 = 1
	KBTagVolumeKey            uint16 = 2
	KBTagVolumeUnlockRecords  uint16 = 3
	KBTagVolumePassphraseHint uint16 = 4
	KBTagWrappingMKey         uint16 = 5
	KBTagVolumeMKey           uint16 = 6
	KBTagReservedF8           uint16 = 0xF8
)

// Protection class constants
const (
	ProtectionClassDirNone uint32 = 0
	ProtectionClassA       uint32 = 1
	ProtectionClassB       uint32 = 2
	ProtectionClassC       uint32 = 3
	ProtectionClassD       uint32 = 4
	ProtectionClassF       uint32 = 6
	ProtectionClassM       uint32 = 14
	CPEffectiveClassMask   uint32 = 0x0000001f
)

// Crypto constants
const (
	CryptoSWID             uint64 = 4
	CryptoReserved5        uint64 = 5
	APFSUnassignedCryptoID uint64 = ^uint64(0)
)

// Keybag constants
const (
	APFSKeybagVersion             uint16 = 2
	APFSVolKeybagEntryMaxSize     uint16 = 512
	APFSFVPersonalRecoveryKeyUUID        = "EBC6C064-0000-11AA-AA11-00306543ECAC"
)

// Volume encryption flags
const (
	APFSFSUnencrypted uint64 = 0x00000001
	APFSFSReserved2   uint64 = 0x00000002
	APFSFSReserved4   uint64 = 0x00000004
	APFSFSOnekey      uint64 = 0x00000008
	APFSFSCryptoFlags uint64 = (APFSFSUnencrypted | APFSFSReserved2 | APFSFSOnekey)
)

// Key wrapping constants
const (
	CPMaxWrappedKeySize = 128
)
