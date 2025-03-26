package crypto

import (
	"crypto/aes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/xts"
)

// NewAESXTSCipher creates a new AES-XTS cipher using Go's crypto libraries
func NewAESXTSCipher(key []byte) (*AESXTSCipher, error) {
	// AES-XTS requires two keys of equal length
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, errors.New("AES-XTS key must be 256, 384 or 512 bits (two AES keys)")
	}

	// Create XTS cipher directly with the key
	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, err
	}

	return &AESXTSCipher{
		Cipher:    xtsCipher,
		BlockSize: 16, // AES block size is always 16 bytes
	}, nil
}

// Encrypt encrypts data using AES-XTS
func (c *AESXTSCipher) Encrypt(dst, src []byte, tweak []byte) error {
	if len(dst) < len(src) {
		return errors.New("output buffer too small")
	}

	if len(src) == 0 || len(src)%c.BlockSize != 0 {
		return errors.New("input length must be a multiple of the block size")
	}

	if len(tweak) < 16 {
		return errors.New("tweak must be at least 16 bytes")
	}

	// Convert the tweak to a sector number (using the first 8 bytes)
	sector := binary.LittleEndian.Uint64(tweak[:8])

	// Use the XTS cipher to encrypt the data
	c.Cipher.Encrypt(dst, src, sector)

	return nil
}

// Decrypt decrypts data using AES-XTS
func (c *AESXTSCipher) Decrypt(dst, src []byte, tweak []byte) error {
	if len(dst) < len(src) {
		return errors.New("output buffer too small")
	}

	if len(src) == 0 || len(src)%c.BlockSize != 0 {
		return errors.New("input length must be a multiple of the block size")
	}

	if len(tweak) < 16 {
		return errors.New("tweak must be at least 16 bytes")
	}

	// Convert the tweak to a sector number (using the first 8 bytes)
	sector := binary.LittleEndian.Uint64(tweak[:8])

	// Use the XTS cipher to decrypt the data
	c.Cipher.Decrypt(dst, src, sector)

	return nil
}

// CreateTweak creates a tweak value from the crypto ID and block number
func CreateTweak(cryptoID, physBlockNum uint64) []byte {
	tweak := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweak, cryptoID)
	binary.LittleEndian.PutUint64(tweak[8:], physBlockNum)
	return tweak
}
