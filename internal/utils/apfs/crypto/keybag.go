package crypto

import (
	"bytes"
	"errors"
)

// NewKBLocker creates a new keybag
func NewKBLocker() *KBLocker {
	return &KBLocker{
		Version: APFSKeybagVersion,
		NKeys:   0,
		NBytes:  0,
		Padding: [8]byte{},
		Entries: []KeybagEntry{},
	}
}

// NewKeybagEntry creates a new keybag entry
func NewKeybagEntry(uuid [16]byte, tag uint16, keyData []byte) KeybagEntry {
	return KeybagEntry{
		UUID:    uuid,
		Tag:     tag,
		KeyLen:  uint16(len(keyData)),
		Padding: [4]byte{},
		KeyData: keyData,
	}
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

// AddEntry adds a new entry to the keybag
func (kbl *KBLocker) AddEntry(entry KeybagEntry) {
	kbl.Entries = append(kbl.Entries, entry)
	kbl.NKeys++
	kbl.NBytes += uint32(24 + len(entry.KeyData)) // Fixed fields + key data
}

// RemoveEntry removes an entry from the keybag by UUID and tag
func (kbl *KBLocker) RemoveEntry(uuid [16]byte, tag uint16) bool {
	for i := range kbl.Entries {
		if bytes.Equal(kbl.Entries[i].UUID[:], uuid[:]) && kbl.Entries[i].Tag == tag {
			// Adjust byte count
			kbl.NBytes -= uint32(24 + len(kbl.Entries[i].KeyData))

			// Remove the entry
			kbl.Entries = append(kbl.Entries[:i], kbl.Entries[i+1:]...)
			kbl.NKeys--
			return true
		}
	}
	return false
}

// Serialize converts the keybag to a byte slice
func (kbl *KBLocker) Serialize() ([]byte, error) {
	// Calculate total size needed
	size := 16 // Fixed fields
	for _, entry := range kbl.Entries {
		size += 24 + len(entry.KeyData)
	}

	buf := make([]byte, size)

	// Write header
	buf[0] = byte(kbl.Version)
	buf[1] = byte(kbl.Version >> 8)
	buf[2] = byte(kbl.NKeys)
	buf[3] = byte(kbl.NKeys >> 8)
	buf[4] = byte(kbl.NBytes)
	buf[5] = byte(kbl.NBytes >> 8)
	buf[6] = byte(kbl.NBytes >> 16)
	buf[7] = byte(kbl.NBytes >> 24)

	// Copy padding
	copy(buf[8:16], kbl.Padding[:])

	// Write entries
	offset := 16
	for _, entry := range kbl.Entries {
		// Copy UUID
		copy(buf[offset:offset+16], entry.UUID[:])
		offset += 16

		// Write tag and key length
		buf[offset] = byte(entry.Tag)
		buf[offset+1] = byte(entry.Tag >> 8)
		buf[offset+2] = byte(entry.KeyLen)
		buf[offset+3] = byte(entry.KeyLen >> 8)
		offset += 4

		// Copy padding
		copy(buf[offset:offset+4], entry.Padding[:])
		offset += 4

		// Copy key data
		copy(buf[offset:offset+len(entry.KeyData)], entry.KeyData)
		offset += len(entry.KeyData)
	}

	return buf, nil
}

// Parse parses a keybag from a byte slice
func (kbl *KBLocker) Parse(data []byte) error {
	if len(data) < 16 {
		return errors.New("data too short for keybag header")
	}

	// Parse header
	kbl.Version = uint16(data[0]) | uint16(data[1])<<8
	kbl.NKeys = uint16(data[2]) | uint16(data[3])<<8
	kbl.NBytes = uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
	copy(kbl.Padding[:], data[8:16])

	// Reset entries
	kbl.Entries = make([]KeybagEntry, 0, kbl.NKeys)

	// Parse entries
	offset := 16
	for i := uint16(0); i < kbl.NKeys; i++ {
		if offset+24 > len(data) {
			return errors.New("data too short for keybag entry")
		}

		var entry KeybagEntry

		// Copy UUID
		copy(entry.UUID[:], data[offset:offset+16])
		offset += 16

		// Parse tag and key length
		entry.Tag = uint16(data[offset]) | uint16(data[offset+1])<<8
		entry.KeyLen = uint16(data[offset+2]) | uint16(data[offset+3])<<8
		offset += 4

		// Copy padding
		copy(entry.Padding[:], data[offset:offset+4])
		offset += 4

		// Check if there's enough data for key data
		if offset+int(entry.KeyLen) > len(data) {
			return errors.New("data too short for keybag entry key data")
		}

		// Copy key data
		entry.KeyData = make([]byte, entry.KeyLen)
		copy(entry.KeyData, data[offset:offset+int(entry.KeyLen)])
		offset += int(entry.KeyLen)

		// Add entry
		kbl.Entries = append(kbl.Entries, entry)
	}

	return nil
}
