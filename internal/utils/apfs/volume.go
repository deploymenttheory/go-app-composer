// volume.go
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// APFSSuperblock represents a volume superblock (apfs_superblock_t)
type APFSSuperblock struct {
	ObjectHeader           ObjectPhys
	Magic                  uint32
	FsIndex                uint32
	Features               uint64
	ReadOnlyCompatFeatures uint64
	IncompatFeatures       uint64
	UnmountTime            uint64
	ReservedBlocks         uint64
	QuotaBlocks            uint64
	AllocBlocks            uint64
	BlockSize              uint32
	RootTreeOID            uint64
	ExtentRefTreeOID       uint64
	SnapMetaTreeOID        uint64
	OMAPOID                uint64
	ReaperOID              uint64
	NextObjID              uint64
	NumFiles               uint64
	NumDirectories         uint64
	NumSymlinks            uint64
	NumOtherFSObjects      uint64
	TotalNodes             uint64
	TotalExtents           uint64
	APFSRole               uint16
	Reserved               uint16
	VolumeName             [256]byte
	NextDocID              uint32
	NumSnapshots           uint32
	SnapshotsOID           uint64
	CryptoStateOID         uint64
	Flags                  uint64
	ModifiedBy             [32]byte
}

// IsValid checks if the APFS superblock has a valid magic number
func (sb *APFSSuperblock) IsValid() bool {
	return sb.Magic == APFSMagic
}

// GetVolumeName returns the APFS volume name as a string
func (sb *APFSSuperblock) GetVolumeName() string {
	nameBytes := bytes.Trim(sb.VolumeName[:], "\x00")
	return string(nameBytes)
}

// HasFeature checks if a given feature flag is set
func (sb *APFSSuperblock) HasFeature(feature uint64) bool {
	return sb.Features&feature != 0
}

// HasIncompatFeature checks if a given incompatible feature flag is set
func (sb *APFSSuperblock) HasIncompatFeature(feature uint64) bool {
	return sb.IncompatFeatures&feature != 0
}

// Parse parses an APFS superblock from raw bytes
func (sb *APFSSuperblock) Parse(data []byte) error {
	if len(data) < binary.Size(APFSSuperblock{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, sb)
}

// Serialize converts the APFS superblock into raw bytes
func (sb *APFSSuperblock) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, sb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// String returns a formatted string representation of the superblock
func (sb *APFSSuperblock) String() string {
	return fmt.Sprintf("APFSSuperblock{Name: '%s', UUID: %x, BlockSize: %d, RootTreeOID: %d}",
		sb.GetVolumeName(), sb.ObjectHeader.OID, sb.BlockSize, sb.RootTreeOID)
}

// Volume flag constants (from APFS spec)
const (

	// Optional Volume Feature Flags
	VolumeFeatureCaseSensitive uint64 = 0x0000000000000001
	VolumeFeatureEncryption    uint64 = 0x0000000000000004

	// Incompatible Volume Feature Flags
	VolumeIncompatFeatureCompression uint64 = 0x0000000000000001
	VolumeIncompatFeatureSnapshot    uint64 = 0x0000000000000002
)

// APFS Volume Roles
const (
	VolumeRoleNone      uint16 = 0x0000
	VolumeRoleSystem    uint16 = 0x0001
	VolumeRoleUser      uint16 = 0x0002
	VolumeRoleRecovery  uint16 = 0x0004
	VolumeRoleVM        uint16 = 0x0008
	VolumeRolePreboot   uint16 = 0x0010
	VolumeRoleInstaller uint16 = 0x0020
	VolumeRoleData      uint16 = 0x0040
	VolumeRoleBaseband  uint16 = 0x0080
	VolumeRoleUpdate    uint16 = 0x0100
	VolumeRoleXART      uint16 = 0x0200
	VolumeRoleHardware  uint16 = 0x0400
	VolumeRoleBackup    uint16 = 0x0800
	VolumeRoleReserved  uint16 = 0xFFFF
)

// ModifiedBy represents the "modified by" structure (apfs_modified_by_t)
type ModifiedBy struct {
	ID      [32]byte
	Version uint64
}

// ParseModifiedBy parses the ModifiedBy structure from bytes
func ParseModifiedBy(data []byte) (*ModifiedBy, error) {
	if len(data) < binary.Size(ModifiedBy{}) {
		return nil, ErrStructTooShort
	}
	var mb ModifiedBy
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &mb)
	if err != nil {
		return nil, err
	}
	return &mb, nil
}

// Serialize serializes ModifiedBy into bytes
func (mb *ModifiedBy) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, mb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// String returns a formatted string representation of ModifiedBy
func (mb *ModifiedBy) String() string {
	return fmt.Sprintf("ModifiedBy{ID: %x, Version: %d}", mb.ID, mb.Version)
}
