// objects.go
/*
Core Object Structures:

ObjectPhys: The base structure for all APFS objects (corresponding to obj_phys_t in the APFS reference)

Includes methods for getting object type, flags, and storage type
Implements checksum verification and calculation
Contains serialization and parsing methods

PRange: A structure representing a range of physical addresses (as defined in the APFS documentation)

Used by various APFS components to define ranges of blocks

CheckpointMapping and CheckPointMappingBlock: Structures for the checkpoint mechanism

Used for mapping ephemeral objects to their on-disk locations

EvictMappingVal: Structure used during partition shrinking operations
OMapKey, OMapVal, OMapSnapshot, and OMapPhys: Core structures for the object map system

Implements the object identifier to physical location mapping
Includes support for snapshots and encryption state


NXEFIJumpstart: Structure for the EFI boot driver embedded in APFS partitions
*/
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ObjectPhys represents the common header at the beginning of all APFS objects (obj_phys_t)
type ObjectPhys struct {
	Checksum [MaxChecksumSize]byte // Fletcher 64 checksum of the object
	OID      uint64                // Object identifier
	XID      uint64                // Transaction identifier
	Type     uint32                // Object type and flags
	Subtype  uint32                // Object subtype
}

// GetObjectType returns the object type (masked with OBJECT_TYPE_MASK)
func (o *ObjectPhys) GetObjectType() uint32 {
	return o.Type & ObjectTypeMask
}

// GetObjectSubtype returns the object subtype
func (o *ObjectPhys) GetObjectSubtype() uint32 {
	return o.Subtype
}

// GetObjectFlags returns the object flags (masked with OBJECT_TYPE_FLAGS_MASK)
func (o *ObjectPhys) GetObjectFlags() uint32 {
	return o.Type & ObjectTypeFlagsMask
}

// GetStorageType returns the storage type (masked with OBJ_STORAGETYPE_MASK)
func (o *ObjectPhys) GetStorageType() uint32 {
	return o.Type & ObjStorageTypeMask
}

// IsVirtual returns true if the object is a virtual object
func (o *ObjectPhys) IsVirtual() bool {
	return o.GetStorageType() == ObjVirtual
}

// IsEphemeral returns true if the object is an ephemeral object
func (o *ObjectPhys) IsEphemeral() bool {
	return o.GetStorageType() == ObjEphemeral
}

// IsPhysical returns true if the object is a physical object
func (o *ObjectPhys) IsPhysical() bool {
	return o.GetStorageType() == ObjPhysical
}

// IsEncrypted returns true if the object is encrypted
func (o *ObjectPhys) IsEncrypted() bool {
	return o.Type&ObjEncrypted != 0
}

// HasNoHeader returns true if the object has no header
func (o *ObjectPhys) HasNoHeader() bool {
	return o.Type&ObjNoheader != 0
}

// Serialize converts the object header to bytes
func (o *ObjectPhys) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, o)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses an object header from bytes
func (o *ObjectPhys) Parse(data []byte) error {
	if len(data) < binary.Size(ObjectPhys{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, o)
}

// String returns a string representation of the object
func (o *ObjectPhys) String() string {
	return fmt.Sprintf("Object{OID: %d, XID: %d, Type: 0x%x, Subtype: 0x%x}",
		o.OID, o.XID, o.Type, o.Subtype)
}

// VerifyChecksum verifies the object's checksum
func (o *ObjectPhys) VerifyChecksum(data []byte) bool {
	// Create a copy of the data to zero out the checksum field
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	for i := 0; i < MaxChecksumSize; i++ {
		dataCopy[i] = 0
	}

	// Calculate the checksum
	checksum := calculateFletcher64(dataCopy)

	// Compare with the stored checksum
	for i := 0; i < MaxChecksumSize; i++ {
		if checksum[i] != o.Checksum[i] {
			return false
		}
	}
	return true
}

// SetChecksum calculates and sets the checksum for the object
func (o *ObjectPhys) SetChecksum(data []byte) {
	// Create a copy of the data to zero out the checksum field
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	for i := 0; i < MaxChecksumSize; i++ {
		dataCopy[i] = 0
	}

	// Calculate the checksum
	checksum := calculateFletcher64(dataCopy)

	// Store the checksum
	copy(o.Checksum[:], checksum[:])
}

// calculateFletcher64 calculates the Fletcher 64 checksum of data
func calculateFletcher64(data []byte) [MaxChecksumSize]byte {
	// Fletcher 64 algorithm
	// Implementation based on the APFS specification
	sum1 := uint32(0)
	sum2 := uint32(0)

	// Process data in 4-byte chunks
	for i := 0; i < len(data); i += 4 {
		if i+4 <= len(data) {
			word := binary.LittleEndian.Uint32(data[i : i+4])
			sum1 = (sum1 + word) % 0xFFFFFFFF
			sum2 = (sum2 + sum1) % 0xFFFFFFFF
		}
	}

	// Handle trailing bytes if data length is not a multiple of 4
	remainingBytes := len(data) % 4
	if remainingBytes > 0 {
		lastBytes := make([]byte, 4)
		copy(lastBytes, data[len(data)-remainingBytes:])
		word := binary.LittleEndian.Uint32(lastBytes)
		sum1 = (sum1 + word) % 0xFFFFFFFF
		sum2 = (sum2 + sum1) % 0xFFFFFFFF
	}

	// Combine the sums into the checksum
	var checksum [MaxChecksumSize]byte
	binary.LittleEndian.PutUint32(checksum[0:], sum1)
	binary.LittleEndian.PutUint32(checksum[4:], sum2)

	return checksum
}

// PRange represents a range of physical addresses (prange_t)
type PRange struct {
	StartPaddr int64  // The first block in the range
	BlockCount uint64 // The number of blocks in the range
}

// NewPRange creates a new PRange
func NewPRange(start int64, count uint64) *PRange {
	return &PRange{
		StartPaddr: start,
		BlockCount: count,
	}
}

// String returns a string representation of the range
func (pr *PRange) String() string {
	return fmt.Sprintf("PRange{Start: %d, Count: %d}", pr.StartPaddr, pr.BlockCount)
}

// Serialize converts the range to bytes
func (pr *PRange) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, pr)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses a range from bytes
func (pr *PRange) Parse(data []byte) error {
	if len(data) < binary.Size(PRange{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, pr)
}

// CheckpointMapping represents a mapping between an ephemeral object identifier and
// its physical address in the checkpoint data area (checkpoint_mapping_t)
type CheckpointMapping struct {
	Type    uint32 // Object type
	Subtype uint32 // Object subtype
	Size    uint32 // Size in bytes of the object
	Pad     uint32 // Reserved
	FSOID   uint64 // Volume object ID this object belongs to
	OID     uint64 // Object ID
	Paddr   uint64 // Physical address
}

// String returns a string representation of the checkpoint mapping
func (cm *CheckpointMapping) String() string {
	return fmt.Sprintf("CheckpointMapping{Type: 0x%x, OID: %d, Paddr: %d}",
		cm.Type, cm.OID, cm.Paddr)
}

// Serialize converts the checkpoint mapping to bytes
func (cm *CheckpointMapping) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, cm)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses a checkpoint mapping from bytes
func (cm *CheckpointMapping) Parse(data []byte) error {
	if len(data) < binary.Size(CheckpointMapping{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, cm)
}

// CheckPointMappingBlock represents a checkpoint-mapping block (checkpoint_map_phys_t)
type CheckPointMappingBlock struct {
	CpmO     ObjectPhys          // Object header
	CpmFlags uint32              // Flags
	CpmCount uint32              // Number of mappings
	CpmMap   []CheckpointMapping // The mappings
}

// IsLastCheckpointMap returns true if this is the last mapping block in a checkpoint
func (cpm *CheckPointMappingBlock) IsLastCheckpointMap() bool {
	return cpm.CpmFlags&CheckpointMapLast != 0
}

// String returns a string representation of the checkpoint mapping block
func (cpm *CheckPointMappingBlock) String() string {
	return fmt.Sprintf("CheckPointMappingBlock{Flags: 0x%x, Count: %d}",
		cpm.CpmFlags, cpm.CpmCount)
}

// Serialize converts the checkpoint mapping block to bytes
func (cpm *CheckPointMappingBlock) Serialize() ([]byte, error) {
	// Calculate the required buffer size
	headerSize := binary.Size(cpm.CpmO) + binary.Size(cpm.CpmFlags) + binary.Size(cpm.CpmCount)
	mappingSize := binary.Size(CheckpointMapping{}) * len(cpm.CpmMap)

	// Create a buffer
	buf := make([]byte, headerSize+mappingSize)

	// Write the header
	binary.LittleEndian.PutUint32(buf[binary.Size(cpm.CpmO):], cpm.CpmFlags)
	binary.LittleEndian.PutUint32(buf[binary.Size(cpm.CpmO)+4:], cpm.CpmCount)

	// Write the mappings
	mappingOffset := headerSize
	for i := 0; i < len(cpm.CpmMap); i++ {
		mapping := cpm.CpmMap[i]
		mappingBytes, err := mapping.Serialize()
		if err != nil {
			return nil, err
		}
		copy(buf[mappingOffset:], mappingBytes)
		mappingOffset += len(mappingBytes)
	}

	// Calculate and set the checksum
	cpm.CpmO.SetChecksum(buf)
	objBytes, err := cpm.CpmO.Serialize()
	if err != nil {
		return nil, err
	}
	copy(buf, objBytes)

	return buf, nil
}

// Parse parses a checkpoint mapping block from bytes
func (cpm *CheckPointMappingBlock) Parse(data []byte) error {
	if len(data) < binary.Size(ObjectPhys{})+8 { // Header + flags + count
		return ErrStructTooShort
	}

	// Parse the header
	err := cpm.CpmO.Parse(data)
	if err != nil {
		return err
	}

	// Verify the checksum
	if !cpm.CpmO.VerifyChecksum(data) {
		return ErrInvalidChecksum
	}

	// Parse flags and count
	cpm.CpmFlags = binary.LittleEndian.Uint32(data[binary.Size(ObjectPhys{}):])
	cpm.CpmCount = binary.LittleEndian.Uint32(data[binary.Size(ObjectPhys{})+4:])

	// Parse mappings
	offset := binary.Size(ObjectPhys{}) + 8
	cpm.CpmMap = make([]CheckpointMapping, cpm.CpmCount)
	for i := uint32(0); i < cpm.CpmCount; i++ {
		if offset+binary.Size(CheckpointMapping{}) > len(data) {
			return ErrStructTooShort
		}

		err := binary.Read(bytes.NewReader(data[offset:]), binary.LittleEndian, &cpm.CpmMap[i])
		if err != nil {
			return err
		}

		offset += binary.Size(CheckpointMapping{})
	}

	return nil
}

// EvictMappingVal represents a range of physical addresses that data is being moved into (evict_mapping_val_t)
type EvictMappingVal struct {
	DstPaddr int64  // The address where the destination starts
	Len      uint64 // The number of blocks being moved
}

// String returns a string representation of the evict mapping value
func (emv *EvictMappingVal) String() string {
	return fmt.Sprintf("EvictMappingVal{DstPaddr: %d, Len: %d}", emv.DstPaddr, emv.Len)
}

// Serialize converts the evict mapping value to bytes
func (emv *EvictMappingVal) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, emv)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses an evict mapping value from bytes
func (emv *EvictMappingVal) Parse(data []byte) error {
	if len(data) < binary.Size(EvictMappingVal{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, emv)
}

// OMapKey represents a key used to access an entry in the object map (omap_key_t)
type OMapKey struct {
	OkOID uint64 // Object identifier
	OkXID uint64 // Transaction identifier
}

// String returns a string representation of the object map key
func (ok *OMapKey) String() string {
	return fmt.Sprintf("OMapKey{OID: %d, XID: %d}", ok.OkOID, ok.OkXID)
}

// Serialize converts the object map key to bytes
func (ok *OMapKey) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, ok)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses an object map key from bytes
func (ok *OMapKey) Parse(data []byte) error {
	if len(data) < binary.Size(OMapKey{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, ok)
}

// OMapVal represents a value in the object map (omap_val_t)
type OMapVal struct {
	OvFlags uint32 // Flags
	OvSize  uint32 // Size in bytes
	OvPaddr uint64 // Object address
}

// IsDeleted returns true if the object has been deleted
func (ov *OMapVal) IsDeleted() bool {
	return ov.OvFlags&OmapValDeleted != 0
}

// IsSaved returns true if the object mapping shouldn't be replaced when the object is updated
func (ov *OMapVal) IsSaved() bool {
	return ov.OvFlags&OmapValSaved != 0
}

// IsEncrypted returns true if the object is encrypted
func (ov *OMapVal) IsEncrypted() bool {
	return ov.OvFlags&OmapValEncrypted != 0
}

// HasNoHeader returns true if the object is stored without a header
func (ov *OMapVal) HasNoHeader() bool {
	return ov.OvFlags&OmapValNoheader != 0
}

// String returns a string representation of the object map value
func (ov *OMapVal) String() string {
	return fmt.Sprintf("OMapVal{Flags: 0x%x, Size: %d, Paddr: %d}",
		ov.OvFlags, ov.OvSize, ov.OvPaddr)
}

// Serialize converts the object map value to bytes
func (ov *OMapVal) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, ov)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses an object map value from bytes
func (ov *OMapVal) Parse(data []byte) error {
	if len(data) < binary.Size(OMapVal{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, ov)
}

// OMapSnapshot represents information about a snapshot of an object map (omap_snapshot_t)
type OMapSnapshot struct {
	OmsFlags uint32 // Flags
	OmsPad   uint32 // Reserved
	OmsOID   uint64 // Reserved
}

// IsDeleted returns true if the snapshot has been deleted
func (os *OMapSnapshot) IsDeleted() bool {
	return os.OmsFlags&OmapSnapshotDeleted != 0
}

// IsReverted returns true if the snapshot has been deleted as part of a revert
func (os *OMapSnapshot) IsReverted() bool {
	return os.OmsFlags&OmapSnapshotReverted != 0
}

// String returns a string representation of the object map snapshot
func (os *OMapSnapshot) String() string {
	return fmt.Sprintf("OMapSnapshot{Flags: 0x%x, OID: %d}", os.OmsFlags, os.OmsOID)
}

// Serialize converts the object map snapshot to bytes
func (os *OMapSnapshot) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, os)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses an object map snapshot from bytes
func (os *OMapSnapshot) Parse(data []byte) error {
	if len(data) < binary.Size(OMapSnapshot{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, os)
}

// OMapPhys represents an object map (omap_phys_t)
type OMapPhys struct {
	OmO                ObjectPhys // Object header
	OmFlags            uint32     // Flags
	OmSnapCount        uint32     // Number of snapshots
	OmTreeType         uint32     // Type of tree used for object mappings
	OmSnapshotTreeType uint32     // Type of tree used for snapshots
	OmTreeOID          uint64     // Object ID of tree used for object mappings
	OmSnapshotTreeOID  uint64     // Object ID of tree used for snapshots
	OmMostRecentSnap   uint64     // Transaction ID of most recent snapshot
	OmPendingRevertMin uint64     // Smallest transaction ID for in-progress revert
	OmPendingRevertMax uint64     // Largest transaction ID for in-progress revert
}

// IsManuallyManaged returns true if the object map doesn't support snapshots
func (om *OMapPhys) IsManuallyManaged() bool {
	return om.OmFlags&OmapManuallyManaged != 0
}

// IsEncrypting returns true if a transition is in progress from unencrypted to encrypted storage
func (om *OMapPhys) IsEncrypting() bool {
	return om.OmFlags&OmapEncrypting != 0
}

// IsDecrypting returns true if a transition is in progress from encrypted to unencrypted storage
func (om *OMapPhys) IsDecrypting() bool {
	return om.OmFlags&OmapDecrypting != 0
}

// IsKeyRolling returns true if a transition is in progress from encrypted storage using an old key to encrypted storage using a new key
func (om *OMapPhys) IsKeyRolling() bool {
	return om.OmFlags&OmapKeyrolling != 0
}

// GetCryptoGeneration returns the crypto generation flag
func (om *OMapPhys) GetCryptoGeneration() bool {
	return om.OmFlags&OmapCryptoGeneration != 0
}

// String returns a string representation of the object map
func (om *OMapPhys) String() string {
	return fmt.Sprintf("OMapPhys{Flags: 0x%x, TreeOID: %d, SnapCount: %d}",
		om.OmFlags, om.OmTreeOID, om.OmSnapCount)
}

// Serialize converts the object map to bytes
func (om *OMapPhys) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, om)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse parses an object map from bytes
func (om *OMapPhys) Parse(data []byte) error {
	if len(data) < binary.Size(OMapPhys{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, om)
}

// NXEFIJumpstart represents information about the embedded EFI driver used to boot from an APFS partition (nx_efi_jumpstart_t)
type NXEFIJumpstart struct {
	NejO          ObjectPhys // Object header
	NejMagic      uint32     // Magic number ('JSDR')
	NejVersion    uint32     // Version
	NejEfiFileLen uint32     // Length in bytes of the embedded EFI driver
	NejNumExtents uint32     // Number of extents
	NejReserved   [16]uint64 // Reserved
	NejRecExtents []PRange   // Extents with the EFI driver
}

// Validate checks if the magic number and version are valid
func (nj *NXEFIJumpstart) Validate() error {
	if nj.NejMagic != EFIJumpstartMagic {
		return ErrInvalidMagic
	}
	if nj.NejVersion != EFIJumpstartVersion {
		return ErrUnsupportedVersion
	}
	return nil
}

// String returns a string representation of the EFI jumpstart
func (nj *NXEFIJumpstart) String() string {
	return fmt.Sprintf("NXEFIJumpstart{Version: %d, FileLen: %d, NumExtents: %d}",
		nj.NejVersion, nj.NejEfiFileLen, nj.NejNumExtents)
}

// Serialize converts the EFI jumpstart to bytes
func (nj *NXEFIJumpstart) Serialize() ([]byte, error) {
	// Calculate the required buffer size
	headerSize := binary.Size(nj.NejO) + 4*4 + 16*8
	extentsSize := binary.Size(PRange{}) * len(nj.NejRecExtents)

	// Create a buffer
	buf := make([]byte, headerSize+extentsSize)

	// Write the header fields
	offset := binary.Size(nj.NejO)
	binary.LittleEndian.PutUint32(buf[offset:], nj.NejMagic)
	binary.LittleEndian.PutUint32(buf[offset+4:], nj.NejVersion)
	binary.LittleEndian.PutUint32(buf[offset+8:], nj.NejEfiFileLen)
	binary.LittleEndian.PutUint32(buf[offset+12:], nj.NejNumExtents)

	// Write the reserved fields
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint64(buf[offset+16+i*8:], nj.NejReserved[i])
	}

	// Write the extents
	extentsOffset := headerSize
	for i := 0; i < len(nj.NejRecExtents); i++ {
		extentBytes, err := nj.NejRecExtents[i].Serialize()
		if err != nil {
			return nil, err
		}
		copy(buf[extentsOffset:], extentBytes)
		extentsOffset += len(extentBytes)
	}

	// Calculate and set the checksum
	nj.NejO.SetChecksum(buf)
	objBytes, err := nj.NejO.Serialize()
	if err != nil {
		return nil, err
	}
	copy(buf, objBytes)

	return buf, nil
}

// Parse parses an EFI jumpstart from bytes
func (nj *NXEFIJumpstart) Parse(data []byte) error {
	// Check minimum size
	minSize := binary.Size(ObjectPhys{}) + 4*4 + 16*8
	if len(data) < minSize {
		return ErrStructTooShort
	}

	// Parse the header
	err := nj.NejO.Parse(data)
	if err != nil {
		return err
	}

	// Verify the checksum
	if !nj.NejO.VerifyChecksum(data) {
		return ErrInvalidChecksum
	}

	// Parse the fields
	offset := binary.Size(ObjectPhys{})
	nj.NejMagic = binary.LittleEndian.Uint32(data[offset:])
	nj.NejVersion = binary.LittleEndian.Uint32(data[offset+4:])
	nj.NejEfiFileLen = binary.LittleEndian.Uint32(data[offset+8:])
	nj.NejNumExtents = binary.LittleEndian.Uint32(data[offset+12:])

	// Parse the reserved fields
	for i := 0; i < 16; i++ {
		nj.NejReserved[i] = binary.LittleEndian.Uint64(data[offset+16+i*8:])
	}

	// Validate the magic and version
	if err := nj.Validate(); err != nil {
		return err
	}

	// Parse the extents
	extentsOffset := minSize
	nj.NejRecExtents = make([]PRange, nj.NejNumExtents)
	for i := uint32(0); i < nj.NejNumExtents; i++ {
		if extentsOffset+binary.Size(PRange{}) > len(data) {
			return ErrStructTooShort
		}

		err := binary.Read(bytes.NewReader(data[extentsOffset:]), binary.LittleEndian, &nj.NejRecExtents[i])
		if err != nil {
			return err
		}

		extentsOffset += binary.Size(PRange{})
	}

	return nil
}
