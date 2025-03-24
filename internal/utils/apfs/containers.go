// container.go
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// NXSuperblock represents a container superblock (nx_superblock_t)
type NXSuperblock struct {
	NXO                    ObjectPhys               // Object header
	Magic                  uint32                   // Magic number ('NXSB')
	BlockSize              uint32                   // Block size of the container
	BlockCount             uint64                   // Number of blocks in the container
	Features               uint64                   // Optional features
	ReadOnlyCompatFeatures uint64                   // Read-only compatible features
	IncompatFeatures       uint64                   // Backwards incompatible features
	UUID                   [16]byte                 // Container UUID
	NextOID                uint64                   // Next object identifier
	NextXID                uint64                   // Next transaction identifier
	XPDescBlocks           uint32                   // Number of blocks used for checkpoint descriptors
	XPDataBlocks           uint32                   // Number of blocks used for checkpoint data
	XPDescBase             uint64                   // Base address of checkpoint descriptor area
	XPDataBase             uint64                   // Base address of checkpoint data area
	XPDescNext             uint32                   // Next index to use in checkpoint descriptor area
	XPDataNext             uint32                   // Next index to use in checkpoint data area
	XPDescIndex            uint32                   // Index of first valid item in checkpoint descriptor area
	XPDescLen              uint32                   // Length of valid items in checkpoint descriptor area
	XPDataIndex            uint32                   // Index of first valid item in checkpoint data area
	XPDataLen              uint32                   // Length of valid items in checkpoint data area
	SpacemanOID            uint64                   // Object identifier for the space manager
	OMapOID                uint64                   // Object identifier for the container object map
	ReaperOID              uint64                   // Object identifier for the reaper
	TestType               uint32                   // Reserved for testing
	MaxFileSystems         uint32                   // Maximum number of volumes in the container
	FSOID                  [NXMaxFileSystems]uint64 // Array of volume OIDs
	Counters               [NXNumCounters]uint64    // Array of counters
	BlockedOutPrange       PRange                   // Physical range of blocks that are not allocated
	EvictMappingTreeOID    uint64                   // Object identifier for the evict mapping tree
	Flags                  uint64                   // Container flags
	EFIJumpstart           uint64                   // Address of the EFI jumpstart object
	FusionUUID             [16]byte                 // UUID for fusion drive set
	KeyLocker              PRange                   // Location of the container's keybag
	EphemeralInfo          [NXEphInfoCount]uint64   // Array of ephemeral data information
	TestOID                uint64                   // Reserved for testing
	FusionMTOID            uint64                   // Object identifier for the fusion middle tree
	FusionWBCOID           uint64                   // Object identifier for the fusion write-back cache object
	FusionWBC              PRange                   // Fusion write-back cache range
	NewestMountedVersion   uint64                   // The newest version that mounted this container
	MkbLocker              PRange                   // Wrapped media key location
}

// IsValid checks if the superblock is valid by verifying the magic number
func (sb *NXSuperblock) IsValid() bool {
	return sb.Magic == NXMagic
}

// SupportsCaseSensitivity returns whether the container supports case sensitivity
func (sb *NXSuperblock) SupportsCaseSensitivity() bool {
	// Need to check the incompatible features - volumes in this container
	// can be either case sensitive or insensitive, but the container must
	// support the feature
	return true
}

// SupportsHardlinkMaps returns whether the container supports hardlink maps
func (sb *NXSuperblock) SupportsHardlinkMaps() bool {
	return sb.Features&NXFeatureDefrag != 0
}

// IsFusionDrive returns whether this is a fusion drive container
func (sb *NXSuperblock) IsFusionDrive() bool {
	return sb.IncompatFeatures&NXIncompatFusion != 0
}

// UsesSoftwareEncryption returns whether this container uses software encryption
func (sb *NXSuperblock) UsesSoftwareEncryption() bool {
	return sb.Flags&NXCryptoSW != 0
}

// IsCheckpointDataAreaContiguous returns whether the checkpoint data area is contiguous
func (sb *NXSuperblock) IsCheckpointDataAreaContiguous() bool {
	return sb.XPDataBlocks&0x80000000 == 0
}

// IsCheckpointDescAreaContiguous returns whether the checkpoint descriptor area is contiguous
func (sb *NXSuperblock) IsCheckpointDescAreaContiguous() bool {
	return sb.XPDescBlocks&0x80000000 == 0
}

// GetCheckpointDataAreaSize returns the number of blocks in the checkpoint data area
func (sb *NXSuperblock) GetCheckpointDataAreaSize() uint32 {
	return sb.XPDataBlocks & 0x7FFFFFFF
}

// GetCheckpointDescAreaSize returns the number of blocks in the checkpoint descriptor area
func (sb *NXSuperblock) GetCheckpointDescAreaSize() uint32 {
	return sb.XPDescBlocks & 0x7FFFFFFF
}

// HasValidVersion checks if the container has a valid and supported APFS version
func (sb *NXSuperblock) HasValidVersion() bool {
	// Check for Version 2 which is the current APFS version
	return sb.IncompatFeatures&NXIncompatVersion2 != 0
}

// String returns a string representation of the container superblock
func (sb *NXSuperblock) String() string {
	return fmt.Sprintf("NXSuperblock{UUID: %x, BlockSize: %d, BlockCount: %d, NextXID: %d}",
		sb.UUID, sb.BlockSize, sb.BlockCount, sb.NextXID)
}

// Parse parses a container superblock from bytes
func (sb *NXSuperblock) Parse(data []byte) error {
	if len(data) < binary.Size(NXSuperblock{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, sb)
}

// Serialize converts the container superblock to bytes
func (sb *NXSuperblock) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, sb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ChunkInfo represents a chunk info entry (chunk_info_t)
type ChunkInfo struct {
	CiXID        uint64
	CiAddr       uint64
	CiBlockCount uint32
	CiFreeCount  uint32
	CiBitmapAddr uint64
}

// String returns a string representation of the chunk info
func (ci *ChunkInfo) String() string {
	return fmt.Sprintf("ChunkInfo{XID: %d, Addr: %d, BlockCount: %d, FreeCount: %d}",
		ci.CiXID, ci.CiAddr, ci.CiBlockCount, ci.CiFreeCount)
}

// ChunkInfoBlock represents a block of chunk info entries (chunk_info_block_t)
type ChunkInfoBlock struct {
	CibO              ObjectPhys
	CibIndex          uint32
	CibChunkInfoCount uint32
	CibChunkInfo      []ChunkInfo
}

// String returns a string representation of the chunk info block
func (cib *ChunkInfoBlock) String() string {
	return fmt.Sprintf("ChunkInfoBlock{Index: %d, ChunkInfoCount: %d}",
		cib.CibIndex, cib.CibChunkInfoCount)
}

// CIBAddrBlock represents a block of chunk info block addresses (cib_addr_block_t)
type CIBAddrBlock struct {
	CabO        ObjectPhys
	CabIndex    uint32
	CabCibCount uint32
	CabCibAddr  []uint64
}

// String returns a string representation of the CIB address block
func (cab *CIBAddrBlock) String() string {
	return fmt.Sprintf("CIBAddrBlock{Index: %d, CibCount: %d}",
		cab.CabIndex, cab.CabCibCount)
}

// SpacemanFreeQueueEntry represents an entry in the space manager free queue (spaceman_free_queue_entry_t)
type SpacemanFreeQueueEntry struct {
	SfqeKey   SpacemanFreeQueueKey
	SfqeCount uint64
}

// String returns a string representation of the free queue entry
func (entry *SpacemanFreeQueueEntry) String() string {
	return fmt.Sprintf("SpacemanFreeQueueEntry{Key: %s, Count: %d}",
		entry.SfqeKey.String(), entry.SfqeCount)
}

// SpacemanFreeQueueKey represents the key for a free queue entry (spaceman_free_queue_key_t)
type SpacemanFreeQueueKey struct {
	SfqkXID   uint64
	SfqkPaddr uint64
}

// String returns a string representation of the free queue key
func (key *SpacemanFreeQueueKey) String() string {
	return fmt.Sprintf("SpacemanFreeQueueKey{XID: %d, Paddr: %d}",
		key.SfqkXID, key.SfqkPaddr)
}

// SpacemanFreeQueue represents a free queue in the space manager (spaceman_free_queue_t)
type SpacemanFreeQueue struct {
	SfqCount         uint64
	SfqTreeOID       uint64
	SfqOldestXID     uint64
	SfqTreeNodeLimit uint16
	SfqPad16         uint16
	SfqPad32         uint32
	SfqReserved      uint64
}

// String returns a string representation of the free queue
func (queue *SpacemanFreeQueue) String() string {
	return fmt.Sprintf("SpacemanFreeQueue{Count: %d, TreeOID: %d, OldestXID: %d}",
		queue.SfqCount, queue.SfqTreeOID, queue.SfqOldestXID)
}

// SpacemanDevice represents the space manager's view of a device (spaceman_device_t)
type SpacemanDevice struct {
	SmBlockCount uint64
	SmChunkCount uint64
	SmCibCount   uint32
	SmCabCount   uint32
	SmFreeCount  uint64
	SmAddrOffset uint32
	SmReserved   uint32
	SmReserved2  uint64
}

// String returns a string representation of the spaceman device
func (dev *SpacemanDevice) String() string {
	return fmt.Sprintf("SpacemanDevice{BlockCount: %d, ChunkCount: %d, FreeCount: %d}",
		dev.SmBlockCount, dev.SmChunkCount, dev.SmFreeCount)
}

// SpacemanAllocationZoneBoundaries represents the boundaries of an allocation zone (spaceman_allocation_zone_boundaries_t)
type SpacemanAllocationZoneBoundaries struct {
	SazZoneStart uint64
	SazZoneEnd   uint64
}

// String returns a string representation of the zone boundaries
func (bounds *SpacemanAllocationZoneBoundaries) String() string {
	return fmt.Sprintf("SpacemanAllocationZoneBoundaries{Start: %d, End: %d}",
		bounds.SazZoneStart, bounds.SazZoneEnd)
}

// SpacemanAllocationZoneInfoPhys represents a zone info structure (spaceman_allocation_zone_info_phys_t)
type SpacemanAllocationZoneInfoPhys struct {
	SazCurrentBoundaries     SpacemanAllocationZoneBoundaries
	SazPreviousBoundaries    [SMAllocznumPreviousBoundaries]SpacemanAllocationZoneBoundaries
	SazZoneID                uint16
	SazPreviousBoundaryIndex uint16
	SazReserved              uint32
}

// SMAllocznumPreviousBoundaries is the number of previous boundaries stored for each zone
const SMAllocznumPreviousBoundaries = 7

// String returns a string representation of the zone info
func (info *SpacemanAllocationZoneInfoPhys) String() string {
	return fmt.Sprintf("SpacemanAllocationZoneInfoPhys{ZoneID: %d, CurrentBoundaries: %s}",
		info.SazZoneID, info.SazCurrentBoundaries.String())
}

// SMDatazoneAlloczoneCount is the number of allocation zones in a data zone
const SMDatazoneAlloczoneCount = 8

// SpacemanDatazoneInfoPhys represents the data zone info (spaceman_datazone_info_phys_t)
type SpacemanDatazoneInfoPhys struct {
	SdzAllocationZones [SDCount][SMDatazoneAlloczoneCount]SpacemanAllocationZoneInfoPhys
}

// String returns a string representation of the data zone info
func (info *SpacemanDatazoneInfoPhys) String() string {
	return "SpacemanDatazoneInfoPhys{...}" // Simplified for brevity
}

// SpacemanPhys represents the space manager (spaceman_phys_t)
type SpacemanPhys struct {
	SmO                   ObjectPhys
	SmBlockSize           uint32
	SmBlocksPerChunk      uint32
	SmChunksPerCib        uint32
	SmCibsPerCab          uint32
	SmDev                 [SDCount]SpacemanDevice
	SmFlags               uint32
	SmIPBmTxMultiplier    uint32
	SmIPBlockCount        uint64
	SmIPBmSizeInBlocks    uint32
	SmIPBmBlockCount      uint32
	SmIPBmBase            uint64
	SmIPBase              uint64
	SmFSReserveBlockCount uint64
	SmFSReserveAllocCount uint64
	SmFq                  [SFQCount]SpacemanFreeQueue
	SmIPBmFreeHead        uint16
	SmIPBmFreeTail        uint16
	SmIPBmXidOffset       uint32
	SmIPBitmapOffset      uint32
	SmIPBmFreeNextOffset  uint32
	SmVersion             uint32
	SmStructSize          uint32
	SmDatazone            SpacemanDatazoneInfoPhys
}

// SMFlagVersioned is a flag indicating the space manager is versioned
const SMFlagVersioned = 0x00000001

// String returns a string representation of the space manager
func (sm *SpacemanPhys) String() string {
	return fmt.Sprintf("SpacemanPhys{Version: %d, BlockSize: %d, IPBlockCount: %d}",
		sm.SmVersion, sm.SmBlockSize, sm.SmIPBlockCount)
}

// IsVersioned returns whether the space manager is versioned
func (sm *SpacemanPhys) IsVersioned() bool {
	return sm.SmFlags&SMFlagVersioned != 0
}

// NXReaperPhys represents the reaper (nx_reaper_phys_t)
type NXReaperPhys struct {
	NrO               ObjectPhys
	NrNextReapID      uint64
	NrCompletedID     uint64
	NrHead            uint64
	NrTail            uint64
	NrFlags           uint32
	NrRlcount         uint32
	NrType            uint32
	NrSize            uint32
	NrFsOID           uint64
	NrOID             uint64
	NrXID             uint64
	NrNrleFlags       uint32
	NrStateBufferSize uint32
	NrStateBuffer     []byte
}

// String returns a string representation of the reaper
func (nr *NXReaperPhys) String() string {
	return fmt.Sprintf("NXReaperPhys{NextReapID: %d, CompletedID: %d, Flags: 0x%x}",
		nr.NrNextReapID, nr.NrCompletedID, nr.NrFlags)
}

// NXReapListPhys represents a reap list (nx_reap_list_phys_t)
type NXReapListPhys struct {
	NrlO       ObjectPhys
	NrlNext    uint64
	NrlFlags   uint32
	NrlMax     uint32
	NrlCount   uint32
	NrlFirst   uint32
	NrlLast    uint32
	NrlFree    uint32
	NrlEntries []NXReapListEntry
}

// String returns a string representation of the reap list
func (nrl *NXReapListPhys) String() string {
	return fmt.Sprintf("NXReapListPhys{Flags: 0x%x, Count: %d, Max: %d}",
		nrl.NrlFlags, nrl.NrlCount, nrl.NrlMax)
}

// NXReapListEntry represents an entry in a reap list (nx_reap_list_entry_t)
type NXReapListEntry struct {
	NrleNext  uint32
	NrleFlags uint32
	NrleType  uint32
	NrleSize  uint32
	NrleFsOID uint64
	NrleOID   uint64
	NrleXID   uint64
}

// String returns a string representation of the reap list entry
func (nrle *NXReapListEntry) String() string {
	return fmt.Sprintf("NXReapListEntry{Flags: 0x%x, OID: %d, XID: %d}",
		nrle.NrleFlags, nrle.NrleOID, nrle.NrleXID)
}

// OMapReapState represents the state used when reaping an object map (omap_reap_state_t)
type OMapReapState struct {
	OmrPhase uint32
	OmrOk    OMapKey
}

// String returns a string representation of the object map reap state
func (omr *OMapReapState) String() string {
	return fmt.Sprintf("OMapReapState{Phase: %d, OkOID: %d, OkXID: %d}",
		omr.OmrPhase, omr.OmrOk.OkOID, omr.OmrOk.OkXID)
}

// OMapCleanupState represents the state used when cleaning up after deleting snapshots (omap_cleanup_state_t)
type OMapCleanupState struct {
	OmcCleaning  uint32
	OmcOmsflags  uint32
	OmcSxidprev  uint64
	OmcSxidstart uint64
	OmcSxidend   uint64
	OmcSxidnext  uint64
	OmcCurkey    OMapKey
}

// String returns a string representation of the object map cleanup state
func (omc *OMapCleanupState) String() string {
	return fmt.Sprintf("OMapCleanupState{Cleaning: %d, Start: %d, End: %d}",
		omc.OmcCleaning, omc.OmcSxidstart, omc.OmcSxidend)
}

// APFSReapState represents the state used during volume reaping (apfs_reap_state_t)
type APFSReapState struct {
	LastPbn    uint64
	CurSnapXID uint64
	Phase      uint32
}

// String returns a string representation of the APFS reap state
func (ars *APFSReapState) String() string {
	return fmt.Sprintf("APFSReapState{Phase: %d, LastPbn: %d, CurSnapXID: %d}",
		ars.Phase, ars.LastPbn, ars.CurSnapXID)
}

// KeybagEntry represents an entry in a keybag (keybag_entry_t)
type KeybagEntry struct {
	KeUUID    [16]byte
	KeTag     uint16
	KeKeylen  uint16
	KePadding [4]byte
	KeKeydata []byte
}

// String returns a string representation of the keybag entry
func (ke *KeybagEntry) String() string {
	return fmt.Sprintf("KeybagEntry{UUID: %x, Tag: %d, Keylen: %d}",
		ke.KeUUID, ke.KeTag, ke.KeKeylen)
}

// KBLocker represents a keybag (kb_locker_t)
type KBLocker struct {
	KlVersion uint16
	KlNkeys   uint16
	KlNbytes  uint32
	KlPadding [8]byte
	KlEntries []KeybagEntry
}

// String returns a string representation of the keybag
func (kl *KBLocker) String() string {
	return fmt.Sprintf("KBLocker{Version: %d, Nkeys: %d, Nbytes: %d}",
		kl.KlVersion, kl.KlNkeys, kl.KlNbytes)
}

// MediaKeybag represents a keybag in a container (media_keybag_t)
type MediaKeybag struct {
	MkObj    ObjectPhys
	MkLocker KBLocker
}

// String returns a string representation of the media keybag
func (mk *MediaKeybag) String() string {
	return fmt.Sprintf("MediaKeybag{Locker: %s}", mk.MkLocker.String())
}

// ContainerManager manages an APFS container
type ContainerManager struct {
	device        io.ReadWriteSeeker
	superblock    *NXSuperblock
	checkpoint    *CheckpointInfo
	spaceman      *SpacemanPhys
	omap          *OMapPhys
	reaper        *NXReaperPhys
	keybag        *MediaKeybag
	ephemeralObjs map[uint64][]byte
	blockSize     uint32
}

// CheckpointInfo represents information about a container checkpoint
type CheckpointInfo struct {
	Superblock     *NXSuperblock
	CheckpointMaps []*CheckPointMappingBlock
	XID            uint64
}

// NewContainerManager creates a new container manager
func NewContainerManager(device io.ReadWriteSeeker) (*ContainerManager, error) {
	// Create the container manager
	cm := &ContainerManager{
		device:        device,
		ephemeralObjs: make(map[uint64][]byte),
		blockSize:     DefaultBlockSize,
	}

	// Read the container superblock from block 0
	err := cm.readSuperblockFromBlockZero()
	if err != nil {
		return nil, fmt.Errorf("failed to read superblock: %w", err)
	}

	// Locate the latest checkpoint
	checkpoint, err := cm.findLatestCheckpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to find valid checkpoint: %w", err)
	}
	cm.checkpoint = checkpoint
	cm.superblock = checkpoint.Superblock
	cm.blockSize = cm.superblock.BlockSize

	// Load ephemeral objects
	err = cm.loadEphemeralObjects()
	if err != nil {
		return nil, fmt.Errorf("failed to load ephemeral objects: %w", err)
	}

	// Load the space manager
	err = cm.loadSpaceManager()
	if err != nil {
		return nil, fmt.Errorf("failed to load space manager: %w", err)
	}

	// Load the object map
	err = cm.loadObjectMap()
	if err != nil {
		return nil, fmt.Errorf("failed to load object map: %w", err)
	}

	// Load the reaper
	if cm.superblock.ReaperOID != 0 {
		err = cm.loadReaper()
		if err != nil {
			return nil, fmt.Errorf("failed to load reaper: %w", err)
		}
	}

	// Load the keybag if present
	if cm.superblock.KeyLocker.BlockCount > 0 {
		err = cm.loadKeybag()
		if err != nil {
			return nil, fmt.Errorf("failed to load keybag: %w", err)
		}
	}

	return cm, nil
}

// readSuperblockFromBlockZero reads the superblock from block 0
func (cm *ContainerManager) readSuperblockFromBlockZero() error {
	// Read block 0
	buf := make([]byte, cm.blockSize)
	_, err := cm.device.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(cm.device, buf)
	if err != nil {
		return err
	}

	// Parse the superblock
	sb := &NXSuperblock{}
	err = sb.Parse(buf)
	if err != nil {
		return err
	}

	// Verify the magic number
	if !sb.IsValid() {
		return ErrInvalidMagic
	}

	// Verify the block size
	if sb.BlockSize < MinimumBlockSize || sb.BlockSize > MaximumBlockSize {
		return ErrInvalidBlockSize
	}

	// Check the container version
	if !sb.HasValidVersion() {
		return ErrUnsupportedVersion
	}

	// Set the container superblock
	cm.superblock = sb
	cm.blockSize = sb.BlockSize

	return nil
}

// findLatestCheckpoint finds the latest valid checkpoint in the container
func (cm *ContainerManager) findLatestCheckpoint() (*CheckpointInfo, error) {
	// Get information about the checkpoint areas
	descBase := cm.superblock.XPDescBase
	descBlocks := cm.superblock.GetCheckpointDescAreaSize()

	// Read all checkpoint descriptor blocks
	var validCheckpoints []*CheckpointInfo

	// Read each block in the checkpoint descriptor area
	for i := uint32(0); i < descBlocks; i++ {
		// Calculate the block offset
		offset := int64(descBase)*int64(cm.blockSize) + int64(i)*int64(cm.blockSize)

		// Read the block
		buf := make([]byte, cm.blockSize)
		_, err := cm.device.Seek(offset, io.SeekStart)
		if err != nil {
			continue
		}

		_, err = io.ReadFull(cm.device, buf)
		if err != nil {
			continue
		}

		// Parse the object header
		obj := &ObjectPhys{}
		err = obj.Parse(buf)
		if err != nil {
			continue
		}

		// Check if this is a superblock or a checkpoint mapping
		objType := obj.GetObjectType()

		if objType == ObjectTypeNXSuperblock {
			// This is a container superblock
			sb := &NXSuperblock{}
			err = sb.Parse(buf)
			if err != nil {
				continue
			}

			// Verify the magic number
			if !sb.IsValid() {
				continue
			}

			// Create a new checkpoint
			cp := &CheckpointInfo{
				Superblock: sb,
				XID:        obj.XID,
			}

			// Find all checkpoint mappings for this superblock
			err = cm.findCheckpointMappings(cp)
			if err != nil {
				continue
			}

			validCheckpoints = append(validCheckpoints, cp)
		}
	}

	// Find the checkpoint with the highest XID
	if len(validCheckpoints) == 0 {
		return nil, ErrNoValidCheckpoint
	}

	latestCheckpoint := validCheckpoints[0]
	for _, cp := range validCheckpoints[1:] {
		if cp.XID > latestCheckpoint.XID {
			latestCheckpoint = cp
		}
	}

	return latestCheckpoint, nil
}

// findCheckpointMappings finds all checkpoint mappings for a superblock
func (cm *ContainerManager) findCheckpointMappings(cp *CheckpointInfo) error {
	// Get information about the checkpoint descriptor area
	descBase := cp.Superblock.XPDescBase
	descIndex := cp.Superblock.XPDescIndex
	descLen := cp.Superblock.XPDescLen

	// Read each block in the checkpoint descriptor area for this checkpoint
	for i := uint32(0); i < descLen; i++ {
		// Calculate the index in the circular buffer
		index := (descIndex + i) % cp.Superblock.GetCheckpointDescAreaSize()

		// Calculate the block offset
		offset := int64(descBase)*int64(cm.blockSize) + int64(index)*int64(cm.blockSize)

		// Read the block
		buf := make([]byte, cm.blockSize)
		_, err := cm.device.Seek(offset, io.SeekStart)
		if err != nil {
			return err
		}

		_, err = io.ReadFull(cm.device, buf)
		if err != nil {
			return err
		}

		// Parse the object header
		obj := &ObjectPhys{}
		err = obj.Parse(buf)
		if err != nil {
			continue
		}

		// Check if this is a checkpoint mapping
		if obj.GetObjectType() == ObjectTypeCheckpointMap {
			// This is a checkpoint mapping
			cpm := &CheckPointMappingBlock{}
			err = cpm.Parse(buf)
			if err != nil {
				continue
			}

			// Add the checkpoint mapping to the list
			cp.CheckpointMaps = append(cp.CheckpointMaps, cpm)

			// Check if this is the last mapping block
			if cpm.IsLastCheckpointMap() {
				break
			}
		}
	}

	return nil
}

// loadEphemeralObjects loads ephemeral objects from the checkpoint
func (cm *ContainerManager) loadEphemeralObjects() error {
	// Check if we have a valid checkpoint
	if cm.checkpoint == nil {
		return ErrNoValidCheckpoint
	}

	// Process each checkpoint mapping
	for _, cpm := range cm.checkpoint.CheckpointMaps {
		for _, mapping := range cpm.CpmMap {
			// Check if this is an ephemeral object
			if mapping.Type&ObjStorageTypeMask == ObjEphemeral {
				// Read the ephemeral object from the checkpoint data area
				err := cm.loadEphemeralObject(mapping)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// loadEphemeralObject loads a single ephemeral object from the checkpoint data area
func (cm *ContainerManager) loadEphemeralObject(mapping CheckpointMapping) error {
	// Calculate the offset in the checkpoint data area
	dataBase := cm.checkpoint.Superblock.XPDataBase
	offset := int64(dataBase)*int64(cm.blockSize) + int64(mapping.Paddr)*int64(cm.blockSize)

	// Read the object
	buf := make([]byte, mapping.Size)
	_, err := cm.device.Seek(offset, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to ephemeral object at offset %d: %w", offset, err)
	}

	_, err = io.ReadFull(cm.device, buf)
	if err != nil {
		return fmt.Errorf("failed to read ephemeral object data: %w", err)
	}

	// Verify the object header if it has one
	if mapping.Type&ObjNoheader == 0 {
		obj := &ObjectPhys{}
		err = obj.Parse(buf)
		if err != nil {
			return fmt.Errorf("failed to parse ephemeral object header: %w", err)
		}

		// Verify the checksum
		if !cm.verifyChecksum(buf, obj.Checksum[:]) {
			return fmt.Errorf("invalid checksum for ephemeral object %d", mapping.OID)
		}

		// Verify object type and subtype match
		if obj.Type != mapping.Type || obj.Subtype != mapping.Subtype {
			return fmt.Errorf("ephemeral object type/subtype mismatch: expected %d/%d, got %d/%d",
				mapping.Type, mapping.Subtype, obj.Type, obj.Subtype)
		}
	}

	// Store the ephemeral object in memory
	cm.ephemeralObjs[mapping.OID] = buf

	return nil
}

// loadSpaceManager loads the space manager from ephemeral objects
func (cm *ContainerManager) loadSpaceManager() error {
	// Get the space manager OID from the superblock
	spacemanOID := cm.superblock.SpacemanOID
	if spacemanOID == 0 {
		return fmt.Errorf("space manager OID not found in superblock")
	}

	// Get the space manager from ephemeral objects
	spacemanData, ok := cm.ephemeralObjs[spacemanOID]
	if !ok {
		return fmt.Errorf("space manager ephemeral object not found")
	}

	// Parse the space manager
	sm := &SpacemanPhys{}
	err := sm.Parse(spacemanData)
	if err != nil {
		return fmt.Errorf("failed to parse space manager: %w", err)
	}

	// Verify object type is space manager
	if sm.SmO.GetObjectType() != ObjectTypeSpaceman {
		return fmt.Errorf("invalid object type for space manager: %d", sm.SmO.GetObjectType())
	}

	cm.spaceman = sm
	return nil
}

// loadObjectMap loads the container object map
func (cm *ContainerManager) loadObjectMap() error {
	// Get the object map OID from the superblock
	omapOID := cm.superblock.OMapOID
	if omapOID == 0 {
		return fmt.Errorf("object map OID not found in superblock")
	}

	// Read the object map
	omapData, err := cm.readPhysicalObject(omapOID)
	if err != nil {
		return fmt.Errorf("failed to read object map: %w", err)
	}

	// Parse the object map
	omap := &OMapPhys{}
	err = omap.Parse(omapData)
	if err != nil {
		return fmt.Errorf("failed to parse object map: %w", err)
	}

	// Verify object type is object map
	if omap.OmO.GetObjectType() != ObjectTypeOMAP {
		return fmt.Errorf("invalid object type for object map: %d", omap.OmO.GetObjectType())
	}

	cm.omap = omap
	return nil
}

// loadReaper loads the reaper from ephemeral objects
func (cm *ContainerManager) loadReaper() error {
	// Get the reaper OID from the superblock
	reaperOID := cm.superblock.ReaperOID
	if reaperOID == 0 {
		// No reaper, not an error
		return nil
	}

	// Get the reaper from ephemeral objects
	reaperData, ok := cm.ephemeralObjs[reaperOID]
	if !ok {
		return fmt.Errorf("reaper ephemeral object not found")
	}

	// Parse the reaper
	reaper := &NXReaperPhys{}
	err := reaper.Parse(reaperData)
	if err != nil {
		return fmt.Errorf("failed to parse reaper: %w", err)
	}

	// Verify object type is reaper
	if reaper.NrO.GetObjectType() != ObjectTypeNXReaper {
		return fmt.Errorf("invalid object type for reaper: %d", reaper.NrO.GetObjectType())
	}

	cm.reaper = reaper
	return nil
}

// loadKeybag loads the container keybag
func (cm *ContainerManager) loadKeybag() error {
	if cm.superblock.KeyLocker.BlockCount == 0 {
		// No keybag, not an error
		return nil
	}

	// Calculate the location of the keybag
	offset := int64(cm.superblock.KeyLocker.Start) * int64(cm.blockSize)
	size := int64(cm.superblock.KeyLocker.BlockCount) * int64(cm.blockSize)

	// Read the keybag
	buf := make([]byte, size)
	_, err := cm.device.Seek(offset, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to keybag: %w", err)
	}

	_, err = io.ReadFull(cm.device, buf)
	if err != nil {
		return fmt.Errorf("failed to read keybag: %w", err)
	}

	// Parse the keybag
	keybag := &MediaKeybag{}
	err = keybag.Parse(buf)
	if err != nil {
		return fmt.Errorf("failed to parse keybag: %w", err)
	}

	// Verify object type is container keybag
	if keybag.MkObj.GetObjectType() != ObjectTypeContainerKeybag {
		return fmt.Errorf("invalid object type for keybag: %d", keybag.MkObj.GetObjectType())
	}

	cm.keybag = keybag
	return nil
}

// readPhysicalObject reads an object at a specific physical address
func (cm *ContainerManager) readPhysicalObject(addr uint64) ([]byte, error) {
	// Validate the address
	if addr == 0 || addr >= cm.superblock.BlockCount {
		return nil, ErrInvalidBlockAddress
	}

	// Calculate the offset
	offset := int64(addr) * int64(cm.blockSize)

	// Read one block initially to get the object header
	buf := make([]byte, cm.blockSize)
	_, err := cm.device.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to object at address %d: %w", addr, err)
	}

	_, err = io.ReadFull(cm.device, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read object header: %w", err)
	}

	// Parse the object header
	obj := &ObjectPhys{}
	err = obj.Parse(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse object header: %w", err)
	}

	// Verify the checksum
	if !cm.verifyChecksum(buf, obj.Checksum[:]) {
		return nil, fmt.Errorf("invalid checksum for object at address %d", addr)
	}

	return buf, nil
}

// resolveObject resolves an object by its ID and transaction ID
func (cm *ContainerManager) resolveObject(oid uint64, xid uint64) ([]byte, error) {
	// Check if it's an ephemeral object
	if data, ok := cm.ephemeralObjs[oid]; ok {
		return data, nil
	}

	// Check if it's a physical object (object ID is the physical address)
	if oid < cm.superblock.BlockCount {
		return cm.readPhysicalObject(oid)
	}

	// Must be a virtual object, lookup in the object map
	if cm.omap == nil {
		return nil, fmt.Errorf("container object map not loaded")
	}

	// Create a key for the object map
	key := OMapKey{
		OkOID: oid,
		OkXID: xid,
	}

	// Convert key to bytes
	keyBytes, err := key.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize object map key: %w", err)
	}

	// Load the B-tree
	btreeOID := cm.omap.OmTreeOID
	btreeData, err := cm.resolveObject(btreeOID, xid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve B-tree: %w", err)
	}

	// Create the B-tree
	btree, err := NewBTree(cm, btreeData)
	if err != nil {
		return nil, fmt.Errorf("failed to create B-tree: %w", err)
	}

	// Search for the key
	valueBytes, err := btree.Search(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("object not found in object map: %w", err)
	}

	// Parse the value
	val := OMapVal{}
	err = val.Parse(valueBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse object map value: %w", err)
	}

	// Check if the object is deleted
	if val.OvFlags&OmapValDeleted != 0 {
		return nil, fmt.Errorf("object has been deleted")
	}

	// Read the physical object
	return cm.readPhysicalObject(val.OvPaddr)
}

// verifyChecksum verifies the Fletcher 64 checksum of an object
func (cm *ContainerManager) verifyChecksum(data []byte, checksum []byte) bool {
	// Skip the checksum field when computing the checksum
	// The checksum is stored in the first MAX_CKSUM_SIZE bytes
	computed := fletcher64Checksum(data, MaxChecksumSize)
	return bytes.Equal(computed, checksum)
}

// GetVolume returns a volume manager for the volume with the specified index
func (cm *ContainerManager) GetVolume(index uint32) (*VolumeManager, error) {
	// Check if index is valid
	if index >= cm.superblock.MaxFileSystems || index >= NXMaxFileSystems {
		return nil, fmt.Errorf("invalid volume index: %d", index)
	}

	// Get the volume OID
	volOID := cm.superblock.FSOID[index]
	if volOID == 0 {
		return nil, fmt.Errorf("no volume at index %d", index)
	}

	// Create the volume manager
	vm := &VolumeManager{
		container: cm,
		index:     index,
	}

	// Resolve the volume superblock
	sbData, err := cm.resolveObject(volOID, cm.checkpoint.XID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve volume superblock: %w", err)
	}

	// Parse the volume superblock
	sb := &APFSSuperblock{}
	err = sb.Parse(sbData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse volume superblock: %w", err)
	}

	// Verify the magic number
	if !sb.IsValid() {
		return nil, ErrInvalidMagic
	}

	vm.superblock = sb

	// Mount the volume
	err = vm.Mount()
	if err != nil {
		return nil, fmt.Errorf("failed to mount volume: %w", err)
	}

	return vm, nil
}

// ListVolumes returns information about all volumes in the container
func (cm *ContainerManager) ListVolumes() ([]VolumeInfo, error) {
	var volumes []VolumeInfo

	// Iterate through the volume OIDs
	for i := uint32(0); i < cm.superblock.MaxFileSystems && i < NXMaxFileSystems; i++ {
		volOID := cm.superblock.FSOID[i]
		if volOID == 0 {
			continue
		}

		// Resolve the volume superblock
		sbData, err := cm.resolveObject(volOID, cm.checkpoint.XID)
		if err != nil {
			continue
		}

		// Parse the volume superblock
		sb := &APFSSuperblock{}
		err = sb.Parse(sbData)
		if err != nil {
			continue
		}

		// Skip invalid volumes
		if !sb.IsValid() {
			continue
		}

		// Create volume info
		info := VolumeInfo{
			Index:         i,
			Name:          string(bytes.Trim(sb.VolName[:], "\x00")),
			UUID:          sb.VolUUID,
			Role:          sb.Role,
			Capacity:      cm.blockSize * cm.superblock.BlockCount,
			Used:          cm.blockSize * sb.FSAllocCount,
			Available:     cm.blockSize * (cm.superblock.BlockCount - sb.FSAllocCount),
			CreateTime:    time.Unix(0, int64(sb.CreateTime)),
			ModTime:       time.Unix(0, int64(sb.LastModTime)),
			Encrypted:     (sb.FSFlags & APFSFSUnencrypted) == 0,
			CaseSensitive: (sb.IncompatFeatures & APFSIncompatCaseInsensitive) == 0,
		}

		volumes = append(volumes, info)
	}

	return volumes, nil
}
