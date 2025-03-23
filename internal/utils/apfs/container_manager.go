//
package apfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Common error definitions
var (
	ErrInvalidChecksum     = errors.New("invalid checksum")
	ErrInvalidMagic        = errors.New("invalid magic number")
	ErrInvalidBlockSize    = errors.New("invalid block size")
	ErrUnsupportedVersion  = errors.New("unsupported APFS version")
	ErrInvalidBlockAddress = errors.New("invalid block address")
	ErrNoValidCheckpoint   = errors.New("no valid checkpoint found")
)

// ContainerManager provides access to an APFS container
type ContainerManager struct {
	device        io.ReadWriteSeeker
	blockSize     uint32
	superblock    *NXSuperblock
	checkpoint    *CheckpointInfo
	omap          *ObjectMap
	ephemeralObjs map[uint64][]byte // Cache for ephemeral objects
}

// CheckpointInfo represents a container checkpoint
type CheckpointInfo struct {
	Superblock         *NXSuperblock
	CheckpointMapBlocks []*CheckPointMappingBlock
	XID                uint64
}

// ObjectMap provides access to the container's object map
type ObjectMap struct {
	physicalObj *OMapPhys
	btree       *BTree
}

// NewContainerManager creates a new container manager from a device
func NewContainerManager(device io.ReadWriteSeeker) (*ContainerManager, error) {
	cm := &ContainerManager{
		device:        device,
		ephemeralObjs: make(map[uint64][]byte),
	}

	// Read container superblock from block 0
	err := cm.readSuperblockFromBlockZero()
	if err != nil {
		return nil, fmt.Errorf("failed to read superblock: %w", err)
	}

	// Locate and read the latest valid checkpoint
	checkpoint, err := cm.findLatestCheckpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to find valid checkpoint: %w", err)
	}
	cm.checkpoint = checkpoint
	
	// Use the checkpoint's superblock as the definitive one
	cm.superblock = checkpoint.Superblock
	cm.blockSize = checkpoint.Superblock.BlockSize

	// Load ephemeral objects from checkpoint
	err = cm.loadEphemeralObjects()
	if err != nil {
		return nil, fmt.Errorf("failed to load ephemeral objects: %w", err)
	}

	// Initialize the container's object map
	err = cm.initObjectMap()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize object map: %w", err)
	}

	return cm, nil
}

// readSuperblockFromBlockZero reads the superblock from block 0
func (cm *ContainerManager) readSuperblockFromBlockZero() error {
	blockData := make([]byte, DefaultBlockSize)
	
	// Read block 0
	_, err := cm.device.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	
	_, err = io.ReadFull(cm.device, blockData)
	if err != nil {
		return err
	}
	
	// Parse the superblock
	sb := &NXSuperblock{}
	err = sb.Parse(blockData)
	if err != nil {
		return err
	}
	
	// Verify checksum
	if !verifyChecksum(blockData[:], sb.NXO.Checksum[:]) {
		return ErrInvalidChecksum
	}
	
	// Set initial block size
	cm.blockSize = sb.BlockSize
	cm.superblock = sb
	
	return nil
}

// findLatestCheckpoint locates the most recent valid checkpoint
func (cm *ContainerManager) findLatestCheckpoint() (*CheckpointInfo, error) {
	sb := cm.superblock
	
	// Calculate the range of the checkpoint descriptor area
	descStart := int64(sb.XPDescBase)
	descBlocks := int(sb.XPDescBlocks & 0x7FFFFFFF) // Mask out the high bit that's used as a flag
	
	// Read through the checkpoint descriptors to find valid checkpoints
	var validCheckpoints []*CheckpointInfo
	
	for i := 0; i < descBlocks; i++ {
		offset := descStart + int64(i) * int64(cm.blockSize)
		block := make([]byte, cm.blockSize)
		
		_, err := cm.device.Seek(offset, io.SeekStart)
		if err != nil {
			return nil, err
		}
		
		_, err = io.ReadFull(cm.device, block)
		if err != nil {
			return nil, err
		}
		
		// Check if this block contains a checkpoint map or a superblock
		obj := ObjectPhys{}
		if err := binary.Read(bytes.NewReader(block), binary.LittleEndian, &obj); err != nil {
			continue // Skip blocks we can't parse
		}
		
		// Check object type
		objType := obj.GetObjectType()
		
		if objType == ObjectTypeNXSuperblock {
			// This block contains a superblock
			checkpoint, err := cm.processCheckpointSuperblock(block, obj.XID)
			if err == nil {
				validCheckpoints = append(validCheckpoints, checkpoint)
			}
		} else if objType == ObjectTypeCheckpointMap {
			// This is a checkpoint mapping block, will be processed with its superblock
			continue
		}
	}
	
	if len(validCheckpoints) == 0 {
		return nil, ErrNoValidCheckpoint
	}
	
	// Find the checkpoint with the highest XID
	latestCheckpoint := validCheckpoints[0]
	for _, cp := range validCheckpoints[1:] {
		if cp.XID > latestCheckpoint.XID {
			latestCheckpoint = cp
		}
	}
	
	return latestCheckpoint, nil
}

// processCheckpointSuperblock processes a superblock found in the checkpoint area
func (cm *ContainerManager) processCheckpointSuperblock(block []byte, xid uint64) (*CheckpointInfo, error) {
	// Parse the superblock
	sb := &NXSuperblock{}
	err := sb.Parse(block)
	if err != nil {
		return nil, err
	}
	
	// Verify checksum
	if !verifyChecksum(block, sb.NXO.Checksum[:]) {
		return nil, ErrInvalidChecksum
	}
	
	// Check that this is a supported version
	if (sb.IncompatFeatures & NX_INCOMPAT_VERSION2) == 0 {
		return nil, ErrUnsupportedVersion
	}
	
	// Create checkpoint info
	checkpoint := &CheckpointInfo{
		Superblock: sb,
		XID:        xid,
	}
	
	// Collect the checkpoint map blocks that belong to this superblock
	err = cm.collectCheckpointMapBlocks(checkpoint)
	if err != nil {
		return nil, err
	}
	
	return checkpoint, nil
}

// collectCheckpointMapBlocks finds all checkpoint mapping blocks for a superblock
func (cm *ContainerManager) collectCheckpointMapBlocks(checkpoint *CheckpointInfo) error {
	sb := checkpoint.Superblock
	
	// Calculate the range of the checkpoint descriptor area
	descStart := int64(sb.XPDescBase)
	descIndex := int(sb.XPDescIndex)
	descLen := int(sb.XPDescLen)
	
	// Read the checkpoint map blocks
	for i := 0; i < descLen; i++ {
		// Calculate the block's position, handling wrap-around in the circular buffer
		index := (descIndex + i) % int(sb.XPDescBlocks & 0x7FFFFFFF)
		offset := descStart + int64(index) * int64(cm.blockSize)
		
		block := make([]byte, cm.blockSize)
		_, err := cm.device.Seek(offset, io.SeekStart)
		if err != nil {
			return err
		}
		
		_, err = io.ReadFull(cm.device, block)
		if err != nil {
			return err
		}
		
		// Check if this is a checkpoint map block
		obj := ObjectPhys{}
		if err := binary.Read(bytes.NewReader(block), binary.LittleEndian, &obj); err != nil {
			continue
		}
		
		if obj.GetObjectType() != ObjectTypeCheckpointMap {
			continue
		}
		
		// Parse the checkpoint map block
		cpm := &CheckPointMappingBlock{}
		if err := cm.parseCheckpointMapBlock(block, cpm); err != nil {
			continue
		}
		
		checkpoint.CheckpointMapBlocks = append(checkpoint.CheckpointMapBlocks, cpm)
		
		// If this is the last mapping block in the checkpoint, we're done
		if (cpm.CpmFlags & CHECKPOINT_MAP_LAST) != 0 {
			break
		}
	}
	
	return nil
}

// parseCheckpointMapBlock parses a checkpoint mapping block
func (cm *ContainerManager) parseCheckpointMapBlock(block []byte, cpm *CheckPointMappingBlock) error {
	// Parse the header
	reader := bytes.NewReader(block)
	if err := binary.Read(reader, binary.LittleEndian, &cpm.CpmO); err != nil {
		return err
	}
	
	// Verify checksum
	if !verifyChecksum(block, cpm.CpmO.Checksum[:]) {
		return ErrInvalidChecksum
	}
	
	// Read flags and count
	if err := binary.Read(reader, binary.LittleEndian, &cpm.CpmFlags); err != nil {
		return err
	}
	
	if err := binary.Read(reader, binary.LittleEndian, &cpm.CpmCount); err != nil {
		return err
	}
	
	// Read mapping entries
	cpm.CpmMap = make([]CheckPointMapping, cpm.CpmCount)
	for i := uint32(0); i < cpm.CpmCount; i++ {
		if err := binary.Read(reader, binary.LittleEndian, &cpm.CpmMap[i]); err != nil {
			return err
		}
	}
	
	return nil
}

// loadEphemeralObjects loads ephemeral objects from the checkpoint
func (cm *ContainerManager) loadEphemeralObjects() error {
	checkpoint := cm.checkpoint
	sb := checkpoint.Superblock
	
	// For each checkpoint mapping block
	for _, cpmBlock := range checkpoint.CheckpointMapBlocks {
		// For each mapping entry
		for _, mapping := range cpmBlock.CpmMap {
			// Only process ephemeral objects
			if (mapping.CpmType & ObjStorageTypeMask) != ObjEphemeral {
				continue
			}
			
			// Read the ephemeral object from the checkpoint data area
			dataOffset := int64(sb.XPDataBase) + int64(mapping.CpmPaddr) * int64(cm.blockSize)
			objData := make([]byte, mapping.CpmSize)
			
			_, err := cm.device.Seek(dataOffset, io.SeekStart)
			if err != nil {
				return err
			}
			
			_, err = io.ReadFull(cm.device, objData)
			if err != nil {
				return err
			}
			
			// Cache the ephemeral object
			cm.ephemeralObjs[mapping.CpmOID] = objData
		}
	}
	
	return nil
}

// initObjectMap initializes the container's object map
func (cm *ContainerManager) initObjectMap() error {
	// Get the object map's OID from the superblock
	omapOID := cm.superblock.OMapOID
	
	// Read the object map
	omapBlock, err := cm.readPhysicalObject(omapOID)
	if err != nil {
		return err
	}
	
	// Parse the object map
	omap := &OMapPhys{}
	if err := parseObjectFromBytes(omapBlock, omap); err != nil {
		return err
	}
	
	// Create an object map structure
	cm.omap = &ObjectMap{
		physicalObj: omap,
	}
	
	// Initialize the B-tree
	btreeObj, err := cm.resolveObject(omap.OmTreeOID, cm.checkpoint.XID)
	if err != nil {
		return err
	}
	
	cm.omap.btree = NewBTree(btreeObj)
	
	return nil
}

// GetVolumes returns all volumes in the container
func (cm *ContainerManager) GetVolumes() ([]*VolumeManager, error) {
	var volumes []*VolumeManager
	
	// Get volume count from superblock
	fsCount := 0
	for i := 0; i < int(cm.superblock.MaxFileSystems); i++ {
		if cm.superblock.FSOID[i] != 0 {
			fsCount++
		} else {
			break
		}
	}
	
	// Process each volume
	for i := 0; i < fsCount; i++ {
		volumeOID := cm.superblock.FSOID[i]
		if volumeOID == 0 {
			continue
		}
		
		// Resolve the volume's superblock
		volSuperblockObj, err := cm.resolveObject(volumeOID, cm.checkpoint.XID)
		if err != nil {
			continue
		}
		
		// Create a volume manager
		vm, err := NewVolumeManager(cm, volSuperblockObj, i)
		if err != nil {
			continue
		}
		
		volumes = append(volumes, vm)
	}
	
	return volumes, nil
}

// GetVolumeByRole returns a volume with the specified role
func (cm *ContainerManager) GetVolumeByRole(role uint16) (*VolumeManager, error) {
	volumes, err := cm.GetVolumes()
	if err != nil {
		return nil, err
	}
	
	for _, vol := range volumes {
		if vol.superblock.Role == role {
			return vol, nil
		}
	}
	
	return nil, fmt.Errorf("volume with role %d not found", role)
}

// resolveObject resolves a virtual object to its physical location
func (cm *ContainerManager) resolveObject(oid uint64, xid uint64) ([]byte, error) {
	// Check if this is a physical object (the OID is a block address)
	if oid < OIDReservedCount {
		// Special case for superblock
		if oid == OIDNXSuperblock {
			return nil, fmt.Errorf("container superblock must be accessed directly")
		}
		
		// This is a physical object
		return cm.readPhysicalObject(oid)
	}
	
	// Check if this is an ephemeral object
	if data, ok := cm.ephemeralObjs[oid]; ok {
		return data, nil
	}
	
	// This is a virtual object, resolve using the object map
	return cm.resolveVirtualObject(oid, xid)
}

// resolveVirtualObject resolves a virtual object using the object map
func (cm *ContainerManager) resolveVirtualObject(oid uint64, xid uint64) ([]byte, error) {
	// Create a key for the object map lookup
	key := OMapKey{
		OkOID: oid,
		OkXID: xid,
	}
	
	// Convert key to bytes
	keyBytes, err := binary.Marshal(binary.LittleEndian, key)
	if err != nil {
		return nil, err
	}
	
	// Search for the key in the object map's B-tree
	valueBytes, err := cm.omap.btree.Search(keyBytes)
	if err != nil {
		return nil, err
	}
	
	// Parse the value
	val := OMapVal{}
	if err := binary.Unmarshal(valueBytes, binary.LittleEndian, &val); err != nil {
		return nil, err
	}
	
	// Check if the object is deleted
	if (val.OvFlags & OMAP_VAL_DELETED) != 0 {
		return nil, fmt.Errorf("object has been deleted")
	}
	
	// Read the physical object
	return cm.readPhysicalObject(val.OvPaddr)
}

// readPhysicalObject reads a physical object from disk
func (cm *ContainerManager) readPhysicalObject(paddr uint64) ([]byte, error) {
	// Calculate the offset
	offset := int64(paddr) * int64(cm.blockSize)
	
	// Read the block
	block := make([]byte, cm.blockSize)
	_, err := cm.device.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, err
	}
	
	_, err = io.ReadFull(cm.device, block)
	if err != nil {
		return nil, err
	}
	
	// Verify the checksum
	obj := ObjectPhys{}
	if err := binary.Read(bytes.NewReader(block), binary.LittleEndian, &obj); err != nil {
		return nil, err
	}
	
	if !verifyChecksum(block, obj.Checksum[:]) {
		return nil, ErrInvalidChecksum
	}
	
	return block, nil
}

// verifyChecksum verifies the Fletcher 64 checksum of an object
func verifyChecksum(data []byte, expectedChecksum []byte) bool {
	// Fletcher 64 checksum calculation
	computed := fletcher64Checksum(data)
	
	// Compare with expected checksum
	for i := 0; i < MaxChecksumSize; i++ {
		if computed[i] != expectedChecksum[i] {
			return false
		}
	}
	
	return true
}

// fletcher64Checksum calculates a Fletcher 64 checksum
func fletcher64Checksum(data []byte) [MaxChecksumSize]byte {
	// Zero out the checksum field in the data for calculation
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	
	for i := 0; i < MaxChecksumSize; i++ {
		dataCopy[i] = 0
	}
	
	// Fletcher 64 algorithm
	// Implementation based on the APFS specification
	sum1 := uint32(0)
	sum2 := uint32(0)
	
	// Process data in 4-byte chunks
	for i := 0; i < len(dataCopy); i += 4 {
		if i+4 <= len(dataCopy) {
			word := binary.LittleEndian.Uint32(dataCopy[i:])
			sum1 = (sum1 + word) % 0xFFFFFFFF
			sum2 = (sum2 + sum1) % 0xFFFFFFFF
		}
	}
	
	// Combine the sums into the checksum
	var checksum [MaxChecksumSize]byte
	binary.LittleEndian.PutUint32(checksum[0:], sum1)
	binary.LittleEndian.PutUint32(checksum[4:], sum2)
	
	return checksum
}

// parseObjectFromBytes parses an object from a byte array
func parseObjectFromBytes(data []byte, obj interface{}) error {
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, obj)
}

// NewBTree creates a new B-tree from block data
func NewBTree(block []byte) *BTree {
	// This is just a stub - in a real implementation, 
	// you would parse the B-tree node and initialize the tree structure
	return &BTree{}
}

// BTree represents an APFS B-tree
type BTree struct {
	// Add necessary fields
}

// Search searches the B-tree for a key
func (bt *BTree) Search(key []byte) ([]byte, error) {
	// This is just a stub - in a real implementation,
	// you would traverse the tree to find the key
	return nil, errors.New("not implemented")
}

// VolumeManager provides access to an APFS volume
type VolumeManager struct {
	container  *ContainerManager
	superblock *APFSSuperblock
	index      int
	// Add other fields as needed
}

// NewVolumeManager creates a new volume manager
func NewVolumeManager(container *ContainerManager, blockData []byte, index int) (*VolumeManager, error) {
	// Parse the volume superblock
	superblock := &APFSSuperblock{}
	if err := parseObjectFromBytes(blockData, superblock); err != nil {
		return nil, err
	}
	
	// Verify magic number
	if superblock.Magic != APFSMagic {
		return nil, ErrInvalidMagic
	}
	
	// Create the volume manager
	vm := &VolumeManager{
		container:  container,
		superblock: superblock,
		index:      index,
	}
	
	return vm, nil
}

// GetName returns the volume name
func (vm *VolumeManager) GetName() string {
	// Convert null-terminated byte array to string
	nameBytes := vm.superblock.VolName[:]
	for i, b := range nameBytes {
		if b == 0 {
			return string(nameBytes[:i])
		}
	}
	return string(nameBytes)
}

// GetUUID returns the volume UUID
func (vm *VolumeManager) GetUUID() [16]byte {
	return vm.superblock.VolUUID
}

// GetRole returns the volume role
func (vm *VolumeManager) GetRole() uint16 {
	return vm.superblock.Role
}

// IsEncrypted returns true if the volume is encrypted
func (vm *VolumeManager) IsEncrypted() bool {
	return (vm.superblock.FSFlags & APFSFSUnencrypted) == 0
}

// Mount prepares the volume for access
func (vm *VolumeManager) Mount() error {
	// Implement mounting logic (initialize object map, root tree, etc.)
	return errors.New("not implemented")
}
