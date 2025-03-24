// snapsnot.go
package apfs

import (
	"encoding/binary"
	"errors"
	"time"
)

// Additional error definitions for snapshot operations
var (
	ErrSnapshotExists      = errors.New("snapshot already exists")
	ErrSnapshotNotFound    = errors.New("snapshot not found")
	ErrTooManySnapshots    = errors.New("too many snapshots")
	ErrInvalidSnapshotName = errors.New("invalid snapshot name")
)

// Snapshot represents an APFS snapshot
type Snapshot struct {
	volume        *VolumeManager
	xid           uint64
	name          string
	createTime    time.Time
	extentrefTree uint64
	sblockOID     uint64
	metadata      *JSnapMetadataVal
}

// SnapshotInfo provides information about a snapshot
type SnapshotInfo struct {
	Name       string
	XID        uint64
	CreateTime time.Time
	Size       int64 // Estimated size in bytes
}

// SnapshotOp represents a snapshot creation operation
type SnapshotOp struct {
	tx           *Transaction
	volume       *VolumeManager
	name         string
	snapXID      uint64
	extentrefOID uint64
	sblockOID    uint64
}

// DeleteSnapshotOp represents a snapshot deletion operation
type DeleteSnapshotOp struct {
	tx          *Transaction
	volume      *VolumeManager
	snapshot    *Snapshot
	metadataKey []byte
	metadataVal []byte
	nameKey     []byte
	nameVal     []byte
}

// MountSnapshotOp represents a snapshot mount operation
type MountSnapshotOp struct {
	tx         *Transaction
	volume     *VolumeManager
	snapshot   *Snapshot
	oldRootXID uint64
}

// CreateSnapshot creates a new snapshot of the volume
func (vm *VolumeManager) CreateSnapshot(tx *Transaction, name string) (*Snapshot, error) {
	// Check if snapshot already exists
	exists, _ := vm.SnapshotExists(name)
	if exists {
		return nil, ErrSnapshotExists
	}

	// Check if snapshot limit reached
	if vm.superblock.NumSnapshots >= OMAP_MAX_SNAP_COUNT {
		return nil, ErrTooManySnapshots
	}

	// Validate name
	if name == "" || len(name) > 255 {
		return nil, ErrInvalidSnapshotName
	}

	// Create the operation
	op := &SnapshotOp{
		tx:      tx,
		volume:  vm,
		name:    name,
		snapXID: tx.xid,
	}

	// Add to transaction
	tx.operations = append(tx.operations, op)

	// Return a placeholder snapshot object
	snapshot := &Snapshot{
		volume:     vm,
		xid:        tx.xid,
		name:       name,
		createTime: time.Now(),
	}

	return snapshot, nil
}

// Execute executes a snapshot creation operation
func (op *SnapshotOp) Execute() error {
	vm := op.volume

	// In a full implementation, this would:
	// 1. Create a copy of the current root tree
	// 2. Move the current extent reference tree to the snapshot
	// 3. Create a new extent reference tree for the volume
	// 4. Create snapshot metadata and name records
	// 5. Update volume snapshot count

	// Store the current extent reference tree OID
	op.extentrefOID = vm.superblock.ExtentrefTreeOID

	// Store the current volume superblock OID
	op.sblockOID = uint64(vm.index) // In a real implementation, we'd get the physical OID

	// Create a new extent reference tree
	// In a real implementation, this would actually create the tree
	newExtentrefTreeOID := vm.superblock.NextObjID
	vm.superblock.NextObjID++
	vm.superblock.ExtentrefTreeOID = newExtentrefTreeOID

	// Create snapshot metadata
	now := time.Now().UnixNano()
	metadata := &JSnapMetadataVal{
		ExtentrefTreeOID:  op.extentrefOID,
		SblockOID:         op.sblockOID,
		CreateTime:        uint64(now),
		ChangeTime:        uint64(now),
		Inum:              SNAP_DIR_INO_NUM, // Snapshots are stored as files in the snapshot directory
		ExtentrefTreeType: vm.superblock.ExtentrefTreeType,
		Flags:             0,
		NameLen:           uint16(len(op.name) + 1), // Include null terminator
	}

	// Create metadata key
	metadataKey := JKey{
		ObjIDAndType: (uint64(op.snapXID) & ObjIDMask) | (APFSTypeSnapMetadata << ObjTypeShift),
	}

	// Serialize key and value
	metadataKeyBytes, _ := binary.Marshal(binary.LittleEndian, metadataKey)
	metadataValBytes, _ := binary.Marshal(binary.LittleEndian, metadata)
	metadataValBytes = append(metadataValBytes, []byte(op.name+"\x00")...)

	// In a full implementation, this would insert into the B-tree

	// Create snapshot name record
	nameVal := &JSnapNameVal{
		SnapXID: op.snapXID,
	}

	// Create name key
	nameKey := &JSnapNameKey{
		Hdr: JKey{
			ObjIDAndType: (~uint64(0) & ObjIDMask) | (APFSTypeSnapName << ObjTypeShift),
		},
		NameLen: uint16(len(op.name) + 1), // Include null terminator
	}

	// Serialize key and value
	nameKeyBytes, _ := binary.Marshal(binary.LittleEndian, nameKey)
	nameKeyBytes = append(nameKeyBytes, []byte(op.name+"\x00")...)
	nameValBytes, _ := binary.Marshal(binary.LittleEndian, nameVal)

	// In a full implementation, this would insert into the B-tree

	// Update object map snapshot list
	// In a full implementation, this would update the object map's snapshot tree

	// Update volume snapshot count
	vm.superblock.NumSnapshots++

	return nil
}

// Revert reverts a snapshot creation operation
func (op *SnapshotOp) Revert() error {
	vm := op.volume

	// Restore the original extent reference tree
	if op.extentrefOID != 0 {
		vm.superblock.ExtentrefTreeOID = op.extentrefOID
	}

	// Decrement volume snapshot count
	vm.superblock.NumSnapshots--

	// Restore the Next OID counter
	vm.superblock.NextObjID--

	return nil
}

// DeleteSnapshot deletes a snapshot
func (vm *VolumeManager) DeleteSnapshot(tx *Transaction, name string) error {
	// Find the snapshot
	snapshot, err := vm.GetSnapshotByName(name)
	if err != nil {
		return err
	}

	// Create the operation
	op := &DeleteSnapshotOp{
		tx:       tx,
		volume:   vm,
		snapshot: snapshot,
	}

	// Add to transaction
	tx.operations = append(tx.operations, op)

	return nil
}

// Execute executes a snapshot deletion operation
func (op *DeleteSnapshotOp) Execute() error {
	vm := op.volume
	snapshot := op.snapshot

	// In a full implementation, this would:
	// 1. Mark snapshot as deleted in the object map
	// 2. Remove snapshot metadata and name records
	// 3. Queue the snapshot's objects for deletion by the reaper
	// 4. Update volume snapshot count

	// Create snapshot deletion marker in the object map
	// In a full implementation, this would update the object map's snapshot tree

	// Decrement volume snapshot count
	vm.superblock.NumSnapshots--

	return nil
}

// Revert reverts a snapshot deletion operation
func (op *DeleteSnapshotOp) Revert() error {
	vm := op.volume

	// In a full implementation, this would:
	// 1. Remove the deletion marker from the object map
	// 2. Restore snapshot metadata and name records
	// 3. Remove objects from the reaper queue

	// Increment volume snapshot count
	vm.superblock.NumSnapshots++

	return nil
}

// MountSnapshot mounts a snapshot for browsing
func (vm *VolumeManager) MountSnapshot(tx *Transaction, name string) error {
	// Find the snapshot
	snapshot, err := vm.GetSnapshotByName(name)
	if err != nil {
		return err
	}

	// Create the operation
	op := &MountSnapshotOp{
		tx:         tx,
		volume:     vm,
		snapshot:   snapshot,
		oldRootXID: vm.superblock.RootToXID,
	}

	// Add to transaction
	tx.operations = append(tx.operations, op)

	return nil
}

// Execute executes a snapshot mount operation
func (op *MountSnapshotOp) Execute() error {
	vm := op.volume
	snapshot := op.snapshot

	// Set the root to XID in the volume superblock
	vm.superblock.RootToXID = snapshot.xid

	// In a full implementation, this would reinitialize the file system tree

	return nil
}

// Revert reverts a snapshot mount operation
func (op *MountSnapshotOp) Revert() error {
	vm := op.volume

	// Restore the original root to XID
	vm.superblock.RootToXID = op.oldRootXID

	// In a full implementation, this would reinitialize the file system tree

	return nil
}

// UnmountSnapshot unmounts a mounted snapshot
func (vm *VolumeManager) UnmountSnapshot(tx *Transaction) error {
	// Check if a snapshot is mounted
	if vm.superblock.RootToXID == 0 {
		return errors.New("no snapshot is mounted")
	}

	// Create the operation (simplified version of MountSnapshotOp)
	op := &MountSnapshotOp{
		tx:         tx,
		volume:     vm,
		oldRootXID: vm.superblock.RootToXID,
	}

	// Add to transaction
	tx.operations = append(tx.operations, op)

	return nil
}

// Execute for unmounting sets RootToXID to 0
func (op *MountSnapshotOp) Execute() error {
	vm := op.volume

	// Clear the root to XID in the volume superblock
	vm.superblock.RootToXID = 0

	// In a full implementation, this would reinitialize the file system tree

	return nil
}

// GetSnapshots returns a list of all snapshots
func (vm *VolumeManager) GetSnapshots() ([]*SnapshotInfo, error) {
	var snapshots []*SnapshotInfo

	// Prepare a key for range iteration
	startKey := JKey{
		ObjIDAndType: (0 & ObjIDMask) | (APFSTypeSnapMetadata << ObjTypeShift),
	}
	endKey := JKey{
		ObjIDAndType: (^uint64(0) & ObjIDMask) | (APFSTypeSnapMetadata << ObjTypeShift),
	}

	// Convert keys to bytes
	startKeyBytes, _ := binary.Marshal(binary.LittleEndian, startKey)
	endKeyBytes, _ := binary.Marshal(binary.LittleEndian, endKey)

	// Iterate through snapshot metadata
	vm.fsTree.IterateRange(startKeyBytes, endKeyBytes, func(key, value []byte) bool {
		// Parse the metadata key
		metadataKey := JKey{}
		if err := binary.Unmarshal(key, binary.LittleEndian, &metadataKey); err != nil {
			return true
		}

		// Extract XID from key
		xid := metadataKey.ObjIDAndType & ObjIDMask

		// Parse the metadata value
		metadata := &JSnapMetadataVal{}
		if err := binary.Unmarshal(value, binary.LittleEndian, metadata); err != nil {
			return true
		}

		// Extract the name
		nameOffset := binary.Size(JSnapMetadataVal{})
		nameLen := int(metadata.NameLen)
		if nameOffset+nameLen > len(value) {
			return true
		}
		name := string(value[nameOffset : nameOffset+nameLen-1]) // Remove null terminator

		// Create snapshot info
		info := &SnapshotInfo{
			Name:       name,
			XID:        xid,
			CreateTime: time.Unix(0, int64(metadata.CreateTime)),
			Size:       0, // In a full implementation, calculate from extents
		}

		snapshots = append(snapshots, info)
		return true
	})

	return snapshots, nil
}

// GetSnapshotByName finds a snapshot by name
func (vm *VolumeManager) GetSnapshotByName(name string) (*Snapshot, error) {
	// Prepare a key for the snapshot name
	nameKey := &JSnapNameKey{
		Hdr: JKey{
			ObjIDAndType: (~uint64(0) & ObjIDMask) | (APFSTypeSnapName << ObjTypeShift),
		},
		NameLen: uint16(len(name) + 1), // Include null terminator
	}

	// Serialize key
	nameKeyBytes, _ := binary.Marshal(binary.LittleEndian, nameKey)
	nameKeyBytes = append(nameKeyBytes, []byte(name+"\x00")...)

	// Search for the key
	valueBytes, err := vm.fsTree.Search(nameKeyBytes)
	if err != nil {
		return nil, ErrSnapshotNotFound
	}

	// Parse the value
	nameVal := &JSnapNameVal{}
	if err := binary.Unmarshal(valueBytes, binary.LittleEndian, nameVal); err != nil {
		return nil, err
	}

	// Get the snapshot XID
	snapXID := nameVal.SnapXID

	// Find the snapshot metadata
	metadataKey := JKey{
		ObjIDAndType: (snapXID & ObjIDMask) | (APFSTypeSnapMetadata << ObjTypeShift),
	}

	// Serialize key
	metadataKeyBytes, _ := binary.Marshal(binary.LittleEndian, metadataKey)

	// Search for the key
	metadataBytes, err := vm.fsTree.Search(metadataKeyBytes)
	if err != nil {
		return nil, err
	}

	// Parse the metadata
	metadata := &JSnapMetadataVal{}
	if err := binary.Unmarshal(metadataBytes, binary.LittleEndian, metadata); err != nil {
		return nil, err
	}

	// Create the snapshot object
	snapshot := &Snapshot{
		volume:        vm,
		xid:           snapXID,
		name:          name,
		createTime:    time.Unix(0, int64(metadata.CreateTime)),
		extentrefTree: metadata.ExtentrefTreeOID,
		sblockOID:     metadata.SblockOID,
		metadata:      metadata,
	}

	return snapshot, nil
}

// GetSnapshotByXID finds a snapshot by transaction ID
func (vm *VolumeManager) GetSnapshotByXID(xid uint64) (*Snapshot, error) {
	// Prepare a key for the snapshot metadata
	metadataKey := JKey{
		ObjIDAndType: (xid & ObjIDMask) | (APFSTypeSnapMetadata << ObjTypeShift),
	}

	// Serialize key
	metadataKeyBytes, _ := binary.Marshal(binary.LittleEndian, metadataKey)

	// Search for the key
	metadataBytes, err := vm.fsTree.Search(metadataKeyBytes)
	if err != nil {
		return nil, ErrSnapshotNotFound
	}

	// Parse the metadata
	metadata := &JSnapMetadataVal{}
	if err := binary.Unmarshal(metadataBytes, binary.LittleEndian, metadata); err != nil {
		return nil, err
	}

	// Extract the name
	nameOffset := binary.Size(JSnapMetadataVal{})
	nameLen := int(metadata.NameLen)
	if nameOffset+nameLen > len(metadataBytes) {
		return nil, errors.New("invalid metadata format")
	}
	name := string(metadataBytes[nameOffset : nameOffset+nameLen-1]) // Remove null terminator

	// Create the snapshot object
	snapshot := &Snapshot{
		volume:        vm,
		xid:           xid,
		name:          name,
		createTime:    time.Unix(0, int64(metadata.CreateTime)),
		extentrefTree: metadata.ExtentrefTreeOID,
		sblockOID:     metadata.SblockOID,
		metadata:      metadata,
	}

	return snapshot, nil
}

// SnapshotExists checks if a snapshot with the given name exists
func (vm *VolumeManager) SnapshotExists(name string) (bool, error) {
	_, err := vm.GetSnapshotByName(name)
	if err == nil {
		return true, nil
	}
	if err == ErrSnapshotNotFound {
		return false, nil
	}
	return false, err
}

// RevertToSnapshot reverts the volume to a snapshot state
func (vm *VolumeManager) RevertToSnapshot(tx *Transaction, name string) error {
	// Find the snapshot
	snapshot, err := vm.GetSnapshotByName(name)
	if err != nil {
		return err
	}

	// In a real implementation, this would:
	// 1. Set the revert_to_xid field in the volume superblock
	// 2. Create a snapshot of the current state for recovery
	// 3. Mark all snapshots after the target for deletion
	// The actual reversion happens during mount

	// Set the revert to XID
	vm.superblock.RevertToXID = snapshot.xid
	vm.superblock.RevertToSblockOID = snapshot.sblockOID

	return nil
}

// ExportSnapshot exports a snapshot to a file
func (vm *VolumeManager) ExportSnapshot(name string, outputPath string) error {
	// This would create a file containing the snapshot data
	// Useful for backups or transferring snapshots between volumes
	return ErrNotImplemented
}

// ImportSnapshot imports a snapshot from a file
func (vm *VolumeManager) ImportSnapshot(tx *Transaction, inputPath string) error {
	// This would read snapshot data from a file and create a new snapshot
	return ErrNotImplemented
}

// DiffSnapshots compares two snapshots and returns the differences
func (vm *VolumeManager) DiffSnapshots(snapshot1, snapshot2 string) ([]string, error) {
	// This would compare two snapshots and return changed files
	return nil, ErrNotImplemented
}

// EstimateSnapshotSize calculates the approximate size of a snapshot
func (vm *VolumeManager) EstimateSnapshotSize(name string) (int64, error) {
	// Find the snapshot
	snapshot, err := vm.GetSnapshotByName(name)
	if err != nil {
		return 0, err
	}

	// In a real implementation, this would:
	// 1. Traverse the snapshot's extent reference tree
	// 2. Sum the sizes of all extents

	return 0, ErrNotImplemented
}

// GetInfo returns information about the snapshot
func (s *Snapshot) GetInfo() *SnapshotInfo {
	return &SnapshotInfo{
		Name:       s.name,
		XID:        s.xid,
		CreateTime: s.createTime,
		Size:       0, // In a full implementation, calculate from extents
	}
}

// GetName returns the name of the snapshot
func (s *Snapshot) GetName() string {
	return s.name
}

// GetXID returns the transaction ID of the snapshot
func (s *Snapshot) GetXID() uint64 {
	return s.xid
}

// GetCreateTime returns the creation time of the snapshot
func (s *Snapshot) GetCreateTime() time.Time {
	return s.createTime
}

// Mount mounts the snapshot
func (s *Snapshot) Mount(tx *Transaction) error {
	return s.volume.MountSnapshot(tx, s.name)
}

// Delete deletes the snapshot
func (s *Snapshot) Delete(tx *Transaction) error {
	return s.volume.DeleteSnapshot(tx, s.name)
}
