//
package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Additional error definitions for file operations
var (
	ErrReadOnly       = errors.New("volume is mounted read-only")
	ErrFileExists     = errors.New("file already exists")
	ErrVolumeFull     = errors.New("volume is full")
	ErrNotImplemented = errors.New("operation not implemented")
)

// Transaction represents an APFS file system transaction
type Transaction struct {
	volume     *VolumeManager
	xid        uint64
	operations []Operation
	completed  bool
}

// Operation represents a file system operation within a transaction
type Operation interface {
	Execute() error
	Revert() error
}

// CreateFileOp represents a file creation operation
type CreateFileOp struct {
	tx           *Transaction
	parentDir    *Directory
	name         string
	mode         uint16
	uid          uint32
	gid          uint32
	createdInode uint64
}

// CreateDirOp represents a directory creation operation
type CreateDirOp struct {
	tx           *Transaction
	parentDir    *Directory
	name         string
	mode         uint16
	uid          uint32
	gid          uint32
	createdInode uint64
}

// WriteFileOp represents a file write operation
type WriteFileOp struct {
	tx          *Transaction
	file        *File
	offset      int64
	data        []byte
	oldExtents  []FileExtent
	newExtents  []FileExtent
	oldSize     uint64
}

// DeleteFileOp represents a file deletion operation
type DeleteFileOp struct {
	tx             *Transaction
	parentDir      *Directory
	file           *File
	deletedDrecKey []byte
	deletedInode   []byte
	deletedExtents [][]byte
}

// SetXattrOp represents an extended attribute set operation
type SetXattrOp struct {
	tx        *Transaction
	file      *File
	name      string
	value     []byte
	oldValue  []byte
	wasCreate bool
}

// RemoveXattrOp represents an extended attribute removal operation
type RemoveXattrOp struct {
	tx        *Transaction
	file      *File
	name      string
	oldValue  []byte
}

// StartTransaction starts a new transaction for modifying the file system
func (vm *VolumeManager) StartTransaction() (*Transaction, error) {
	// Check if the volume is read-only
	if vm.isReadOnly() {
		return nil, ErrReadOnly
	}

	// Get next transaction ID from the container
	nextXID := vm.container.superblock.NextXID

	tx := &Transaction{
		volume:     vm,
		xid:        nextXID,
		operations: make([]Operation, 0),
		completed:  false,
	}

	return tx, nil
}

// isReadOnly returns true if the volume is mounted read-only
func (vm *VolumeManager) isReadOnly() bool {
	// Check readonly compatible features
	if (vm.superblock.ReadOnlyCompatFeatures & vm.container.superblock.ReadOnlyCompatFeatures) != 
		vm.container.superblock.ReadOnlyCompatFeatures {
		return true
	}

	// Check sealed volume flag
	if (vm.superblock.IncompatFeatures & APFSIncompatSealedVolume) != 0 {
		return true
	}

	return false
}

// Commit commits the transaction to the file system
func (tx *Transaction) Commit() error {
	if tx.completed {
		return errors.New("transaction already completed")
	}

	// Execute all operations in the transaction
	for _, op := range tx.operations {
		if err := op.Execute(); err != nil {
			// If an operation fails, revert all previous operations
			for i := len(tx.operations) - 1; i >= 0; i-- {
				tx.operations[i].Revert()
			}
			return err
		}
	}

	// Update the transaction ID in the container superblock
	tx.volume.container.superblock.NextXID = tx.xid + 1

	// Write the checkpoint
	if err := tx.writeCheckpoint(); err != nil {
		// If checkpoint writing fails, revert all operations
		for i := len(tx.operations) - 1; i >= 0; i-- {
			tx.operations[i].Revert()
		}
		return err
	}

	tx.completed = true
	return nil
}

// Rollback rolls back the transaction, reverting all operations
func (tx *Transaction) Rollback() error {
	if tx.completed {
		return errors.New("transaction already completed")
	}

	// No need to do anything if no operations were performed
	tx.completed = true
	return nil
}

// writeCheckpoint writes a checkpoint to persist the transaction
func (tx *Transaction) writeCheckpoint() error {
	// In a full implementation, this would:
	// 1. Prepare a new checkpoint descriptor
	// 2. Write all modified ephemeral objects to the checkpoint data area
	// 3. Write the checkpoint mapping blocks
	// 4. Write the updated container superblock to the checkpoint descriptor area
	// 5. Update block 0 with the latest container superblock

	// For now, we'll just return not implemented
	return ErrNotImplemented
}

// CreateFile creates a new file in a directory
func (dir *Directory) CreateFile(tx *Transaction, name string, mode uint16, uid uint32, gid uint32) (*File, error) {
	// Check if file already exists
	if _, err := dir.Lookup(name); err == nil {
		return nil, ErrFileExists
	}

	// Create the operation
	op := &CreateFileOp{
		tx:        tx,
		parentDir: dir,
		name:      name,
		mode:      mode | SIfreg, // Ensure it's a regular file
		uid:       uid,
		gid:       gid,
	}

	// Add to transaction
	tx.operations = append(tx.operations, op)

	// The file will be created during transaction commit
	// For now, return a placeholder file object
	file := &File{
		volume:      dir.volume,
		inodeNumber: 0, // Will be assigned during Execute
		parent:      dir.inodeNumber,
		name:        name,
		info: &FileInfo{
			Name:   name,
			Size:   0,
			Mode:   mode | SIfreg,
			ModTime: time.Now(),
			IsDir:   false,
			UID:     uid,
			GID:     gid,
		},
	}

	return file, nil
}

// Execute executes a file creation operation
func (op *CreateFileOp) Execute() error {
	vm := op.tx.volume

	// Allocate a new inode number
	newInodeNum := vm.superblock.NextObjID
	vm.superblock.NextObjID++

	// Create inode record
	now := time.Now().UnixNano()
	inode := &JInodeVal{
		ParentID:              op.parentDir.inodeNumber,
		PrivateID:             newInodeNum,
		CreateTime:            uint64(now),
		ModTime:               uint64(now),
		ChangeTime:            uint64(now),
		AccessTime:            uint64(now),
		InternalFlags:         0,
		NLink:                 1,
		DefaultProtectionClass: 0,
		WriteGenerationCounter: 0,
		BSDFlags:              0,
		Owner:                 op.uid,
		Group:                 op.gid,
		Mode:                  op.mode,
		Pad1:                  0,
		UncompressedSize:      0,
	}

	// Create an empty data stream
	dstream := &JDstream{
		Size:              0,
		AllocedSize:       0,
		DefaultCryptoID:   0,
		TotalBytesWritten: 0,
		TotalBytesRead:    0,
	}

	// Attach the data stream as an extended field
	inode = attachDataStream(inode, dstream)

	// Insert inode into the file system tree
	inodeKey := JKey{
		ObjIDAndType: (newInodeNum & ObjIDMask) | (APFSTypeInode << ObjTypeShift),
	}
	
	// Serialize key and value
	inodeKeyBytes, _ := binary.Marshal(binary.LittleEndian, inodeKey)
	inodeValBytes, _ := binary.Marshal(binary.LittleEndian, inode)

	// In a full implementation, this would insert into the B-tree
	// For now, we just store the key and value for the revert operation
	op.createdInode = newInodeNum

	// Create directory entry record
	drecVal := &JDrecVal{
		FileID:    newInodeNum,
		DateAdded: uint64(now),
		Flags:     DTReg,
	}

	// Create directory entry key
	drecKey := &JDrecKey{
		Hdr: JKey{
			ObjIDAndType: (op.parentDir.inodeNumber & ObjIDMask) | (APFSTypeDirRec << ObjTypeShift),
		},
		NameLen: uint16(len(op.name) + 1), // +1 for null terminator
	}

	// Serialize key and value
	drecKeyBytes, _ := binary.Marshal(binary.LittleEndian, drecKey)
	drecKeyBytes = append(drecKeyBytes, []byte(op.name+"\x00")...)
	drecValBytes, _ := binary.Marshal(binary.LittleEndian, drecVal)

	// In a full implementation, this would insert into the B-tree
	
	// Update parent directory's entry count
	op.parentDir.inode.NChildren++

	// Update volume file count
	vm.superblock.NumFiles++

	return nil
}

// Revert reverts a file creation operation
func (op *CreateFileOp) Revert() error {
	vm := op.tx.volume

	// Undo the inode creation
	if op.createdInode != 0 {
		// In a full implementation, this would remove from the B-tree
		
		// Decrement parent directory's entry count
		op.parentDir.inode.NChildren--

		// Decrement volume file count
		vm.superblock.NumFiles--

		// Restore the next OID counter
		vm.superblock.NextObjID--
	}

	return nil
}

// CreateDirectory creates a new directory
func (dir *Directory) CreateDirectory(tx *Transaction, name string, mode uint16, uid uint32, gid uint32) (*Directory, error) {
	// Check if directory already exists
	if _, err := dir.Lookup(name); err == nil {
		return nil, ErrFileExists
	}

	// Create the operation
	op := &CreateDirOp{
		tx:        tx,
		parentDir: dir,
		name:      name,
		mode:      mode | SIfdir, // Ensure it's a directory
		uid:       uid,
		gid:       gid,
	}

	// Add to transaction
	tx.operations = append(tx.operations, op)

	// The directory will be created during transaction commit
	// For now, return a placeholder directory object
	newDir := &Directory{
		volume:      dir.volume,
		inodeNumber: 0, // Will be assigned during Execute
		parent:      dir.inodeNumber,
		name:        name,
		info: &FileInfo{
			Name:   name,
			Size:   0,
			Mode:   mode | SIfdir,
			ModTime: time.Now(),
			IsDir:   true,
			UID:     uid,
			GID:     gid,
		},
		entries:    make([]*DirectoryEntry, 0),
		entriesMap: make(map[string]*DirectoryEntry),
	}

	return newDir, nil
}

// Execute executes a directory creation operation
func (op *CreateDirOp) Execute() error {
	vm := op.tx.volume

	// Allocate a new inode number
	newInodeNum := vm.superblock.NextObjID
	vm.superblock.NextObjID++

	// Create inode record
	now := time.Now().UnixNano()
	inode := &JInodeVal{
		ParentID:              op.parentDir.inodeNumber,
		PrivateID:             newInodeNum,
		CreateTime:            uint64(now),
		ModTime:               uint64(now),
		ChangeTime:            uint64(now),
		AccessTime:            uint64(now),
		InternalFlags:         0,
		NChildren:             0,
		DefaultProtectionClass: 0,
		WriteGenerationCounter: 0,
		BSDFlags:              0,
		Owner:                 op.uid,
		Group:                 op.gid,
		Mode:                  op.mode,
		Pad1:                  0,
		UncompressedSize:      0,
	}

	// Insert inode into the file system tree
	inodeKey := JKey{
		ObjIDAndType: (newInodeNum & ObjIDMask) | (APFSTypeInode << ObjTypeShift),
	}
	
	// Serialize key and value
	inodeKeyBytes, _ := binary.Marshal(binary.LittleEndian, inodeKey)
	inodeValBytes, _ := binary.Marshal(binary.LittleEndian, inode)

	// In a full implementation, this would insert into the B-tree
	// For now, we just store the key and value for the revert operation
	op.createdInode = newInodeNum

	// Create directory entry record
	drecVal := &JDrecVal{
		FileID:    newInodeNum,
		DateAdded: uint64(now),
		Flags:     DTDir,
	}

	// Create directory entry key
	drecKey := &JDrecKey{
		Hdr: JKey{
			ObjIDAndType: (op.parentDir.inodeNumber & ObjIDMask) | (APFSTypeDirRec << ObjTypeShift),
		},
		NameLen: uint16(len(op.name) + 1), // +1 for null terminator
	}

	// Serialize key and value
	drecKeyBytes, _ := binary.Marshal(binary.LittleEndian, drecKey)
	drecKeyBytes = append(drecKeyBytes, []byte(op.name+"\x00")...)
	drecValBytes, _ := binary.Marshal(binary.LittleEndian, drecVal)

	// In a full implementation, this would insert into the B-tree
	
	// Update parent directory's entry count
	op.parentDir.inode.NChildren++

	// Update volume directory count
	vm.superblock.NumDirectories++

	return nil
}

// Revert reverts a directory creation operation
func (op *CreateDirOp) Revert() error {
	vm := op.tx.volume

	// Undo the inode creation
	if op.createdInode != 0 {
		// In a full implementation, this would remove from the B-tree
		
		// Decrement parent directory's entry count
		op.parentDir.inode.NChildren--

		// Decrement volume directory count
		vm.superblock.NumDirectories--

		// Restore the next OID counter
		vm.superblock.NextObjID--
	}

	return nil
}

// Write writes data to a file
func (file *File) Write(tx *Transaction, offset int64, data []byte) error {
	// Create the operation
	op := &WriteFileOp{
		tx:         tx,
		file:       file,
		offset:     offset,
		data:       data,
		oldExtents: file.extents,
		oldSize:    0,
	}

	if file.dataStream != nil {
		op.oldSize = file.dataStream.Size
	}

	// Add to transaction
	tx.operations = append(tx.operations, op)

	return nil
}

// Execute executes a file write operation
func (op *WriteFileOp) Execute() error {
	file := op.file
	vm := file.volume
	
	// In a full implementation, this would:
	// 1. Calculate which blocks need to be allocated/modified
	// 2. Allocate new blocks if necessary
	// 3. Update file extents
	// 4. Write data to the allocated blocks
	// 5. Update the file's data stream size

	// For now, we'll just update the size if necessary
	newSize := op.offset + int64(len(op.data))
	if file.dataStream == nil {
		// Create a new data stream
		file.dataStream = &JDstream{
			Size:              uint64(newSize),
			AllocedSize:       uint64(newSize),
			DefaultCryptoID:   0,
			TotalBytesWritten: uint64(len(op.data)),
			TotalBytesRead:    0,
		}
		
		// Attach the data stream to the inode
		file.inode = attachDataStream(file.inode, file.dataStream)
	} else if uint64(newSize) > file.dataStream.Size {
		// Update the size
		file.dataStream.Size = uint64(newSize)
		file.dataStream.AllocedSize = uint64(newSize)
		file.dataStream.TotalBytesWritten += uint64(len(op.data))
		
		// Update the data stream in the inode
		file.inode = updateDataStream(file.inode, file.dataStream)
	}

	// Update file info
	file.info.Size = int64(file.dataStream.Size)
	file.info.ModTime = time.Now()
	
	// Update inode timestamps
	now := time.Now().UnixNano()
	file.inode.ModTime = uint64(now)
	file.inode.ChangeTime = uint64(now)
	
	return nil
}

// Revert reverts a file write operation
func (op *WriteFileOp) Revert() error {
	file := op.file
	
	// Restore old extents
	file.extents = op.oldExtents
	
	// Restore data stream
	if file.dataStream != nil {
		file.dataStream.Size = op.oldSize
		file.dataStream.AllocedSize = op.oldSize
		
		// Update the data stream in the inode
		file.inode = updateDataStream(file.inode, file.dataStream)
	}
	
	return nil
}

// attachDataStream attaches a data stream as an extended field to an inode
func attachDataStream(inode *JInodeVal, dstream *JDstream) *JInodeVal {
	// This is a simplified implementation that would actually need to:
	// 1. Check if inode already has extended fields
	// 2. Add a data stream extended field
	// 3. Update the extended fields blob header
	
	// In a real implementation, this would modify the inode in place
	// For now, we just return the original inode
	return inode
}

// updateDataStream updates an existing data stream in an inode
func updateDataStream(inode *JInodeVal, dstream *JDstream) *JInodeVal {
	// This is a simplified implementation that would actually need to:
	// 1. Find the data stream extended field
	// 2. Update its contents
	
	// In a real implementation, this would modify the inode in place
	// For now, we just return the original inode
	return inode
}

// Delete deletes a file
func (file *File) Delete(tx *Transaction) error {
	// Find parent directory
	parentDir, err := file.volume.GetDirectoryByInode(file.parent)
	if err != nil {
		return err
	}
	
	// Create the operation
	op := &DeleteFileOp{
		tx:        tx,
		parentDir: parentDir,
		file:      file,
	}
	
	// Add to transaction
	tx.operations = append(tx.operations, op)
	
	return nil
}

// Execute executes a file deletion operation
func (op *DeleteFileOp) Execute() error {
	file := op.file
	vm := file.volume
	
	// In a full implementation, this would:
	// 1. Remove the directory entry
	// 2. Decrement the inode's link count
	// 3. If link count reaches 0, remove the inode and its extents
	// 4. Update parent directory's children count
	
	// Update parent directory's entry count
	op.parentDir.inode.NChildren--
	
	// Update volume file count
	vm.superblock.NumFiles--
	
	return nil
}

// Revert reverts a file deletion operation
func (op *DeleteFileOp) Revert() error {
	// In a full implementation, this would:
	// 1. Restore the directory entry
	// 2. Restore the inode's link count
	// 3. Restore the inode and its extents if they were removed
	// 4. Update parent directory's children count
	
	// Update parent directory's entry count
	op.parentDir.inode.NChildren++
	
	// Update volume file count
	op.file.volume.superblock.NumFiles++
	
	return nil
}

// SetXattr sets an extended attribute on a file
func (file *File) SetXattr(tx *Transaction, name string, value []byte) error {
	// Check if attribute already exists
	oldValue, err := file.GetXattr(name)
	wasCreate := err != nil
	
	// Create the operation
	op := &SetXattrOp{
		tx:        tx,
		file:      file,
		name:      name,
		value:     value,
		oldValue:  oldValue,
		wasCreate: wasCreate,
	}
	
	// Add to transaction
	tx.operations = append(tx.operations, op)
	
	return nil
}

// Execute executes an extended attribute set operation
func (op *SetXattrOp) Execute() error {
	file := op.file
	vm := file.volume
	
	// In a full implementation, this would:
	// 1. Create or update the xattr record
	// 2. Handle embedded vs. data stream storage based on size
	
	// Update inode change time
	now := time.Now().UnixNano()
	file.inode.ChangeTime = uint64(now)
	
	return nil
}

// Revert reverts an extended attribute set operation
func (op *SetXattrOp) Revert() error {
	file := op.file
	
	// In a full implementation, this would:
	// 1. Remove the xattr if it was created
	// 2. Restore the old value if it was updated
	
	return nil
}

// RemoveXattr removes an extended attribute from a file
func (file *File) RemoveXattr(tx *Transaction, name string) error {
	// Get current value
	oldValue, err := file.GetXattr(name)
	if err != nil {
		return err
	}
	
	// Create the operation
	op := &RemoveXattrOp{
		tx:        tx,
		file:      file,
		name:      name,
		oldValue:  oldValue,
	}
	
	// Add to transaction
	tx.operations = append(tx.operations, op)
	
	return nil
}

// Execute executes an extended attribute removal operation
func (op *RemoveXattrOp) Execute() error {
	file := op.file
	vm := file.volume
	
	// In a full implementation, this would:
	// 1. Remove the xattr record
	// 2. Handle cleanup of data streams if necessary
	
	// Update inode change time
	now := time.Now().UnixNano()
	file.inode.ChangeTime = uint64(now)
	
	return nil
}

// Revert reverts an extended attribute removal operation
func (op *RemoveXattrOp) Revert() error {
	file := op.file
	
	// In a full implementation, this would:
	// 1. Restore the xattr record
	// 2. Restore any data streams
	
	return nil
}

// Rename renames a file or directory
func (vm *VolumeManager) Rename(tx *Transaction, oldPath string, newPath string) error {
	// In a full implementation, this would:
	// 1. Find the source file/directory
	// 2. Find the destination parent directory
	// 3. Check if destination already exists
	// 4. Create a rename operation
	// 5. Add to transaction
	
	return ErrNotImplemented
}
