// data_streams.go
/*
 set of functions to handle various aspects of APFS data streams, including:

Extended attribute operations (Delete, GetSize)
Resource fork management
Compressed data support
Sparse file handling
General data stream management (creation, deletion, extent allocation/deallocation)
*/
package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// JDstream represents information about a data stream (j_dstream_t)
type JDstream struct {
	Size              uint64 // Size in bytes of the data
	AllocedSize       uint64 // Total allocated space for the data
	DefaultCryptoID   uint64 // Default crypto ID for extents
	TotalBytesWritten uint64 // Total bytes written to this data stream
	TotalBytesRead    uint64 // Total bytes read from this data stream
}

// Serialize the JDstream structure to bytes
func (ds *JDstream) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, ds)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JDstream from bytes
func (ds *JDstream) Parse(data []byte) error {
	if len(data) < binary.Size(JDstream{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, ds)
}

// JPhysExtKey represents the key half of a physical extent record (j_phys_ext_key_t)
type JPhysExtKey struct {
	Hdr JKey // The record's header
}

// Serialize the JPhysExtKey structure to bytes
func (key *JPhysExtKey) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JPhysExtKey from bytes
func (key *JPhysExtKey) Parse(data []byte) error {
	if len(data) < binary.Size(JPhysExtKey{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, key)
}

// JPhysExtVal represents the value half of a physical extent record (j_phys_ext_val_t)
type JPhysExtVal struct {
	LenAndKind  uint64 // Bit field containing length and kind
	OwningObjID uint64 // The ID of the file system record using this extent
	Refcnt      int32  // Reference count
}

// Serialize the JPhysExtVal structure to bytes
func (val *JPhysExtVal) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, val)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JPhysExtVal from bytes
func (val *JPhysExtVal) Parse(data []byte) error {
	if len(data) < binary.Size(JPhysExtVal{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, val)
}

// GetLength returns the length of the extent in blocks
func (val *JPhysExtVal) GetLength() uint64 {
	return val.LenAndKind & PextLenMask
}

// GetKind returns the kind of the extent
func (val *JPhysExtVal) GetKind() uint8 {
	return uint8((val.LenAndKind & PextKindMask) >> PextKindShift)
}

// SetLength sets the length of the extent in blocks
func (val *JPhysExtVal) SetLength(length uint64) {
	val.LenAndKind = (val.LenAndKind & PextKindMask) | (length & PextLenMask)
}

// SetKind sets the kind of the extent
func (val *JPhysExtVal) SetKind(kind uint8) {
	val.LenAndKind = (val.LenAndKind & PextLenMask) | (uint64(kind) << PextKindShift)
}

// JFileExtentKey represents the key half of a file extent record (j_file_extent_key_t)
type JFileExtentKey struct {
	Hdr         JKey   // The record's header
	LogicalAddr uint64 // The logical address (file offset in bytes)
}

// Serialize the JFileExtentKey structure to bytes
func (key *JFileExtentKey) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JFileExtentKey from bytes
func (key *JFileExtentKey) Parse(data []byte) error {
	if len(data) < binary.Size(JFileExtentKey{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, key)
}

// JFileExtentVal represents the value half of a file extent record (j_file_extent_val_t)
type JFileExtentVal struct {
	LenAndFlags  uint64 // Bit field containing length and flags
	PhysBlockNum uint64 // The physical block number
	CryptoID     uint64 // The crypto ID or tweak for encryption
}

// Serialize the JFileExtentVal structure to bytes
func (val *JFileExtentVal) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, val)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JFileExtentVal from bytes
func (val *JFileExtentVal) Parse(data []byte) error {
	if len(data) < binary.Size(JFileExtentVal{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, val)
}

// GetLength returns the length of the extent in bytes
func (val *JFileExtentVal) GetLength() uint64 {
	return val.LenAndFlags & JFileExtentLenMask
}

// GetFlags returns the flags of the extent
func (val *JFileExtentVal) GetFlags() uint8 {
	return uint8((val.LenAndFlags & JFileExtentFlagMask) >> JFileExtentFlagShift)
}

// SetLength sets the length of the extent in bytes
func (val *JFileExtentVal) SetLength(length uint64) {
	val.LenAndFlags = (val.LenAndFlags & JFileExtentFlagMask) | (length & JFileExtentLenMask)
}

// SetFlags sets the flags of the extent
func (val *JFileExtentVal) SetFlags(flags uint8) {
	val.LenAndFlags = (val.LenAndFlags & JFileExtentLenMask) | (uint64(flags) << JFileExtentFlagShift)
}

// IsCryptoIDTweak returns true if the crypto ID is a tweak value
func (val *JFileExtentVal) IsCryptoIDTweak() bool {
	return val.GetFlags()&FextCryptoIDIsTweak != 0
}

// JDstreamIDKey represents the key half of a data stream record (j_dstream_id_key_t)
type JDstreamIDKey struct {
	Hdr JKey // The record's header
}

// Serialize the JDstreamIDKey structure to bytes
func (key *JDstreamIDKey) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JDstreamIDKey from bytes
func (key *JDstreamIDKey) Parse(data []byte) error {
	if len(data) < binary.Size(JDstreamIDKey{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, key)
}

// JDstreamIDVal represents the value half of a data stream record (j_dstream_id_val_t)
type JDstreamIDVal struct {
	Refcnt uint32 // Reference count
}

// Serialize the JDstreamIDVal structure to bytes
func (val *JDstreamIDVal) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, val)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JDstreamIDVal from bytes
func (val *JDstreamIDVal) Parse(data []byte) error {
	if len(data) < binary.Size(JDstreamIDVal{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, val)
}

// JXattrDstream represents a data stream for extended attributes (j_xattr_dstream_t)
type JXattrDstream struct {
	XattrObjID uint64   // The data stream's identifier
	Dstream    JDstream // The data stream information
}

// Serialize the JXattrDstream structure to bytes
func (xds *JXattrDstream) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, xds)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse creates a JXattrDstream from bytes
func (xds *JXattrDstream) Parse(data []byte) error {
	if len(data) < binary.Size(JXattrDstream{}) {
		return ErrStructTooShort
	}
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, xds)
}

// DataExtent represents a contiguous range of data blocks for a file
type DataExtent struct {
	LogicalOffset uint64 // Logical byte offset within the file
	PhysicalStart uint64 // Physical block number on disk
	Length        uint64 // Length in bytes
	CryptoID      uint64 // Crypto ID or tweak for encryption
}

// FileData manages the data of a file
type FileData struct {
	volume      *VolumeManager
	inodeNumber uint64
	dataStream  *JDstream
	extents     []DataExtent
	cryptoID    uint64
}

// NewFileData creates a new FileData instance for an inode
func NewFileData(vm *VolumeManager, inodeNumber uint64) (*FileData, error) {
	fd := &FileData{
		volume:      vm,
		inodeNumber: inodeNumber,
		extents:     make([]DataExtent, 0),
	}

	// Load the file's data stream and extents
	err := fd.loadDataStream()
	if err != nil {
		return nil, err
	}

	if fd.dataStream != nil {
		err = fd.loadExtents()
		if err != nil {
			return nil, err
		}
	}

	return fd, nil
}

// loadDataStream loads the file's data stream from the inode
func (fd *FileData) loadDataStream() error {
	// Find the inode
	inodeVal, err := fd.volume.findInode(fd.inodeNumber)
	if err != nil {
		return err
	}

	// Extract the data stream from the inode's extended fields
	dstream, err := fd.volume.getInodeDataStream(inodeVal)
	if err != nil {
		return nil // Not an error, file may not have a data stream
	}

	fd.dataStream = dstream
	fd.cryptoID = dstream.DefaultCryptoID

	return nil
}

// loadExtents loads all the file extents
func (fd *FileData) loadExtents() error {
	// Prepare a key for range iteration
	startKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (fd.inodeNumber & ObjIDMask) | (APFSTypeFileExtent << ObjTypeShift),
		},
		LogicalAddr: 0,
	}

	endKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (fd.inodeNumber & ObjIDMask) | ((APFSTypeFileExtent + 1) << ObjTypeShift),
		},
		LogicalAddr: 0,
	}

	// Convert keys to bytes
	startKeyBytes, _ := startKey.Serialize()
	endKeyBytes, _ := endKey.Serialize()

	// Iterate through file extents
	fd.volume.fsTree.IterateRange(startKeyBytes, endKeyBytes, func(key, value []byte) bool {
		// Parse the file extent key
		extKey := &JFileExtentKey{}
		if err := extKey.Parse(key); err != nil {
			return true
		}

		// Parse the file extent value
		extVal := &JFileExtentVal{}
		if err := extVal.Parse(value); err != nil {
			return true
		}

		// Create extent
		extent := DataExtent{
			LogicalOffset: extKey.LogicalAddr,
			PhysicalStart: extVal.PhysBlockNum,
			Length:        extVal.GetLength(),
			CryptoID:      extVal.CryptoID,
		}

		fd.extents = append(fd.extents, extent)
		return true
	})

	// Sort extents by logical address if needed
	// (they should already be sorted because of B-tree ordering)

	return nil
}

// GetSize returns the size of the file in bytes
func (fd *FileData) GetSize() uint64 {
	if fd.dataStream == nil {
		return 0
	}
	return fd.dataStream.Size
}

// GetAllocatedSize returns the allocated size of the file in bytes
func (fd *FileData) GetAllocatedSize() uint64 {
	if fd.dataStream == nil {
		return 0
	}
	return fd.dataStream.AllocedSize
}

// Read reads data from the file at the specified offset
func (fd *FileData) Read(offset int64, length int) ([]byte, error) {
	// Check if file has a data stream
	if fd.dataStream == nil {
		return nil, errors.New("file has no data")
	}

	// Check if offset is beyond the end of the file
	if offset >= int64(fd.dataStream.Size) {
		return nil, nil // EOF
	}

	// Adjust length if it would read past the end of the file
	if offset+int64(length) > int64(fd.dataStream.Size) {
		length = int(int64(fd.dataStream.Size) - offset)
	}

	// Allocate buffer for the data
	data := make([]byte, length)
	bytesRead := 0

	// Find extents that cover the requested range
	blockSize := int64(fd.volume.container.blockSize)
	startBlock := offset / blockSize
	endBlock := (offset + int64(length) + blockSize - 1) / blockSize

	for _, extent := range fd.extents {
		// Check if this extent contains data we need
		extentStartBlock := int64(extent.LogicalOffset) / blockSize
		extentEndBlock := extentStartBlock + int64(extent.Length)/blockSize

		if extentEndBlock <= startBlock || extentStartBlock >= endBlock {
			// This extent doesn't overlap our range
			continue
		}

		// Calculate overlap
		overlapStart := max(startBlock, extentStartBlock)
		overlapEnd := min(endBlock, extentEndBlock)

		// Calculate offsets
		extentOffset := (overlapStart - extentStartBlock) * blockSize
		bufferOffset := (overlapStart - startBlock) * blockSize
		overlapLength := (overlapEnd - overlapStart) * blockSize

		// Adjust for partial blocks at the beginning and end
		if overlapStart == startBlock {
			extentOffset += (offset % blockSize)
			overlapLength -= (offset % blockSize)
		}

		if overlapEnd == endBlock && (offset+int64(length))%blockSize != 0 {
			overlapLength -= blockSize - ((offset + int64(length)) % blockSize)
		}

		// Read the data from the extent
		extentData, err := fd.readExtent(extent, int64(extentOffset), int(overlapLength))
		if err != nil {
			return nil, err
		}

		// Copy to the output buffer
		copy(data[bufferOffset:bufferOffset+int64(len(extentData))], extentData)
		bytesRead += len(extentData)
	}

	// Update read statistics
	fd.dataStream.TotalBytesRead += uint64(bytesRead)

	return data[:bytesRead], nil
}

// readExtent reads data from a specific extent
func (fd *FileData) readExtent(extent DataExtent, offset int64, length int) ([]byte, error) {
	// Calculate physical offset
	physOffset := int64(extent.PhysicalStart)*int64(fd.volume.container.blockSize) + offset

	// Read the data
	data := make([]byte, length)

	_, err := fd.volume.container.device.Seek(physOffset, io.SeekStart)
	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(fd.volume.container.device, data)
	if err != nil {
		return nil, err
	}

	// Decrypt if necessary
	if fd.isEncrypted() && extent.CryptoID != 0 {
		// Check if we have a decryption context
		if fd.volume.encryptionContext == nil || !fd.volume.encryptionContext.IsDecrypted() {
			return nil, ErrNoKeyAvailable
		}

		// Decrypt the data
		decrypted, err := fd.volume.encryptionContext.DecryptBlock(
			data,
			extent.PhysicalStart,
			extent.CryptoID,
		)
		if err != nil {
			return nil, err
		}

		return decrypted, nil
	}

	return data, nil
}

// isEncrypted returns true if the file is encrypted
func (fd *FileData) isEncrypted() bool {
	return (fd.volume.superblock.FSFlags & APFSFSUnencrypted) == 0
}

// Write writes data to the file at the specified offset
func (fd *FileData) Write(tx *Transaction, offset int64, data []byte) error {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Create or update the data stream if needed
	if fd.dataStream == nil {
		fd.dataStream = &JDstream{
			Size:              0,
			AllocedSize:       0,
			DefaultCryptoID:   0,
			TotalBytesWritten: 0,
			TotalBytesRead:    0,
		}
	}

	// Calculate new file size
	newSize := offset + int64(len(data))
	if newSize > int64(fd.dataStream.Size) {
		fd.dataStream.Size = uint64(newSize)
	}

	// In a real implementation, this would:
	// 1. Allocate blocks for the file if needed
	// 2. Split existing extents if needed
	// 3. Create new extents for new data
	// 4. Write the data to the allocated blocks
	// 5. Update the file's extents list
	// 6. Update the data stream size

	// For now, we'll just update the data stream size
	fd.dataStream.TotalBytesWritten += uint64(len(data))

	return ErrNotImplemented
}

// Truncate truncates the file to the specified size
func (fd *FileData) Truncate(tx *Transaction, size int64) error {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Check if the file has a data stream
	if fd.dataStream == nil {
		// If truncating to zero, nothing to do
		if size == 0 {
			return nil
		}

		// Otherwise, create a data stream
		fd.dataStream = &JDstream{
			Size:              0,
			AllocedSize:       0,
			DefaultCryptoID:   0,
			TotalBytesWritten: 0,
			TotalBytesRead:    0,
		}
	}

	// In a real implementation, this would:
	// 1. If expanding, allocate new blocks
	// 2. If shrinking, free blocks and update extents
	// 3. Update the data stream size

	// For now, just update the data stream size
	fd.dataStream.Size = uint64(size)

	return ErrNotImplemented
}

// Clone creates a copy-on-write clone of this file
func (fd *FileData) Clone(tx *Transaction, targetInodeNumber uint64) error {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Check if the file has a data stream
	if fd.dataStream == nil {
		return nil // Nothing to clone
	}

	// In a real implementation, this would:
	// 1. Create a data stream for the target inode
	// 2. Copy the extents, incrementing their reference counts
	// 3. Set the INODE_WAS_CLONED flag on both inodes

	return ErrNotImplemented
}

// GetExtents returns the file's extents
func (fd *FileData) GetExtents() []DataExtent {
	return fd.extents
}

// XAttrData manages the data of an extended attribute
type XAttrData struct {
	volume      *VolumeManager
	inodeNumber uint64
	name        string
	dataStream  *JXattrDstream
	extents     []DataExtent
}

// NewXAttrData creates a new XAttrData instance
func NewXAttrData(vm *VolumeManager, inodeNumber uint64, name string) (*XAttrData, error) {
	xd := &XAttrData{
		volume:      vm,
		inodeNumber: inodeNumber,
		name:        name,
		extents:     make([]DataExtent, 0),
	}

	// Look up the extended attribute
	xattrKey := &JXattrKey{
		Hdr: JKey{
			ObjIDAndType: (inodeNumber & ObjIDMask) | (APFSTypeXattr << ObjTypeShift),
		},
		NameLen: uint16(len(name) + 1), // +1 for null terminator
	}

	// Convert key to bytes
	keyBytes, err := xattrKey.Serialize()
	if err != nil {
		return nil, err
	}

	// Append the name
	keyBytes = append(keyBytes, []byte(name+"\x00")...)

	// Search the file system tree
	valueBytes, err := vm.fsTree.Search(keyBytes)
	if err != nil {
		return nil, ErrNotFound
	}

	// Parse the xattr value
	xattrVal := &JXattrVal{}
	err = xattrVal.Parse(valueBytes)
	if err != nil {
		return nil, err
	}

	// Check if the attribute is stored in a data stream
	if (xattrVal.Flags & XattrDataStream) != 0 {
		// Get the data stream ID
		var streamID uint64

		// The xdata field contains the stream ID
		dataOffset := binary.Size(JXattrVal{})
		if dataOffset+8 > len(valueBytes) {
			return nil, errors.New("invalid xattr data stream ID")
		}

		streamID = binary.LittleEndian.Uint64(valueBytes[dataOffset:])

		// Load the data stream
		err = xd.loadDataStream(streamID)
		if err != nil {
			return nil, err
		}
	}

	return xd, nil
}

// loadDataStream loads the extended attribute's data stream
func (xd *XAttrData) loadDataStream(streamID uint64) error {
	// Create a key for the data stream
	dstreamKey := &JDstreamIDKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | (APFSTypeDstreamID << ObjTypeShift),
		},
	}

	// Convert key to bytes
	keyBytes, err := dstreamKey.Serialize()
	if err != nil {
		return err
	}

	// Search for the key
	valueBytes, err := xd.volume.fsTree.Search(keyBytes)
	if err != nil {
		return err
	}

	// Parse the value
	dstreamVal := &JDstreamIDVal{}
	err = dstreamVal.Parse(valueBytes)
	if err != nil {
		return err
	}

	// The data stream is stored in file extents
	// Load the extents for this data stream
	err = xd.loadExtents(streamID)
	if err != nil {
		return err
	}

	return nil
}

// loadExtents loads the extended attribute's extents
func (xd *XAttrData) loadExtents(streamID uint64) error {
	// Prepare a key for range iteration
	startKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | (APFSTypeFileExtent << ObjTypeShift),
		},
		LogicalAddr: 0,
	}

	endKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | ((APFSTypeFileExtent + 1) << ObjTypeShift),
		},
		LogicalAddr: 0,
	}

	// Convert keys to bytes
	startKeyBytes, _ := startKey.Serialize()
	endKeyBytes, _ := endKey.Serialize()

	// Iterate through file extents
	xd.volume.fsTree.IterateRange(startKeyBytes, endKeyBytes, func(key, value []byte) bool {
		// Parse the file extent key
		extKey := &JFileExtentKey{}
		if err := extKey.Parse(key); err != nil {
			return true
		}

		// Parse the file extent value
		extVal := &JFileExtentVal{}
		if err := extVal.Parse(value); err != nil {
			return true
		}

		// Create extent
		extent := DataExtent{
			LogicalOffset: extKey.LogicalAddr,
			PhysicalStart: extVal.PhysBlockNum,
			Length:        extVal.GetLength(),
			CryptoID:      extVal.CryptoID,
		}

		xd.extents = append(xd.extents, extent)
		return true
	})

	return nil
}

// Read reads the extended attribute's data
func (xd *XAttrData) Read() ([]byte, error) {
	// Check if we have a direct value
	xattrKey := &JXattrKey{
		Hdr: JKey{
			ObjIDAndType: (xd.inodeNumber & ObjIDMask) | (APFSTypeXattr << ObjTypeShift),
		},
		NameLen: uint16(len(xd.name) + 1), // +1 for null terminator
	}

	// Convert key to bytes
	keyBytes, err := xattrKey.Serialize()
	if err != nil {
		return nil, err
	}

	// Append the name
	keyBytes = append(keyBytes, []byte(xd.name+"\x00")...)

	// Search the file system tree
	valueBytes, err := xd.volume.fsTree.Search(keyBytes)
	if err != nil {
		return nil, ErrNotFound
	}

	// Parse the xattr value
	xattrVal := &JXattrVal{}
	err = xattrVal.Parse(valueBytes)
	if err != nil {
		return nil, err
	}

	// Check if the attribute is embedded or in a data stream
	if (xattrVal.Flags & XattrDataEmbedded) != 0 {
		// Data is embedded in the value
		dataOffset := binary.Size(JXattrVal{})
		if dataOffset+int(xattrVal.XDataLen) > len(valueBytes) {
			return nil, errors.New("invalid embedded xattr data")
		}

		return valueBytes[dataOffset : dataOffset+int(xattrVal.XDataLen)], nil
	} else if (xattrVal.Flags & XattrDataStream) != 0 {
		// Data is in a data stream - read from extents
		// This is complex and depends on the data stream size
		return nil, fmt.Errorf("reading from xattr data streams not implemented")
	}

	return nil, errors.New("invalid xattr flags")
}

// Write writes data to the extended attribute
func (xd *XAttrData) Write(tx *Transaction, data []byte) error {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Determine storage method based on data size
	if len(data) <= XattrMaxEmbeddedSize {
		// Store embedded
		// Create a new xattr record
		xattrVal := &JXattrVal{
			Flags:    XattrDataEmbedded,
			XDataLen: uint16(len(data)),
		}

		// In a real implementation, this would update the xattr record

	} else {
		// Store in data stream
		// Create or update data stream

		// In a real implementation, this would:
		// 1. Create a new data stream if it doesn't exist
		// 2. Allocate blocks for the data
		// 3. Write the data to the allocated blocks
		// 4. Update the data stream size
	}

	return ErrNotImplemented
}

// Delete deletes the extended attribute
func (xd *XAttrData) Delete(tx *Transaction) error {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Create a key for the xattr record
	xattrKey := &JXattrKey{
		Hdr: JKey{
			ObjIDAndType: (xd.inodeNumber & ObjIDMask) | (APFSTypeXattr << ObjTypeShift),
		},
		NameLen: uint16(len(xd.name) + 1), // +1 for null terminator
	}

	// Convert key to bytes
	keyBytes, err := xattrKey.Serialize()
	if err != nil {
		return err
	}

	// Append the name
	keyBytes = append(keyBytes, []byte(xd.name+"\x00")...)

	// Search the file system tree to make sure it exists first
	valueBytes, err := xd.volume.fsTree.Search(keyBytes)
	if err != nil {
		return ErrNotFound
	}

	// Parse the xattr value to determine if it has a data stream
	xattrVal := &JXattrVal{}
	err = xattrVal.Parse(valueBytes)
	if err != nil {
		return err
	}

	// If the attribute has a data stream, we need to delete that too
	if (xattrVal.Flags & XattrDataStream) != 0 {
		// Get the data stream ID
		dataOffset := binary.Size(JXattrVal{})
		if dataOffset+8 > len(valueBytes) {
			return errors.New("invalid xattr data stream ID")
		}

		streamID := binary.LittleEndian.Uint64(valueBytes[dataOffset:])

		// Delete the data stream (would remove extents, etc.)
		err = xd.deleteDataStream(tx, streamID)
		if err != nil {
			return err
		}
	}

	// In a real implementation, this would remove the xattr record from the B-tree
	// For now, just mark it as to be removed in the transaction

	return ErrNotImplemented
}

// deleteDataStream deletes a data stream and all its extents
func (xd *XAttrData) deleteDataStream(tx *Transaction, streamID uint64) error {
	// In a real implementation, this would:
	// 1. Delete all file extents associated with this data stream
	// 2. Delete the data stream ID record
	// 3. Decrement reference counts for any shared extents
	// 4. Free the physical blocks if their reference count becomes zero

	return ErrNotImplemented
}

// GetSize returns the size of the extended attribute data
func (xd *XAttrData) GetSize() (uint64, error) {
	// Check if we have a direct value
	xattrKey := &JXattrKey{
		Hdr: JKey{
			ObjIDAndType: (xd.inodeNumber & ObjIDMask) | (APFSTypeXattr << ObjTypeShift),
		},
		NameLen: uint16(len(xd.name) + 1), // +1 for null terminator
	}

	// Convert key to bytes
	keyBytes, err := xattrKey.Serialize()
	if err != nil {
		return 0, err
	}

	// Append the name
	keyBytes = append(keyBytes, []byte(xd.name+"\x00")...)

	// Search the file system tree
	valueBytes, err := xd.volume.fsTree.Search(keyBytes)
	if err != nil {
		return 0, ErrNotFound
	}

	// Parse the xattr value
	xattrVal := &JXattrVal{}
	err = xattrVal.Parse(valueBytes)
	if err != nil {
		return 0, err
	}

	// Check if the attribute is embedded or in a data stream
	if (xattrVal.Flags & XattrDataEmbedded) != 0 {
		return uint64(xattrVal.XDataLen), nil
	} else if (xattrVal.Flags & XattrDataStream) != 0 {
		if xd.dataStream != nil {
			return xd.dataStream.Dstream.Size, nil
		}

		// We need to get the data stream size by loading it
		dataOffset := binary.Size(JXattrVal{})
		if dataOffset+8 > len(valueBytes) {
			return 0, errors.New("invalid xattr data stream ID")
		}

		streamID := binary.LittleEndian.Uint64(valueBytes[dataOffset:])
		size, err := xd.getDataStreamSize(streamID)
		if err != nil {
			return 0, err
		}

		return size, nil
	}

	return 0, errors.New("invalid xattr flags")
}

// getDataStreamSize gets the size of a data stream
func (xd *XAttrData) getDataStreamSize(streamID uint64) (uint64, error) {
	// In a full implementation, this would load the data stream's information
	// For now, calculate the size from extents if available

	var size uint64
	for _, extent := range xd.extents {
		extentEnd := extent.LogicalOffset + extent.Length
		if extentEnd > size {
			size = extentEnd
		}
	}

	return size, nil
}

// ResourceFork manages a file's resource fork
type ResourceFork struct {
	fileData *FileData
}

// NewResourceFork creates a new ResourceFork instance for a file
func NewResourceFork(vm *VolumeManager, inodeNumber uint64) (*ResourceFork, error) {
	// First, check if the file has a resource fork
	// Look for the resource fork extended attribute
	xattr, err := NewXAttrData(vm, inodeNumber, "com.apple.ResourceFork")
	if err != nil {
		return nil, err
	}

	// Create a FileData for the resource fork
	fileData := &FileData{
		volume:      vm,
		inodeNumber: inodeNumber,
		extents:     make([]DataExtent, 0),
	}

	// If the attribute is in a data stream, we can use its extents
	if len(xattr.extents) > 0 {
		fileData.extents = xattr.extents

		// Set data stream if available
		if xattr.dataStream != nil {
			fileData.dataStream = &xattr.dataStream.Dstream
		}
	}

	return &ResourceFork{
		fileData: fileData,
	}, nil
}

// Read reads data from the resource fork
func (rf *ResourceFork) Read(offset int64, length int) ([]byte, error) {
	return rf.fileData.Read(offset, length)
}

// Write writes data to the resource fork
func (rf *ResourceFork) Write(tx *Transaction, offset int64, data []byte) error {
	return rf.fileData.Write(tx, offset, data)
}

// GetSize returns the size of the resource fork
func (rf *ResourceFork) GetSize() uint64 {
	return rf.fileData.GetSize()
}

// CompressedData manages compressed file data
type CompressedData struct {
	fileData         *FileData
	uncompressedSize uint64
}

// NewCompressedData creates a new CompressedData instance for a file
func NewCompressedData(fileData *FileData, uncompressedSize uint64) *CompressedData {
	return &CompressedData{
		fileData:         fileData,
		uncompressedSize: uncompressedSize,
	}
}

// GetCompressedSize returns the compressed size of the file
func (cd *CompressedData) GetCompressedSize() uint64 {
	return cd.fileData.GetSize()
}

// GetUncompressedSize returns the uncompressed size of the file
func (cd *CompressedData) GetUncompressedSize() uint64 {
	return cd.uncompressedSize
}

// Read reads and decompresses data from the file
func (cd *CompressedData) Read(offset int64, length int) ([]byte, error) {
	// In a real implementation, this would:
	// 1. Determine which compressed blocks are needed based on offset and length
	// 2. Read those compressed blocks
	// 3. Decompress them
	// 4. Extract the requested portion of the decompressed data

	return nil, ErrNotImplemented
}

// Write compresses and writes data to the file
func (cd *CompressedData) Write(tx *Transaction, offset int64, data []byte) error {
	// In a real implementation, this would:
	// 1. Read and decompress any existing blocks that will be partially modified
	// 2. Update the decompressed data with the new data
	// 3. Compress the modified blocks
	// 4. Write the compressed blocks

	return ErrNotImplemented
}

// SparseData manages sparse file data
type SparseData struct {
	fileData    *FileData
	sparseBytes uint64
}

// NewSparseData creates a new SparseData instance for a file
func NewSparseData(fileData *FileData, sparseBytes uint64) *SparseData {
	return &SparseData{
		fileData:    fileData,
		sparseBytes: sparseBytes,
	}
}

// GetLogicalSize returns the logical size of the file
func (sd *SparseData) GetLogicalSize() uint64 {
	return sd.fileData.GetSize()
}

// GetPhysicalSize returns the physical size of the file (excluding sparse regions)
func (sd *SparseData) GetPhysicalSize() uint64 {
	return sd.fileData.GetSize() - sd.sparseBytes
}

// GetSparseBytes returns the number of sparse (unallocated) bytes
func (sd *SparseData) GetSparseBytes() uint64 {
	return sd.sparseBytes
}

// Read reads data from the file, returning zeros for sparse regions
func (sd *SparseData) Read(offset int64, length int) ([]byte, error) {
	// First try to read normally
	data, err := sd.fileData.Read(offset, length)

	// If we hit an empty region (EOF or sparse), fill with zeros
	if err == nil && len(data) < length {
		// Fill the rest with zeros
		fullData := make([]byte, length)
		copy(fullData, data)
		return fullData, nil
	}

	return data, err
}

// IsSparseRegion checks if a region of the file is sparse
func (sd *SparseData) IsSparseRegion(offset int64, length int) (bool, error) {
	// In a real implementation, this would check the file's extents
	// to determine if the requested region is allocated or sparse

	return false, ErrNotImplemented
}

// Write writes data to the file, potentially creating sparse regions
func (sd *SparseData) Write(tx *Transaction, offset int64, data []byte) error {
	// In a real implementation, this would:
	// 1. Check if the data consists of all zeros
	// 2. If yes, mark the region as sparse instead of allocating storage
	// 3. Otherwise, write the data normally

	return sd.fileData.Write(tx, offset, data)
}

// DataStreamManager manages operations on data streams
type DataStreamManager struct {
	volume *VolumeManager
}

// NewDataStreamManager creates a new DataStreamManager
func NewDataStreamManager(vm *VolumeManager) *DataStreamManager {
	return &DataStreamManager{
		volume: vm,
	}
}

// CreateDataStream creates a new data stream
func (dsm *DataStreamManager) CreateDataStream(tx *Transaction) (uint64, *JDstream, error) {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return 0, nil, errors.New("invalid transaction")
	}

	// Allocate a new object ID
	streamID := dsm.volume.superblock.NextObjID
	dsm.volume.superblock.NextObjID++

	// Create the data stream
	dstream := &JDstream{
		Size:              0,
		AllocedSize:       0,
		DefaultCryptoID:   0,
		TotalBytesWritten: 0,
		TotalBytesRead:    0,
	}

	// Create the data stream ID record
	dstreamIDKey := &JDstreamIDKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | (APFSTypeDstreamID << ObjTypeShift),
		},
	}

	dstreamIDVal := &JDstreamIDVal{
		Refcnt: 1,
	}

	// In a real implementation, this would insert the record into the B-tree

	return streamID, dstream, ErrNotImplemented
}

// DeleteDataStream deletes a data stream
func (dsm *DataStreamManager) DeleteDataStream(tx *Transaction, streamID uint64) error {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Find the data stream ID record
	dstreamIDKey := &JDstreamIDKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | (APFSTypeDstreamID << ObjTypeShift),
		},
	}

	// Convert key to bytes
	keyBytes, err := dstreamIDKey.Serialize()
	if err != nil {
		return err
	}

	// Search the file system tree
	valueBytes, err := dsm.volume.fsTree.Search(keyBytes)
	if err != nil {
		return ErrNotFound
	}

	// Parse the value
	dstreamIDVal := &JDstreamIDVal{}
	err = dstreamIDVal.Parse(valueBytes)
	if err != nil {
		return err
	}

	// Decrement the reference count
	dstreamIDVal.Refcnt--

	// If reference count reaches zero, delete the data stream
	if dstreamIDVal.Refcnt == 0 {
		// Delete all file extents
		err = dsm.deleteDataStreamExtents(tx, streamID)
		if err != nil {
			return err
		}

		// Delete the data stream ID record
		// In a real implementation, this would remove the record from the B-tree
	} else {
		// Update the data stream ID record
		// In a real implementation, this would update the record in the B-tree
	}

	return ErrNotImplemented
}

// deleteDataStreamExtents deletes all extents for a data stream
func (dsm *DataStreamManager) deleteDataStreamExtents(tx *Transaction, streamID uint64) error {
	// Prepare a key for range iteration
	startKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | (APFSTypeFileExtent << ObjTypeShift),
		},
		LogicalAddr: 0,
	}

	endKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | ((APFSTypeFileExtent + 1) << ObjTypeShift),
		},
		LogicalAddr: 0,
	}

	// Convert keys to bytes
	startKeyBytes, _ := startKey.Serialize()
	endKeyBytes, _ := endKey.Serialize()

	// Iterate through file extents
	dsm.volume.fsTree.IterateRange(startKeyBytes, endKeyBytes, func(key, value []byte) bool {
		// Parse the file extent key
		extKey := &JFileExtentKey{}
		if err := extKey.Parse(key); err != nil {
			return true
		}

		// Parse the file extent value
		extVal := &JFileExtentVal{}
		if err := extVal.Parse(value); err != nil {
			return true
		}

		// In a real implementation, this would:
		// 1. Add an operation to the transaction to delete this extent
		// 2. If the extent is shared, decrement its reference count
		// 3. If the reference count reaches zero, free the physical blocks

		return true
	})

	return ErrNotImplemented
}

// GetDataStream gets a data stream by its ID
func (dsm *DataStreamManager) GetDataStream(streamID uint64) (*JDstream, error) {
	// Create a key for the data stream
	dstreamKey := &JDstreamIDKey{
		Hdr: JKey{
			ObjIDAndType: (streamID & ObjIDMask) | (APFSTypeDstreamID << ObjTypeShift),
		},
	}

	// Convert key to bytes
	keyBytes, err := dstreamKey.Serialize()
	if err != nil {
		return nil, err
	}

	// Search for the key
	valueBytes, err := dsm.volume.fsTree.Search(keyBytes)
	if err != nil {
		return nil, err
	}

	// Parse the value
	dstreamVal := &JDstreamIDVal{}
	err = dstreamVal.Parse(valueBytes)
	if err != nil {
		return nil, err
	}

	// Load the data stream information by examining the extents
	fd := &FileData{
		volume:      dsm.volume,
		inodeNumber: streamID,
		extents:     make([]DataExtent, 0),
	}

	err = fd.loadExtents()
	if err != nil {
		return nil, err
	}

	// Create a data stream with the calculated size
	var size uint64
	for _, extent := range fd.extents {
		extentEnd := extent.LogicalOffset + extent.Length
		if extentEnd > size {
			size = extentEnd
		}
	}

	dstream := &JDstream{
		Size:              size,
		AllocedSize:       size,
		DefaultCryptoID:   0,
		TotalBytesWritten: 0,
		TotalBytesRead:    0,
	}

	return dstream, nil
}

// AllocateExtent allocates a new extent for a file or data stream
func (dsm *DataStreamManager) AllocateExtent(tx *Transaction, ownerID uint64, length uint64) (*DataExtent, error) {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return nil, errors.New("invalid transaction")
	}

	// Check if length is valid
	if length == 0 {
		return nil, errors.New("invalid extent length")
	}

	// Round up to block size
	blockSize := dsm.volume.container.blockSize
	blocks := (length + uint64(blockSize) - 1) / uint64(blockSize)

	// Allocate blocks
	physAddr, err := dsm.volume.container.spaceman.AllocateBlocks(uint32(blocks))
	if err != nil {
		return nil, err
	}

	// Create the extent
	extent := &DataExtent{
		LogicalOffset: 0, // Caller must set this
		PhysicalStart: physAddr,
		Length:        blocks * uint64(blockSize),
		CryptoID:      0, // Caller must set this if needed
	}

	return extent, nil
}

// FreeExtent frees an extent
func (dsm *DataStreamManager) FreeExtent(tx *Transaction, extent *DataExtent) error {
	// Check if the transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// In a real implementation, this would:
	// 1. Add an operation to the transaction to free this extent
	// 2. If the extent is shared, decrement its reference count
	// 3. If the reference count reaches zero, free the physical blocks

	return ErrNotImplemented
}
