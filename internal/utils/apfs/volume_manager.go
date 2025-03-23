//
package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// Common error definitions for file system operations
var (
	ErrNotDirectory    = errors.New("not a directory")
	ErrNotFound        = errors.New("file or directory not found")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInvalidName     = errors.New("invalid file name")
	ErrIsDirectory     = errors.New("is a directory")
	ErrNotAFile        = errors.New("not a file")
)

// FileInfo holds information about a file or directory
type FileInfo struct {
	Name        string
	Size        int64
	Mode        uint16
	ModTime     time.Time
	IsDir       bool
	UID         uint32
	GID         uint32
	InodeNumber uint64
	Blocks      uint64
	Flags       uint32
	XattrNames  []string
}

// File represents an APFS file
type File struct {
	volume      *VolumeManager
	inodeNumber uint64
	inode       *JInodeVal
	info        *FileInfo
	extents     []FileExtent
	dataStream  *JDstream
	parent      uint64
	name        string
}

// Directory represents an APFS directory
type Directory struct {
	volume      *VolumeManager
	inodeNumber uint64
	inode       *JInodeVal
	info        *FileInfo
	entries     []*DirectoryEntry
	entriesMap  map[string]*DirectoryEntry
	parent      uint64
	name        string
}

// DirectoryEntry represents an entry in a directory
type DirectoryEntry struct {
	Name      string
	InodeNum  uint64
	Type      uint16
	DateAdded time.Time
	Parent    uint64
}

// FileExtent represents a contiguous range of blocks that make up a file
type FileExtent struct {
	LogicalAddr   uint64
	PhysicalBlock uint64
	Length        uint64
	CryptoID      uint64
}

// Mount completes the full mounting of a volume
func (vm *VolumeManager) Mount() error {
	// Initialize the object map
	err := vm.initObjectMap()
	if err != nil {
		return fmt.Errorf("failed to initialize volume object map: %w", err)
	}

	// Initialize the root file system tree
	err = vm.initFileSystemTree()
	if err != nil {
		return fmt.Errorf("failed to initialize file system tree: %w", err)
	}

	return nil
}

// initObjectMap initializes the volume's object map
func (vm *VolumeManager) initObjectMap() error {
	// Get the object map's OID from the superblock
	omapOID := vm.superblock.OMapOID

	// Resolve the object map through the container's object map
	omapData, err := vm.container.resolveObject(omapOID, vm.container.checkpoint.XID)
	if err != nil {
		return err
	}

	// Parse the object map
	omap := &OMapPhys{}
	if err := parseObjectFromBytes(omapData, omap); err != nil {
		return err
	}

	// Initialize the volume's object map
	vm.omap = &ObjectMap{
		physicalObj: omap,
	}

	// Initialize the B-tree
	btreeData, err := vm.resolveObject(omap.OmTreeOID, vm.container.checkpoint.XID)
	if err != nil {
		return err
	}

	vm.omap.btree, err = NewBTree(vm.container, btreeData)
	if err != nil {
		return err
	}

	return nil
}

// initFileSystemTree initializes the volume's file system tree
func (vm *VolumeManager) initFileSystemTree() error {
	// Get the root tree's OID from the superblock
	rootTreeOID := vm.superblock.RootTreeOID

	// Resolve the root tree through the volume's object map
	rootTreeData, err := vm.resolveObject(rootTreeOID, vm.container.checkpoint.XID)
	if err != nil {
		return err
	}

	// Initialize the file system B-tree
	fsTree, err := NewBTree(vm.container, rootTreeData)
	if err != nil {
		return err
	}

	vm.fsTree = fsTree
	return nil
}

// resolveObject resolves an object using the volume's object map
func (vm *VolumeManager) resolveObject(oid uint64, xid uint64) ([]byte, error) {
	// First try to resolve through the container
	objData, err := vm.container.resolveObject(oid, xid)
	if err == nil {
		return objData, nil
	}

	// If that fails, use the volume's object map
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
	valueBytes, err := vm.omap.btree.Search(keyBytes)
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
	return vm.container.readPhysicalObject(val.OvPaddr)
}

// GetRootDirectory returns the root directory of the volume
func (vm *VolumeManager) GetRootDirectory() (*Directory, error) {
	return vm.GetDirectoryByInode(RootDirInoNum)
}

// GetDirectoryByInode returns a directory by its inode number
func (vm *VolumeManager) GetDirectoryByInode(inodeNum uint64) (*Directory, error) {
	// Find the inode record
	inodeVal, err := vm.findInode(inodeNum)
	if err != nil {
		return nil, err
	}

	// Make sure it's a directory
	if (inodeVal.Mode & SIfmt) != SIfdir {
		return nil, ErrNotDirectory
	}

	// Create the directory object
	dir := &Directory{
		volume:      vm,
		inodeNumber: inodeNum,
		inode:       inodeVal,
		parent:      inodeVal.ParentID,
		name:        "", // Will be filled in for non-root directories
	}

	// Load the directory info
	info, err := vm.getFileInfo(inodeNum, inodeVal, "")
	if err != nil {
		return nil, err
	}
	dir.info = info

	// Load directory entries
	err = dir.loadEntries()
	if err != nil {
		return nil, err
	}

	return dir, nil
}

// findInode finds an inode by its number
func (vm *VolumeManager) findInode(inodeNum uint64) (*JInodeVal, error) {
	// Create the key for the inode record
	key := JKey{
		ObjIDAndType: (inodeNum & ObjIDMask) | (APFSTypeInode << ObjTypeShift),
	}

	// Convert key to bytes
	keyBytes, err := binary.Marshal(binary.LittleEndian, key)
	if err != nil {
		return nil, err
	}

	// Search the file system tree
	valueBytes, err := vm.fsTree.Search(keyBytes)
	if err != nil {
		return nil, ErrNotFound
	}

	// Parse the inode value
	inodeVal := &JInodeVal{}
	if err := binary.Unmarshal(valueBytes, binary.LittleEndian, inodeVal); err != nil {
		return nil, err
	}

	return inodeVal, nil
}

// getFileInfo extracts file information from an inode
func (vm *VolumeManager) getFileInfo(inodeNum uint64, inode *JInodeVal, name string) (*FileInfo, error) {
	// Determine file type
	fileType := inode.Mode & SIfmt
	isDir := fileType == SIfdir

	// Get size
	var size int64
	if !isDir {
		// Look for data stream extended field
		dstream, err := vm.getInodeDataStream(inode)
		if err == nil && dstream != nil {
			size = int64(dstream.Size)
		}
	}

	// Convert timestamps
	modTime := time.Unix(0, int64(inode.ModTime))

	// Create file info
	info := &FileInfo{
		Name:        name,
		Size:        size,
		Mode:        inode.Mode,
		ModTime:     modTime,
		IsDir:       isDir,
		UID:         inode.Owner,
		GID:         inode.Group,
		InodeNumber: inodeNum,
		Flags:       inode.BSDFlags,
	}

	// Get extended attribute names
	xattrNames, err := vm.getXattrNames(inodeNum)
	if err == nil {
		info.XattrNames = xattrNames
	}

	return info, nil
}

// getInodeDataStream extracts the data stream information from an inode
func (vm *VolumeManager) getInodeDataStream(inode *JInodeVal) (*JDstream, error) {
	// Check for extended fields
	xfBlobOffset := binary.Size(JInodeVal{})
	if xfBlobOffset >= len(inode) {
		return nil, errors.New("no extended fields")
	}

	// Parse the extended fields blob
	xfBlob := &XfBlob{}
	if err := binary.Read(bytes.NewReader(inode[xfBlobOffset:]), binary.LittleEndian, xfBlob); err != nil {
		return nil, err
	}

	// Look for a data stream field
	xfDataOffset := xfBlobOffset + binary.Size(XfBlob{})
	xfFieldSize := binary.Size(XField{})

	for i := 0; i < int(xfBlob.XfNumExts); i++ {
		fieldOffset := xfDataOffset + i*xfFieldSize
		
		field := &XField{}
		if err := binary.Read(bytes.NewReader(inode[fieldOffset:]), binary.LittleEndian, field); err != nil {
			continue
		}

		if field.XType == InoExtTypeDstream {
			// Found the data stream field
			dataOffset := xfDataOffset + int(xfBlob.XfNumExts)*xfFieldSize
			
			// Find the correct data offset
			for j := 0; j < i; j++ {
				prevField := &XField{}
				binary.Read(bytes.NewReader(inode[xfDataOffset+j*xfFieldSize:]), binary.LittleEndian, prevField)
				dataOffset += int(prevField.XSize)
				
				// Align to 8-byte boundary
				if dataOffset % 8 != 0 {
					dataOffset += 8 - (dataOffset % 8)
				}
			}
			
			// Read the data stream
			dstream := &JDstream{}
			if err := binary.Read(bytes.NewReader(inode[dataOffset:]), binary.LittleEndian, dstream); err != nil {
				return nil, err
			}
			
			return dstream, nil
		}
	}

	return nil, errors.New("data stream not found")
}

// getXattrNames returns the names of all extended attributes for an inode
func (vm *VolumeManager) getXattrNames(inodeNum uint64) ([]string, error) {
	var names []string

	// Prepare a key for range iteration
	startKey := JKey{
		ObjIDAndType: (inodeNum & ObjIDMask) | (APFSTypeXattr << ObjTypeShift),
	}
	endKey := JKey{
		ObjIDAndType: (inodeNum & ObjIDMask) | ((APFSTypeXattr + 1) << ObjTypeShift),
	}

	// Convert keys to bytes
	startKeyBytes, _ := binary.Marshal(binary.LittleEndian, startKey)
	endKeyBytes, _ := binary.Marshal(binary.LittleEndian, endKey)

	// Iterate through xattr records
	vm.fsTree.IterateRange(startKeyBytes, endKeyBytes, func(key, value []byte) bool {
		// Parse the xattr key
		xattrKey := &JXattrKey{}
		if err := binary.Unmarshal(key, binary.LittleEndian, xattrKey); err != nil {
			return true
		}

		// Extract the name
		nameOffset := binary.Size(JXattrKey{})
		nameLen := int(xattrKey.NameLen)
		if nameOffset+nameLen <= len(key) {
			name := string(key[nameOffset : nameOffset+nameLen-1]) // Remove null terminator
			names = append(names, name)
		}

		return true
	})

	return names, nil
}

// loadEntries loads the entries of a directory
func (dir *Directory) loadEntries() error {
	dir.entries = make([]*DirectoryEntry, 0)
	dir.entriesMap = make(map[string]*DirectoryEntry)

	// Prepare a key for range iteration
	startKey := JKey{
		ObjIDAndType: (dir.inodeNumber & ObjIDMask) | (APFSTypeDirRec << ObjTypeShift),
	}
	endKey := JKey{
		ObjIDAndType: (dir.inodeNumber & ObjIDMask) | ((APFSTypeDirRec + 1) << ObjTypeShift),
	}

	// Convert keys to bytes
	startKeyBytes, _ := binary.Marshal(binary.LittleEndian, startKey)
	endKeyBytes, _ := binary.Marshal(binary.LittleEndian, endKey)

	// Iterate through directory entries
	dir.volume.fsTree.IterateRange(startKeyBytes, endKeyBytes, func(key, value []byte) bool {
		// Parse the directory entry key
		drecKey := &JDrecKey{}
		if err := binary.Unmarshal(key, binary.LittleEndian, drecKey); err != nil {
			return true
		}

		// Extract the name
		nameOffset := binary.Size(JDrecKey{})
		nameLen := int(drecKey.NameLen)
		if nameOffset+nameLen > len(key) {
			return true
		}
		name := string(key[nameOffset : nameOffset+nameLen-1]) // Remove null terminator

		// Parse the directory entry value
		drecVal := &JDrecVal{}
		if err := binary.Unmarshal(value, binary.LittleEndian, drecVal); err != nil {
			return true
		}

		// Create directory entry
		entry := &DirectoryEntry{
			Name:      name,
			InodeNum:  drecVal.FileID,
			Type:      drecVal.Flags & DREC_TYPE_MASK,
			DateAdded: time.Unix(0, int64(drecVal.DateAdded)),
			Parent:    dir.inodeNumber,
		}

		dir.entries = append(dir.entries, entry)
		dir.entriesMap[name] = entry

		return true
	})

	return nil
}

// ListEntries returns all entries in the directory
func (dir *Directory) ListEntries() ([]*DirectoryEntry, error) {
	// If entries haven't been loaded yet, load them
	if dir.entries == nil {
		err := dir.loadEntries()
		if err != nil {
			return nil, err
		}
	}
	return dir.entries, nil
}

// Lookup finds a directory entry by name
func (dir *Directory) Lookup(name string) (*DirectoryEntry, error) {
	// If entries haven't been loaded yet, load them
	if dir.entriesMap == nil {
		err := dir.loadEntries()
		if err != nil {
			return nil, err
		}
	}

	entry, ok := dir.entriesMap[name]
	if !ok {
		return nil, ErrNotFound
	}
	return entry, nil
}

// GetFile returns a file by name from this directory
func (dir *Directory) GetFile(name string) (*File, error) {
	// Find the directory entry
	entry, err := dir.Lookup(name)
	if err != nil {
		return nil, err
	}

	// Check if it's a directory
	if entry.Type == DTDir {
		return nil, ErrIsDirectory
	}

	// Get the file
	return dir.volume.GetFileByInode(entry.InodeNum, name, dir.inodeNumber)
}

// GetDirectory returns a subdirectory by name
func (dir *Directory) GetDirectory(name string) (*Directory, error) {
	// Find the directory entry
	entry, err := dir.Lookup(name)
	if err != nil {
		return nil, err
	}

	// Check if it's a directory
	if entry.Type != DTDir {
		return nil, ErrNotDirectory
	}

	// Get the directory
	subdir, err := dir.volume.GetDirectoryByInode(entry.InodeNum)
	if err != nil {
		return nil, err
	}

	// Set the name and parent
	subdir.name = name
	subdir.parent = dir.inodeNumber

	return subdir, nil
}

// GetFileByPath returns a file by path
func (vm *VolumeManager) GetFileByPath(filePath string) (*File, error) {
	// Clean the path
	filePath = path.Clean(filePath)
	if filePath == "/" {
		return nil, ErrIsDirectory
	}

	// Split the path into directory and file name
	dir, fileName := path.Split(filePath)
	
	// Get the parent directory
	parentDir, err := vm.GetDirectoryByPath(dir)
	if err != nil {
		return nil, err
	}

	// Get the file from the parent directory
	return parentDir.GetFile(fileName)
}

// GetDirectoryByPath returns a directory by path
func (vm *VolumeManager) GetDirectoryByPath(dirPath string) (*Directory, error) {
	// Clean the path
	dirPath = path.Clean(dirPath)
	
	// Start at the root directory
	rootDir, err := vm.GetRootDirectory()
	if err != nil {
		return nil, err
	}

	// Handle root directory case
	if dirPath == "/" || dirPath == "" {
		return rootDir, nil
	}

	// Split the path into components
	components := strings.Split(strings.Trim(dirPath, "/"), "/")
	currentDir := rootDir

	// Traverse the path
	for _, component := range components {
		if component == "" {
			continue
		}

		// Handle special cases
		if component == "." {
			continue
		}
		if component == ".." {
			// Go to parent directory
			if currentDir.parent == 0 {
				// We're at the root, stay here
				continue
			}
			
			parentDir, err := vm.GetDirectoryByInode(currentDir.parent)
			if err != nil {
				return nil, err
			}
			currentDir = parentDir
			continue
		}

		// Regular directory
		nextDir, err := currentDir.GetDirectory(component)
		if err != nil {
			return nil, err
		}
		currentDir = nextDir
	}

	return currentDir, nil
}

// GetFileByInode returns a file by its inode number
func (vm *VolumeManager) GetFileByInode(inodeNum uint64, name string, parent uint64) (*File, error) {
	// Find the inode record
	inodeVal, err := vm.findInode(inodeNum)
	if err != nil {
		return nil, err
	}

	// Make sure it's not a directory
	if (inodeVal.Mode & SIfmt) == SIfdir {
		return nil, ErrIsDirectory
	}

	// Create the file object
	file := &File{
		volume:      vm,
		inodeNumber: inodeNum,
		inode:       inodeVal,
		parent:      parent,
		name:        name,
	}

	// Load the file info
	info, err := vm.getFileInfo(inodeNum, inodeVal, name)
	if err != nil {
		return nil, err
	}
	file.info = info

	// Load data stream
	dstream, err := vm.getInodeDataStream(inodeVal)
	if err == nil {
		file.dataStream = dstream
		
		// Load file extents
		err = file.loadExtents()
		if err != nil {
			return nil, err
		}
	}

	return file, nil
}

// loadExtents loads the file extents
func (file *File) loadExtents() error {
	file.extents = make([]FileExtent, 0)

	// Prepare a key for range iteration
	startKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (file.inodeNumber & ObjIDMask) | (APFSTypeFileExtent << ObjTypeShift),
		},
		LogicalAddr: 0,
	}
	endKey := JFileExtentKey{
		Hdr: JKey{
			ObjIDAndType: (file.inodeNumber & ObjIDMask) | ((APFSTypeFileExtent + 1) << ObjTypeShift),
		},
		LogicalAddr: 0,
	}

	// Convert keys to bytes
	startKeyBytes, _ := binary.Marshal(binary.LittleEndian, startKey)
	endKeyBytes, _ := binary.Marshal(binary.LittleEndian, endKey)

	// Iterate through file extents
	file.volume.fsTree.IterateRange(startKeyBytes, endKeyBytes, func(key, value []byte) bool {
		// Parse the file extent key
		extKey := &JFileExtentKey{}
		if err := binary.Unmarshal(key, binary.LittleEndian, extKey); err != nil {
			return true
		}

		// Parse the file extent value
		extVal := &JFileExtentVal{}
		if err := binary.Unmarshal(value, binary.LittleEndian, extVal); err != nil {
			return true
		}

		// Create file extent
		extent := FileExtent{
			LogicalAddr:   extKey.LogicalAddr,
			PhysicalBlock: extVal.PhysBlockNum,
			Length:        extVal.LenAndFlags & JFileExtentLenMask,
			CryptoID:      extVal.CryptoID,
		}

		file.extents = append(file.extents, extent)
		return true
	})

	// Sort extents by logical address
	// (they should already be sorted because of B-tree ordering)
	return nil
}

// Read reads data from the file
func (file *File) Read(offset int64, length int) ([]byte, error) {
	// Check if file has a data stream
	if file.dataStream == nil {
		return nil, errors.New("file has no data")
	}

	// Check if offset is beyond the end of the file
	if offset >= int64(file.dataStream.Size) {
		return nil, nil // EOF
	}

	// Adjust length if it would read past the end of the file
	if offset+int64(length) > int64(file.dataStream.Size) {
		length = int(int64(file.dataStream.Size) - offset)
	}

	// Allocate buffer for the data
	data := make([]byte, length)
	bytesRead := 0

	// Find extents that cover the requested range
	blockSize := int64(file.volume.container.blockSize)
	startBlock := offset / blockSize
	endBlock := (offset + int64(length) + blockSize - 1) / blockSize

	// Read from each extent
	for _, extent := range file.extents {
		// Check if this extent contains data we need
		extentStartBlock := int64(extent.LogicalAddr) / blockSize
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
			bufferOffset = 0
			extentOffset += (offset % blockSize)
			overlapLength -= (offset % blockSize)
		}
		
		if overlapEnd == endBlock && (offset+int64(length))%blockSize != 0 {
			overlapLength -= blockSize - ((offset+int64(length)) % blockSize)
		}

		// Read the data from the extent
		extentData, err := file.readExtent(extent, int64(extentOffset), int(overlapLength))
		if err != nil {
			return nil, err
		}

		// Copy to the output buffer
		copy(data[bufferOffset:bufferOffset+int64(len(extentData))], extentData)
		bytesRead += len(extentData)
	}

	return data[:bytesRead], nil
}

// readExtent reads data from a specific file extent
func (file *File) readExtent(extent FileExtent, offset int64, length int) ([]byte, error) {
	// Calculate physical offset
	physOffset := int64(extent.PhysicalBlock)*int64(file.volume.container.blockSize) + offset
	
	// Read the data
	data := make([]byte, length)
	
	_, err := file.volume.container.device.Seek(physOffset, io.SeekStart)
	if err != nil {
		return nil, err
	}
	
	_, err = io.ReadFull(file.volume.container.device, data)
	if err != nil {
		return nil, err
	}

	// Decrypt if necessary
	if file.info.IsEncrypted() && extent.CryptoID != 0 {
		// In a full implementation, we'd decrypt the data here
		// For now, just return the encrypted data
	}

	return data, nil
}

// GetInfo returns information about the file
func (file *File) GetInfo() *FileInfo {
	return file.info
}

// GetXattr gets an extended attribute
func (file *File) GetXattr(name string) ([]byte, error) {
	return file.volume.getXattr(file.inodeNumber, name)
}

// getXattr gets an extended attribute for an inode
func (vm *VolumeManager) getXattr(inodeNum uint64, name string) ([]byte, error) {
	// Create the key for the xattr record
	xattrKey := &JXattrKey{
		Hdr: JKey{
			ObjIDAndType: (inodeNum & ObjIDMask) | (APFSTypeXattr << ObjTypeShift),
		},
		NameLen: uint16(len(name) + 1), // +1 for null terminator
	}

	// Convert key to bytes
	keyBytes, err := binary.Marshal(binary.LittleEndian, xattrKey)
	if err != nil {
		return nil, err
	}

	// Append the name
	nameBytes := []byte(name + "\x00")
	keyBytes = append(keyBytes, nameBytes...)

	// Search the file system tree
	valueBytes, err := vm.fsTree.Search(keyBytes)
	if err != nil {
		return nil, ErrNotFound
	}

	// Parse the xattr value
	xattrVal := &JXattrVal{}
	if err := binary.Unmarshal(valueBytes, binary.LittleEndian, xattrVal); err != nil {
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
		// Data is in a data stream
		// In a full implementation, we'd read the data stream
		return nil, errors.New("xattr data streams not implemented")
	}

	return nil, errors.New("invalid xattr flags")
}

// IsEncrypted returns true if the file is encrypted
func (info *FileInfo) IsEncrypted() bool {
	// In a full implementation, check if the file has encrypted extents
	return false
}

// Return helpers
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
