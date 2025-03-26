// https://newosxbook.com/DMG.html#ref1

package dmgutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"
)

// HFS+ file system constants
const (
	// Magic signatures
	HFSPlusMagic = "H+"
	HFSXMagic    = "HX"

	// Block sizes
	DefaultBlockSize = 4096

	// File types
	HFSPlusFileType     = 0x0000 // Regular file
	HFSPlusFolderType   = 0x0001 // Directory
	HFSPlusAliasType    = 0x0002 // Alias/Symbolic link
	HFSPlusHardLinkType = 0x0003 // Hard link

	// Special file IDs
	HFSRootFolderID        = 2
	HFSRootParentFolderID  = 1
	HFSExtentsFileID       = 3
	HFSCatalogFileID       = 4
	HFSBadBlockFileID      = 5
	HFSAllocationFileID    = 6
	HFSStartupFileID       = 7
	HFSAttributesFileID    = 8
	HFSRepairCatalogFileID = 14
	HFSBogusExtentFileID   = 15
	HFSFirstUserCatalogID  = 16

	// B-tree node kinds
	kBTLeafNode   = -1
	kBTIndexNode  = 0
	kBTHeaderNode = 1
	kBTMapNode    = 2

	// Catalog file record types
	kHFSPlusFolderRecord       = 0x0001
	kHFSPlusFileRecord         = 0x0002
	kHFSPlusFolderThreadRecord = 0x0003
	kHFSPlusFileThreadRecord   = 0x0004
)

// HFSPlusVolumeHeader represents the volume header of an HFS+ file system
type HFSPlusVolumeHeader struct {
	Signature          [2]byte  // "H+" for HFS+, "HX" for HFSX
	Version            uint16   // Current version is 4 for HFS+
	Attributes         uint32   // Volume attributes
	LastMountedVersion uint32   // Implementation version that last mounted this volume
	JournalInfoBlock   uint32   // Journal info block (0 if no journal)
	CreateDate         uint32   // Date and time of volume creation (Mac OS format)
	ModifyDate         uint32   // Date and time of last modification
	BackupDate         uint32   // Date and time of last backup
	CheckedDate        uint32   // Date and time of last consistency check
	FileCount          uint32   // Number of files in the volume
	FolderCount        uint32   // Number of folders in the volume
	BlockSize          uint32   // Size of allocation blocks in bytes
	TotalBlocks        uint32   // Total number of allocation blocks
	FreeBlocks         uint32   // Number of unused allocation blocks
	NextAllocation     uint32   // Block number to start next allocation search
	ResourceClumpSize  uint32   // Default clump size for resource forks
	DataClumpSize      uint32   // Default clump size for data forks
	NextCatalogID      uint32   // Next unused catalog ID (for files and folders)
	WriteCount         uint32   // Number of times volume has been written to
	EncodingsBitmap    uint64   // Encoding bitmap (for text encoding conversions)
	FinderInfo         [32]byte // Information used by the Finder
	// Special file locations
	AllocationFile HFSPlusForkData // Location of allocation bitmap file
	ExtentsFile    HFSPlusForkData // Location of extents overflow file
	CatalogFile    HFSPlusForkData // Location of catalog file
	AttributesFile HFSPlusForkData // Location of attributes file
	StartupFile    HFSPlusForkData // Location of startup file
}

// HFSPlusForkData represents the on-disk location of a fork
type HFSPlusForkData struct {
	LogicalSize uint64                     // Fork's logical size in bytes
	ClumpSize   uint32                     // Fork's clump size in bytes
	TotalBlocks uint32                     // Total blocks used by this fork
	Extents     [8]HFSPlusExtentDescriptor // Initial set of extents
}

// HFSPlusExtentDescriptor describes the physical location of a contiguous chunk of blocks
type HFSPlusExtentDescriptor struct {
	StartBlock uint32 // First allocation block
	BlockCount uint32 // Number of allocation blocks
}

// HFSPlusCatalogKey is the key for catalog B-tree nodes
type HFSPlusCatalogKey struct {
	KeyLength      uint16
	ParentID       uint32
	NodeNameLength uint16
	NodeName       []uint16 // Unicode string
}

// HFSPlusBTNodeDescriptor represents a B-tree node descriptor
type HFSPlusBTNodeDescriptor struct {
	ForwardLink uint32 // Node number of next node
	BackLink    uint32 // Node number of previous node
	Kind        int16  // Kind of node (leaf, index, header, or map)
	Height      uint8  // Height from leaf (0 for leaf)
	NumRecords  uint16 // Number of records in this node
	Reserved    uint16 // Reserved - initialized as zero
}

// HFSPlusBTHeaderRecord represents a B-tree header record
type HFSPlusBTHeaderRecord struct {
	TreeDepth     uint16     // Current depth of the tree
	RootNode      uint32     // Node number of root node
	LeafRecords   uint32     // Number of leaf records in the tree
	FirstLeafNode uint32     // Node number of first leaf node
	LastLeafNode  uint32     // Node number of last leaf node
	NodeSize      uint16     // Size of a node in bytes
	MaxKeyLength  uint16     // Maximum length of a key
	TotalNodes    uint32     // Total number of nodes in the tree
	FreeNodes     uint32     // Number of free nodes
	Reserved1     uint16     // Reserved - initialized as zero
	ClumpSize     uint32     // Clump size
	BTreeType     uint8      // 0 for normal B-tree, 1 for index file
	Reserved2     uint8      // Reserved - initialized as zero
	Attributes    uint32     // Attributes of the B-tree
	Reserved3     [16]uint32 // Reserved - initialized as zero
}

// HFSPlusCatalogFolder represents a folder record in the catalog file
type HFSPlusCatalogFolder struct {
	RecordType       uint16                 // Record type (folder)
	Flags            uint16                 // Folder flags
	Valence          uint32                 // Number of files and folders in this folder
	FolderID         uint32                 // The unique folder ID
	CreateDate       uint32                 // Date and time of creation
	ContentModDate   uint32                 // Date and time of last content modification
	AttributeModDate uint32                 // Date and time of last attribute modification
	AccessDate       uint32                 // Date and time of last access
	BackupDate       uint32                 // Date and time of last backup
	Permissions      HFSPlusPermissions     // BSD permissions
	UserInfo         HFSPlusFolderInfo      // Finder information
	FinderInfo       HFSPlusFolderExtraInfo // More Finder information
	TextEncoding     uint32                 // Text encoding hint for filenames
	Reserved         uint32                 // Reserved - initialized as zero
}

// HFSPlusCatalogFile represents a file record in the catalog file
type HFSPlusCatalogFile struct {
	RecordType       uint16               // Record type (file)
	Flags            uint16               // File flags
	Reserved1        uint32               // Reserved - initialized as zero
	FileID           uint32               // The unique file ID
	CreateDate       uint32               // Date and time of creation
	ContentModDate   uint32               // Date and time of last content modification
	AttributeModDate uint32               // Date and time of last attribute modification
	AccessDate       uint32               // Date and time of last access
	BackupDate       uint32               // Date and time of last backup
	Permissions      HFSPlusPermissions   // BSD permissions
	UserInfo         HFSPlusFileInfo      // Finder information
	FinderInfo       HFSPlusFileExtraInfo // More Finder information
	TextEncoding     uint32               // Text encoding hint
	Reserved2        uint32               // Reserved - initialized as zero
	DataFork         HFSPlusForkData      // Data fork
	ResourceFork     HFSPlusForkData      // Resource fork
}

// Placeholder structs for Finder information
type HFSPlusFolderInfo struct {
	WindowBounds [8]byte
	Reserved1    uint16
	Flags        uint16
	Location     [4]byte
	Reserved2    uint16
}

type HFSPlusFolderExtraInfo struct {
	Reserved1           [4]byte
	ExtendedFinderFlags uint16
	Reserved2           uint16
	PutAwayFolderID     uint32
}

type HFSPlusFileInfo struct {
	FileType    [4]byte
	FileCreator [4]byte
	FinderFlags uint16
	Location    [4]byte
	Reserved1   uint16
}

type HFSPlusFileExtraInfo struct {
	Reserved1           [4]byte
	ExtendedFinderFlags uint16
	Reserved2           uint16
	PutAwayFolderID     uint32
}

type HFSPlusPermissions struct {
	OwnerID     uint32
	GroupID     uint32
	Permissions uint32
	Special     [4]byte
}

// HFSPlusParser represents a parser for HFS+ file systems
type HFSPlusParser struct {
	file            *os.File
	header          HFSPlusVolumeHeader
	blockSize       uint32
	catalogNodeSize uint16
}

// NewHFSPlusParser creates a new HFS+ parser from an extracted partition
func NewHFSPlusParser(partitionPath string) (*HFSPlusParser, error) {
	file, err := os.Open(partitionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open partition file: %v", err)
	}

	parser := &HFSPlusParser{
		file: file,
	}

	// Read volume header (1024 bytes from the start of the partition)
	if _, err := file.Seek(1024, io.SeekStart); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to seek to volume header: %v", err)
	}

	if err := binary.Read(file, binary.BigEndian, &parser.header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to read volume header: %v", err)
	}

	// Verify signature
	signature := string(parser.header.Signature[:])
	if signature != HFSPlusMagic && signature != HFSXMagic {
		file.Close()
		return nil, fmt.Errorf("invalid HFS+ signature: %s", signature)
	}

	parser.blockSize = parser.header.BlockSize

	// Read catalog file header to get node size
	catalogStart := parser.header.CatalogFile.Extents[0].StartBlock * parser.blockSize
	if _, err := file.Seek(int64(catalogStart), io.SeekStart); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to seek to catalog file: %v", err)
	}

	var nodeDescriptor HFSPlusBTNodeDescriptor
	if err := binary.Read(file, binary.BigEndian, &nodeDescriptor); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to read node descriptor: %v", err)
	}

	if nodeDescriptor.Kind != kBTHeaderNode {
		file.Close()
		return nil, fmt.Errorf("catalog file does not start with a header node")
	}

	var headerRecord HFSPlusBTHeaderRecord
	// Skip forward link, backlink, etc. (14 bytes) + 2 bytes
	if _, err := file.Seek(int64(catalogStart)+14+2, io.SeekStart); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to seek to header record: %v", err)
	}

	if err := binary.Read(file, binary.BigEndian, &headerRecord); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to read header record: %v", err)
	}

	parser.catalogNodeSize = headerRecord.NodeSize

	return parser, nil
}

// Close closes the HFS+ parser
func (p *HFSPlusParser) Close() error {
	return p.file.Close()
}

// ListFiles lists all files in the HFS+ volume
func (p *HFSPlusParser) ListFiles(rootPath string) ([]string, error) {
	var files []string

	// Start from the root directory (ID = 2)
	err := p.traverseDirectory(HFSRootFolderID, rootPath, &files)
	if err != nil {
		return nil, err
	}

	return files, nil
}

// traverseDirectory recursively traverses a directory and collects file paths
func (p *HFSPlusParser) traverseDirectory(dirID uint32, path string, files *[]string) error {
	entries, err := p.readDirectoryEntries(dirID)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name)

		if entry.IsDirectory {
			// Recursively traverse subdirectory
			err := p.traverseDirectory(entry.ID, entryPath, files)
			if err != nil {
				return err
			}
		} else {
			// Add file to the list
			*files = append(*files, entryPath)
		}
	}

	return nil
}

// DirectoryEntry represents a file or directory in the HFS+ volume
type DirectoryEntry struct {
	ID             uint32
	Name           string
	IsDirectory    bool
	DataLength     uint64
	ResourceLength uint64
	CreateDate     time.Time
	ModifyDate     time.Time
	DataFork       HFSPlusForkData
	ResourceFork   HFSPlusForkData
}

// readDirectoryEntries reads all entries in a directory
func (p *HFSPlusParser) readDirectoryEntries(dirID uint32) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry

	// Find the B-tree leaf nodes containing the directory entries
	// This is a simplified implementation - in a full version, we would traverse
	// the B-tree properly starting from the root node

	// For now, we'll read the catalog file sequentially and look for records with the given parent ID
	catalogExtent := p.header.CatalogFile.Extents[0]
	catalogStart := catalogExtent.StartBlock * p.blockSize
	catalogBlocks := catalogExtent.BlockCount

	// Read the entire catalog file into memory (not efficient for large volumes, but simpler for now)
	catalogSize := catalogBlocks * p.blockSize
	catalogData := make([]byte, catalogSize)

	if _, err := p.file.Seek(int64(catalogStart), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to catalog file: %v", err)
	}

	if _, err := io.ReadFull(p.file, catalogData); err != nil {
		return nil, fmt.Errorf("failed to read catalog file: %v", err)
	}

	// Process each node in the catalog file
	nodeOffset := uint32(0)
	for nodeOffset < catalogSize {
		var nodeDescriptor HFSPlusBTNodeDescriptor
		nodeReader := bytes.NewReader(catalogData[nodeOffset:])

		if err := binary.Read(nodeReader, binary.BigEndian, &nodeDescriptor); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read node descriptor: %v", err)
		}

		// Only process leaf nodes
		if nodeDescriptor.Kind == kBTLeafNode {
			// Process each record in the node
			for i := uint16(0); i < nodeDescriptor.NumRecords; i++ {
				// Calculate the offset of the record
				// The record offsets are stored at the end of the node
				recordOffsetPos := nodeOffset + uint32(p.catalogNodeSize) - uint32(i+1)*2

				if recordOffsetPos >= catalogSize {
					return nil, fmt.Errorf("record offset position out of bounds")
				}

				recordOffset := binary.BigEndian.Uint16(catalogData[recordOffsetPos:])
				recordPos := nodeOffset + uint32(recordOffset)

				if recordPos >= catalogSize {
					return nil, fmt.Errorf("record position out of bounds")
				}

				// Read the key length and parent ID
				keyLength := binary.BigEndian.Uint16(catalogData[recordPos:])
				parentID := binary.BigEndian.Uint32(catalogData[recordPos+2:])

				// Only process records for our directory
				if parentID == dirID {
					// Read the name length and name
					nameLength := binary.BigEndian.Uint16(catalogData[recordPos+6:])
					nameBytes := catalogData[recordPos+8 : recordPos+8+uint32(nameLength*2)]

					// Convert from UTF-16BE to string
					nameRunes := make([]uint16, nameLength)
					for j := uint16(0); j < nameLength; j++ {
						nameRunes[j] = binary.BigEndian.Uint16(nameBytes[j*2:])
					}
					name := string(utf16.Decode(nameRunes))

					// Skip the key to get to the record data
					recordDataPos := recordPos + 8 + uint32(nameLength*2)

					// Read the record type
					recordType := binary.BigEndian.Uint16(catalogData[recordDataPos:])

					switch recordType {
					case kHFSPlusFolderRecord:
						// Parse folder record
						var folderRecord HFSPlusCatalogFolder
						folderReader := bytes.NewReader(catalogData[recordDataPos:])
						if err := binary.Read(folderReader, binary.BigEndian, &folderRecord); err != nil {
							return nil, fmt.Errorf("failed to read folder record: %v", err)
						}

						entries = append(entries, DirectoryEntry{
							ID:          folderRecord.FolderID,
							Name:        name,
							IsDirectory: true,
							CreateDate:  macTimeToUnixTime(folderRecord.CreateDate),
							ModifyDate:  macTimeToUnixTime(folderRecord.ContentModDate),
						})

					case kHFSPlusFileRecord:
						// Parse file record
						var fileRecord HFSPlusCatalogFile
						fileReader := bytes.NewReader(catalogData[recordDataPos:])
						if err := binary.Read(fileReader, binary.BigEndian, &fileRecord); err != nil {
							return nil, fmt.Errorf("failed to read file record: %v", err)
						}

						entries = append(entries, DirectoryEntry{
							ID:             fileRecord.FileID,
							Name:           name,
							IsDirectory:    false,
							DataLength:     fileRecord.DataFork.LogicalSize,
							ResourceLength: fileRecord.ResourceFork.LogicalSize,
							CreateDate:     macTimeToUnixTime(fileRecord.CreateDate),
							ModifyDate:     macTimeToUnixTime(fileRecord.ContentModDate),
							DataFork:       fileRecord.DataFork,
							ResourceFork:   fileRecord.ResourceFork,
						})
					}
				}
			}
		}

		// Move to the next node
		nodeOffset += uint32(p.catalogNodeSize)
	}

	return entries, nil
}

// ExtractFile extracts a file from the HFS+ volume
func (p *HFSPlusParser) ExtractFile(filePath string, outputPath string) error {
	// Split the file path into components
	components := strings.Split(filePath, string(filepath.Separator))

	// Remove empty components
	var cleanComponents []string
	for _, component := range components {
		if component != "" {
			cleanComponents = append(cleanComponents, component)
		}
	}

	// Start from the root directory
	currentDirID := HFSRootFolderID

	// Traverse the path one component at a time
	for i, component := range cleanComponents {
		isLastComponent := i == len(cleanComponents)-1

		// Read current directory entries
		entries, err := p.readDirectoryEntries(currentDirID)
		if err != nil {
			return fmt.Errorf("failed to read directory entries: %v", err)
		}

		// Look for the current path component
		var found bool
		for _, entry := range entries {
			if entry.Name == component {
				if isLastComponent {
					// This is the file we're looking for
					if entry.IsDirectory {
						return fmt.Errorf("path points to a directory, not a file")
					}

					// Extract the file
					return p.extractFileData(entry, outputPath)
				} else {
					// This is an intermediate directory
					if !entry.IsDirectory {
						return fmt.Errorf("path component is a file, not a directory")
					}

					// Continue with the next directory
					currentDirID = entry.ID
					found = true
					break
				}
			}
		}

		if !found {
			return fmt.Errorf("path component not found: %s", component)
		}
	}

	return fmt.Errorf("file not found: %s", filePath)
}

// extractFileData extracts a file's data to the output path
func (p *HFSPlusParser) extractFileData(entry DirectoryEntry, outputPath string) error {
	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPath)
	if err := fsutil.CreateDirIfNotExists(outputDir); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create output file
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer output.Close()

	// Extract data fork
	if entry.DataLength > 0 {
		// Process each extent in the data fork
		for _, extent := range entry.DataFork.Extents {
			if extent.BlockCount == 0 {
				continue
			}

			// Calculate extent start and size
			extentStart := extent.StartBlock * p.blockSize
			extentSize := extent.BlockCount * p.blockSize

			// Seek to extent start
			if _, err := p.file.Seek(int64(extentStart), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to extent: %v", err)
			}

			// Read and write extent data
			buffer := make([]byte, 65536) // 64KB buffer
			remaining := extentSize

			for remaining > 0 {
				readSize := remaining
				if readSize > uint32(len(buffer)) {
					readSize = uint32(len(buffer))
				}

				n, err := p.file.Read(buffer[:readSize])
				if err != nil {
					if err == io.EOF {
						break
					}
					return fmt.Errorf("failed to read extent data: %v", err)
				}

				if _, err := output.Write(buffer[:n]); err != nil {
					return fmt.Errorf("failed to write to output file: %v", err)
				}

				remaining -= uint32(n)
			}
		}
	}

	// If there's a resource fork, we could extract it to a separate file
	// For now, we'll just focus on the data fork

	return nil
}

// macTimeToUnixTime converts a Mac OS timestamp to Unix time
func macTimeToUnixTime(macTime uint32) time.Time {
	// Mac OS time starts from January 1, 1904
	// Unix time starts from January 1, 1970
	// The difference is 2,082,844,800 seconds
	unixTime := int64(macTime) - 2082844800
	return time.Unix(unixTime, 0)
}

// ExtractFileToReader extracts a file and returns a reader for its content
func (p *HFSPlusParser) ExtractFileToReader(filePath string) (io.ReadCloser, error) {
	// Create a pipe for reading file data
	pr, pw := io.Pipe()

	// Extract file data in a goroutine
	go func() {
		defer pw.Close()

		// Split the file path into components
		components := strings.Split(filePath, string(filepath.Separator))

		// Remove empty components
		var cleanComponents []string
		for _, component := range components {
			if component != "" {
				cleanComponents = append(cleanComponents, component)
			}
		}

		// Start from the root directory
		currentDirID := HFSRootFolderID

		// Traverse the path one component at a time
		for i, component := range cleanComponents {
			isLastComponent := i == len(cleanComponents)-1

			// Read current directory entries
			entries, err := p.readDirectoryEntries(currentDirID)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to read directory entries: %v", err))
				return
			}

			// Look for the current path component
			var found bool
			for _, entry := range entries {
				if entry.Name == component {
					if isLastComponent {
						// This is the file we're looking for
						if entry.IsDirectory {
							pw.CloseWithError(fmt.Errorf("path points to a directory, not a file"))
							return
						}

						// Extract the file to the pipe
						if err := p.writeFileDataToPipe(entry, pw); err != nil {
							pw.CloseWithError(err)
						}
						return
					} else {
						// This is an intermediate directory
						if !entry.IsDirectory {
							pw.CloseWithError(fmt.Errorf("path component is a file, not a directory"))
							return
						}

						// Continue with the next directory
						currentDirID = entry.ID
						found = true
						break
					}
				}
			}

			if !found {
				pw.CloseWithError(fmt.Errorf("path component not found: %s", component))
				return
			}
		}

		pw.CloseWithError(fmt.Errorf("file not found: %s", filePath))
	}()

	return pr, nil
}

// writeFileDataToPipe writes a file's data to a pipe
func (p *HFSPlusParser) writeFileDataToPipe(entry DirectoryEntry, pipe io.Writer) error {
	// Extract data fork
	if entry.DataLength > 0 {
		// Process each extent in the data fork
		for _, extent := range entry.DataFork.Extents {
			if extent.BlockCount == 0 {
				continue
			}

			// Calculate extent start and size
			extentStart := extent.StartBlock * p.blockSize
			extentSize := extent.BlockCount * p.blockSize

			// Seek to extent start
			if _, err := p.file.Seek(int64(extentStart), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to extent: %v", err)
			}

			// Read and write extent data
			buffer := make([]byte, 65536) // 64KB buffer
			remaining := extentSize

			for remaining > 0 {
				readSize := remaining
				if readSize > uint32(len(buffer)) {
					readSize = uint32(len(buffer))
				}

				n, err := p.file.Read(buffer[:readSize])
				if err != nil {
					if err == io.EOF {
						break
					}
					return fmt.Errorf("failed to read extent data: %v", err)
				}

				if _, err := pipe.Write(buffer[:n]); err != nil {
					return fmt.Errorf("failed to write to pipe: %v", err)
				}

				remaining -= uint32(n)
			}
		}
	}

	return nil
}
