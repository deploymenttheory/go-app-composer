// https://newosxbook.com/DMG.html#ref1

package dmgutil

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourusername/fsutil"
)

const (
	// Magic signatures
	kolyMagic = "koly"
	mishMagic = "mish"

	// Block types
	blockTypeZeroFill = 0x00000000
	blockTypeRaw      = 0x00000001
	blockTypeIgnored  = 0x00000002
	blockTypeADC      = 0x80000004
	blockTypeZLib     = 0x80000005
	blockTypeBZip2    = 0x80000006
	blockTypeComment  = 0x7FFFFFFE
	blockTypeTerminal = 0xFFFFFFFF

	// Sector size is typically 512 bytes
	sectorSize = 512
)

// UUID represents a 128-bit identifier
type UUID [16]byte

// KolyTrailer represents the 512-byte trailer found at the end of DMG files
type KolyTrailer struct {
	Signature             [4]byte
	Version               uint32
	HeaderSize            uint32
	Flags                 uint32
	RunningDataForkOffset uint64
	DataForkOffset        uint64
	DataForkLength        uint64
	RsrcForkOffset        uint64
	RsrcForkLength        uint64
	SegmentNumber         uint32
	SegmentCount          uint32
	SegmentID             UUID
	DataChecksumType      uint32
	DataChecksumSize      uint32
	DataChecksum          [32]uint32
	XMLOffset             uint64
	XMLLength             uint64
	Reserved1             [120]byte
	ChecksumType          uint32
	ChecksumSize          uint32
	Checksum              [32]uint32
	ImageVariant          uint32
	SectorCount           uint64
	Reserved2             uint32
	Reserved3             uint32
	Reserved4             uint32
}

// MishHeader represents the block metadata for a partition
type MishHeader struct {
	Signature          uint32
	Version            uint32
	SectorNumber       uint64
	SectorCount        uint64
	DataOffset         uint64
	BuffersNeeded      uint32
	BlockDescriptors   uint32
	Reserved1          uint32
	Reserved2          uint32
	Reserved3          uint32
	Reserved4          uint32
	Reserved5          uint32
	Reserved6          uint32
	ChecksumType       uint32
	ChecksumSize       uint32
	Checksum           [32]uint32
	NumberOfBlockChunks uint32
}

// BLKXChunkEntry represents one chunk in a blkx table
type BLKXChunkEntry struct {
	EntryType        uint32
	Comment          uint32
	SectorNumber     uint64
	SectorCount      uint64
	CompressedOffset uint64
	CompressedLength uint64
}

// DMGPartition represents a partition in the DMG
type DMGPartition struct {
	Name       string
	ID         string
	Attributes string
	BlkxData   []byte
	MishHeader MishHeader
	Chunks     []BLKXChunkEntry
}

// XMLPropertyList is a simplified structure to parse the XML plist in the DMG
type XMLPropertyList struct {
	Dict struct {
		ResourceFork struct {
			Blkx []struct {
				Attributes string `xml:"Attributes"`
				CFName     string `xml:"CFName"`
				Data       string `xml:"Data"`
				ID         string `xml:"ID"`
				Name       string `xml:"Name"`
			} `xml:"blkx>dict"`
		} `xml:"resource-fork>dict"`
	} `xml:"dict"`
}

// DMGReader represents a DMG file reader
type DMGReader struct {
	file       *os.File
	kolyTrailer KolyTrailer
	xmlPlist    []byte
	partitions  []DMGPartition
	verbose     bool
}

// NewDMGReader creates a new DMG reader
func NewDMGReader(filename string, verbose bool) (*DMGReader, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}

	reader := &DMGReader{
		file:    file,
		verbose: verbose,
	}

	if err := reader.readKolyTrailer(); err != nil {
		file.Close()
		return nil, err
	}

	if err := reader.readXMLPlist(); err != nil {
		file.Close()
		return nil, err
	}

	if err := reader.parsePartitions(); err != nil {
		file.Close()
		return nil, err
	}

	return reader, nil
}

// Close closes the DMG reader
func (r *DMGReader) Close() error {
	return r.file.Close()
}

// GetPartitions returns the partitions in the DMG
func (r *DMGReader) GetPartitions() []DMGPartition {
	return r.partitions
}

// readKolyTrailer reads the koly trailer from the end of the file
func (r *DMGReader) readKolyTrailer() error {
	// Get file size
	fileInfo, err := r.file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}
	fileSize := fileInfo.Size()

	// Seek to the koly trailer (512 bytes from the end)
	_, err = r.file.Seek(fileSize-512, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to koly trailer: %v", err)
	}

	// Read and parse the koly trailer
	err = binary.Read(r.file, binary.BigEndian, &r.kolyTrailer)
	if err != nil {
		return fmt.Errorf("failed to read koly trailer: %v", err)
	}

	// Verify signature
	if string(r.kolyTrailer.Signature[:]) != kolyMagic {
		return errors.New("invalid koly signature")
	}

	if r.verbose {
		fmt.Printf("KOLY header found at %d:\n", fileSize-512)
		fmt.Printf("\tUDIF version %d, Header Size: %d\n", r.kolyTrailer.Version, r.kolyTrailer.HeaderSize)
		fmt.Printf("\tFlags: %d\n", r.kolyTrailer.Flags)
		if r.kolyTrailer.RsrcForkLength > 0 {
			fmt.Printf("\tRsrc fork: from %d, spanning %d bytes\n", r.kolyTrailer.RsrcForkOffset, r.kolyTrailer.RsrcForkLength)
		} else {
			fmt.Printf("\tRsrc fork: None\n")
		}
		fmt.Printf("\tData fork: from %d, spanning %d bytes\n", r.kolyTrailer.DataForkOffset, r.kolyTrailer.DataForkLength)
		fmt.Printf("\tXML plist: from %d, spanning %d bytes (to %d)\n", r.kolyTrailer.XMLOffset, r.kolyTrailer.XMLLength, r.kolyTrailer.XMLOffset+r.kolyTrailer.XMLLength)
		fmt.Printf("\tSegment #: %d, Count: %d\n", r.kolyTrailer.SegmentNumber, r.kolyTrailer.SegmentCount)
		fmt.Printf("\tSegment UUID: %s\n", formatUUID(r.kolyTrailer.SegmentID))
		fmt.Printf("\tRunning Data fork offset %d\n", r.kolyTrailer.RunningDataForkOffset)
		fmt.Printf("\tSectors: %d\n", r.kolyTrailer.SectorCount)
	}

	return nil
}

// readXMLPlist reads the XML property list from the DMG
func (r *DMGReader) readXMLPlist() error {
	r.xmlPlist = make([]byte, r.kolyTrailer.XMLLength)
	_, err := r.file.Seek(int64(r.kolyTrailer.XMLOffset), io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to XML plist: %v", err)
	}

	_, err = io.ReadFull(r.file, r.xmlPlist)
	if err != nil {
		return fmt.Errorf("failed to read XML plist: %v", err)
	}

	if r.verbose {
		fmt.Println("XML plist read successfully")
	}

	return nil
}

// parsePartitions parses the partitions from the XML plist
func (r *DMGReader) parsePartitions() error {
	var plist XMLPropertyList
	err := xml.Unmarshal(r.xmlPlist, &plist)
	if err != nil {
		return fmt.Errorf("failed to parse XML plist: %v", err)
	}

	if r.verbose {
		fmt.Printf("Found %d partitions\n", len(plist.Dict.ResourceFork.Blkx))
	}

	for _, blkx := range plist.Dict.ResourceFork.Blkx {
		partition := DMGPartition{
			Name:       blkx.Name,
			ID:         blkx.ID,
			Attributes: blkx.Attributes,
		}

		// Decode base64 data
		data, err := base64.StdEncoding.DecodeString(blkx.Data)
		if err != nil {
			return fmt.Errorf("failed to decode base64 data: %v", err)
		}
		partition.BlkxData = data

		// Parse mish header and chunks
		if len(data) >= 4 && string(data[:4]) == mishMagic {
			err = partition.parseMishHeader(data)
			if err != nil {
				return err
			}
		} else {
			if r.verbose {
				fmt.Printf("Partition %s does not have a mish header\n", partition.Name)
			}
			continue
		}

		r.partitions = append(r.partitions, partition)
	}

	return nil
}

// parseMishHeader parses the mish header and chunks from the blkx data
func (p *DMGPartition) parseMishHeader(data []byte) error {
	buf := bytes.NewReader(data)

	// Read mish header
	if err := binary.Read(buf, binary.BigEndian, &p.MishHeader); err != nil {
		return fmt.Errorf("failed to read mish header: %v", err)
	}

	// Verify mish signature
	sigBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sigBytes, p.MishHeader.Signature)
	if string(sigBytes) != mishMagic {
		return fmt.Errorf("invalid mish signature: %x", p.MishHeader.Signature)
	}

	// Read chunk entries
	chunkCount := p.MishHeader.NumberOfBlockChunks
	p.Chunks = make([]BLKXChunkEntry, chunkCount)
	for i := uint32(0); i < chunkCount; i++ {
		if err := binary.Read(buf, binary.BigEndian, &p.Chunks[i]); err != nil {
			return fmt.Errorf("failed to read chunk entry: %v", err)
		}
	}

	return nil
}

// ExtractPartition extracts a partition to the specified output file
func (r *DMGReader) ExtractPartition(partitionIndex int, outputPath string) error {
	if partitionIndex < 0 || partitionIndex >= len(r.partitions) {
		return fmt.Errorf("invalid partition index: %d", partitionIndex)
	}

	partition := r.partitions[partitionIndex]
	
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

	if r.verbose {
		fmt.Printf("Extracting partition %d (%s) to %s\n", partitionIndex, partition.Name, outputPath)
		fmt.Printf("Partition has %d chunks\n", len(partition.Chunks))
	}

	// Process all chunks
	buffer := make([]byte, sectorSize*256) // Buffer for reading/writing
	for i, chunk := range partition.Chunks {
		if chunk.EntryType == blockTypeTerminal {
			if r.verbose {
				fmt.Printf("Reached terminal block at chunk %d\n", i)
			}
			break
		}

		if chunk.EntryType == blockTypeComment || chunk.EntryType == blockTypeIgnored || chunk.SectorCount == 0 {
			continue
		}

		if r.verbose {
			fmt.Printf("Processing chunk %d: Type=0x%08x, Sectors=%d, Offset=%d, Length=%d\n",
				i, chunk.EntryType, chunk.SectorCount, chunk.CompressedOffset, chunk.CompressedLength)
		}

		// Seek to the chunk data
		_, err := r.file.Seek(int64(chunk.CompressedOffset), io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek to chunk data: %v", err)
		}

		// Read the compressed data
		compressedData := make([]byte, chunk.CompressedLength)
		_, err = io.ReadFull(r.file, compressedData)
		if err != nil {
			return fmt.Errorf("failed to read chunk data: %v", err)
		}

		// Process based on chunk type
		switch chunk.EntryType {
		case blockTypeZeroFill:
			// Fill with zeros
			zeroBuffer := make([]byte, chunk.SectorCount*sectorSize)
			_, err = output.Write(zeroBuffer)
			if err != nil {
				return fmt.Errorf("failed to write zero fill: %v", err)
			}

		case blockTypeRaw:
			// Raw data, no compression
			_, err = output.Write(compressedData)
			if err != nil {
				return fmt.Errorf("failed to write raw data: %v", err)
			}

		case blockTypeZLib:
			// zlib compressed data
			zr, err := zlib.NewReader(bytes.NewReader(compressedData))
			if err != nil {
				return fmt.Errorf("failed to create zlib reader: %v", err)
			}
			defer zr.Close()

			n, err := io.CopyBuffer(output, zr, buffer)
			if err != nil {
				return fmt.Errorf("failed to decompress zlib data: %v", err)
			}
			
			if r.verbose {
				fmt.Printf("Decompressed %d bytes of zlib data\n", n)
			}

		case blockTypeBZip2:
			// bzip2 compressed data
			bzr := bzip2.NewReader(bytes.NewReader(compressedData))
			
			n, err := io.CopyBuffer(output, bzr, buffer)
			if err != nil {
				return fmt.Errorf("failed to decompress bzip2 data: %v", err)
			}
			
			if r.verbose {
				fmt.Printf("Decompressed %d bytes of bzip2 data\n", n)
			}
			
		case blockTypeADC:
			return fmt.Errorf("ADC compression not implemented yet")

		default:
			return fmt.Errorf("unknown block type: 0x%08x", chunk.EntryType)
		}
	}

	if r.verbose {
		fmt.Println("Extraction completed successfully")
	}
	
	return nil
}

// ExtractAllPartitions extracts all partitions to the specified output directory
func (r *DMGReader) ExtractAllPartitions(outputDir string) error {
	// Create output directory if it doesn't exist
	if err := fsutil.CreateDirIfNotExists(outputDir); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	for i, partition := range r.partitions {
		// Skip certain system partitions that are not useful
		if strings.Contains(partition.Name, "Driver Descriptor Map") || 
		   strings.Contains(partition.Name, "partition_map") {
			if r.verbose {
				fmt.Printf("Skipping system partition: %s\n", partition.Name)
			}
			continue
		}

		// Create a safe filename from the partition name
		safeName := strings.Replace(partition.Name, " ", "_", -1)
		safeName = strings.Replace(safeName, "(", "", -1)
		safeName = strings.Replace(safeName, ")", "", -1)
		safeName = strings.Replace(safeName, ":", "_", -1)
		
		outputPath := filepath.Join(outputDir, fmt.Sprintf("%d_%s.bin", i, safeName))
		
		if err := r.ExtractPartition(i, outputPath); err != nil {
			return fmt.Errorf("failed to extract partition %d: %v", i, err)
		}
	}

	return nil
}

// MountPartition extracts a partition to a temporary location and returns the path
// This is useful for accessing the partition content without writing to disk permanently
func (r *DMGReader) MountPartition(partitionIndex int) (string, error) {
	if partitionIndex < 0 || partitionIndex >= len(r.partitions) {
		return "", fmt.Errorf("invalid partition index: %d", partitionIndex)
	}

	partition := r.partitions[partitionIndex]
	
	// Create temporary directory
	tempDir, err := fsutil.CreateTempDir("dmg_mount_")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %v", err)
	}
	
	// Create a safe filename from the partition name
	safeName := strings.Replace(partition.Name, " ", "_", -1)
	safeName = strings.Replace(safeName, "(", "", -1)
	safeName = strings.Replace(safeName, ")", "", -1)
	safeName = strings.Replace(safeName, ":", "_", -1)
	
	outputPath := filepath.Join(tempDir, fmt.Sprintf("%s.bin", safeName))
	
	// Extract partition to temporary location
	if err := r.ExtractPartition(partitionIndex, outputPath); err != nil {
		// Clean up on failure
		fsutil.DeleteDirRecursive(tempDir)
		return "", err
	}
	
	return outputPath, nil
}

// ExtractFile extracts a specific file from an HFS+ partition
// Note: This is a placeholder as HFS+ parsing would require additional implementation
func (r *DMGReader) ExtractFile(partitionIndex int, filePath, outputPath string) error {
	// This would require implementing HFS+ filesystem parsing
	// For now, return an error indicating this functionality is not implemented
	return fmt.Errorf("extracting specific files from HFS+ partitions is not implemented yet")
}

// ListPartitions lists all partitions in the DMG
func (r *DMGReader) ListPartitions() {
	fmt.Println("DMG Partitions:")
	fmt.Println("---------------------------------------------------")
	for i, partition := range r.partitions {
		fmt.Printf("%d: %s (ID: %s, Attributes: %s)\n", i, partition.Name, partition.ID, partition.Attributes)
		fmt.Printf("   Sectors: %d, Chunks: %d\n", partition.MishHeader.SectorCount, partition.MishHeader.NumberOfBlockChunks)
		fmt.Println("---------------------------------------------------")
	}
}

// PrintInfo prints detailed information about the DMG
func (r *DMGReader) PrintInfo() {
	fmt.Println("DMG File Information:")
	fmt.Println("---------------------------------------------------")
	fmt.Printf("UDIF Version: %d\n", r.kolyTrailer.Version)
	fmt.Printf("Header Size: %d\n", r.kolyTrailer.HeaderSize)
	fmt.Printf("Flags: 0x%08x\n", r.kolyTrailer.Flags)
	fmt.Printf("Data Fork Offset: %d\n", r.kolyTrailer.DataForkOffset)
	fmt.Printf("Data Fork Length: %d\n", r.kolyTrailer.DataForkLength)
	fmt.Printf("Resource Fork Offset: %d\n", r.kolyTrailer.RsrcForkOffset)
	fmt.Printf("Resource Fork Length: %d\n", r.kolyTrailer.RsrcForkLength)
	fmt.Printf("Segment Number: %d of %d\n", r.kolyTrailer.SegmentNumber, r.kolyTrailer.SegmentCount)
	fmt.Printf("Segment ID: %s\n", formatUUID(r.kolyTrailer.SegmentID))
	fmt.Printf("XML Offset: %d\n", r.kolyTrailer.XMLOffset)
	fmt.Printf("XML Length: %d\n", r.kolyTrailer.XMLLength)
	fmt.Printf("Sector Count: %d\n", r.kolyTrailer.SectorCount)
	fmt.Printf("Image Variant: %d\n", r.kolyTrailer.ImageVariant)
	fmt.Println("---------------------------------------------------")
	fmt.Printf("Total Partitions: %d\n", len(r.partitions))
	fmt.Println("---------------------------------------------------")
}

// GetCompressedSize returns the total compressed size of all partitions
func (r *DMGReader) GetCompressedSize() uint64 {
	var size uint64
	for _, partition := range r.partitions {
		for _, chunk := range partition.Chunks {
			size += chunk.CompressedLength
		}
	}
	return size
}

// GetUncompressedSize returns the total uncompressed size of all partitions
func (r *DMGReader) GetUncompressedSize() uint64 {
	var size uint64
	for _, partition := range r.partitions {
		for _, chunk := range partition.Chunks {
			size += chunk.SectorCount * sectorSize
		}
	}
	return size
}

// Utility function to format a UUID
func formatUUID(uuid UUID) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(uuid[0:4]),
		hex.EncodeToString(uuid[4:6]),
		hex.EncodeToString(uuid[6:8]),
		hex.EncodeToString(uuid[8:10]),
		hex.EncodeToString(uuid[10:16]))
}
