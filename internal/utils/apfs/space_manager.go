// space_manager.go
/*
spaceman_phys_t: Core structure managing disk-space allocation.

chunk_info_t: Structure describing individual chunk information.

chunk_info_block: Container of multiple chunk_info_t entries.

spaceman_free_queue_t / spaceman_free_queue_entry_t: Managing freed space and blocks to be reclaimed.

spaceman_device_t: Device-specific space manager information.
*/
package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Additional error definitions for space management
var (
	ErrNoFreeSpace    = errors.New("no free space available")
	ErrBlockInUse     = errors.New("block is already in use")
	ErrInvalidAddress = errors.New("invalid block address")
	ErrQuotaExceeded  = errors.New("volume quota exceeded")
)

// SpaceManager handles allocation and deallocation of blocks
type SpaceManager struct {
	container       *ContainerManager
	spaceman        *SpacemanPhys
	cibAddrBlocks   map[uint32]*CIBAddrBlock
	cibBlocks       map[uint64]*ChunkInfoBlock
	bitmapBlocks    map[uint64][]byte
	freeQueueBlocks map[uint64]map[uint64]uint64
	internalPool    *InternalPoolManager
}

// InternalPoolManager manages the container's internal pool bitmap
type InternalPoolManager struct {
	spaceman      *SpaceManager
	bitmapBase    uint64
	bitmapBlocks  uint32
	bitmapSize    uint32
	freeHead      uint16
	freeTail      uint16
	xidOffset     uint32
	bitmapOffset  uint32
	freeNextOffset uint32
}

// NewSpaceManager creates a new space manager for the container
func NewSpaceManager(container *ContainerManager) (*SpaceManager, error) {
	// Get the space manager object ID from the container superblock
	spacemanOID := container.superblock.SpacemanOID
	
	// Check if space manager exists
	if spacemanOID == 0 {
		return nil, errors.New("space manager not found")
	}
	
	// Resolve the space manager object
	spacemanData, err := container.resolveObject(spacemanOID, container.checkpoint.XID)
	if err != nil {
		return nil, err
	}
	
	// Parse the space manager
	spaceman := &SpacemanPhys{}
	err = parseObjectFromBytes(spacemanData, spaceman)
	if err != nil {
		return nil, err
	}
	
	// Create the space manager
	sm := &SpaceManager{
		container:       container,
		spaceman:        spaceman,
		cibAddrBlocks:   make(map[uint32]*CIBAddrBlock),
		cibBlocks:       make(map[uint64]*ChunkInfoBlock),
		bitmapBlocks:    make(map[uint64][]byte),
		freeQueueBlocks: make(map[uint64]map[uint64]uint64),
	}
	
	// Initialize the internal pool manager
	sm.internalPool = &InternalPoolManager{
		spaceman:      sm,
		bitmapBase:    spaceman.IPBmBase,
		bitmapBlocks:  spaceman.IPBmBlockCount,
		bitmapSize:    spaceman.IPBmSizeInBlocks,
		freeHead:      spaceman.IPBmFreeHead,
		freeTail:      spaceman.IPBmFreeTail,
		xidOffset:     spaceman.IPBmXidOffset,
		bitmapOffset:  spaceman.IPBitmapOffset,
		freeNextOffset: spaceman.IPBmFreeNextOffset,
	}
	
	return sm, nil
}

// AllocateBlock allocates a new block from the container
func (sm *SpaceManager) AllocateBlock() (uint64, error) {
	// First, try to allocate from the internal pool
	addr, err := sm.internalPool.AllocateBlock()
	if err == nil {
		return addr, nil
	}
	
	// If internal pool allocation failed, try main device
	addr, err = sm.allocateBlockFromDevice(SD_MAIN)
	if err == nil {
		return addr, nil
	}
	
	// If main device allocation failed and we have a Fusion drive, try tier2
	if (sm.container.superblock.IncompatFeatures & NX_INCOMPAT_FUSION) != 0 {
		addr, err = sm.allocateBlockFromDevice(SD_TIER2)
		if err == nil {
			return addr, nil
		}
	}
	
	return 0, ErrNoFreeSpace
}

// allocateBlockFromDevice allocates a block from a specific device tier
func (sm *SpaceManager) allocateBlockFromDevice(tier uint32) (uint64, error) {
	// Get device info
	dev := &sm.spaceman.Smdev[tier]
	
	// Check if there's free space
	if dev.SmFreeCount == 0 {
		return 0, ErrNoFreeSpace
	}
	
	// Try to find a free chunk from the bitmap
	// In a full implementation, this would:
	// 1. Find a chunk with free space
	// 2. Find a free block in that chunk's bitmap
	// 3. Mark the block as used
	// 4. Update free space count
	
	// For simplicity, we'll just search all chunks
	for i := uint32(0); i < dev.SmCibCount; i++ {
		// Get CIB block
		cib, err := sm.getCIBBlock(tier, i)
		if err != nil {
			continue
		}
		
		// Check each chunk in the CIB
		for j := uint32(0); j < cib.CibChunkInfoCount; j++ {
			chunk := &cib.CibChunkInfo[j]
			
			// Skip if no free blocks
			if chunk.CiFreeCount == 0 {
				continue
			}
			
			// Get the bitmap for this chunk
			bitmap, err := sm.getChunkBitmap(chunk.CiBitmapAddr)
			if err != nil {
				continue
			}
			
			// Find a free bit in the bitmap
			for k := uint32(0); k < chunk.CiBlockCount; k++ {
				byteIndex := k / 8
				bitIndex := k % 8
				
				// Check if bit is free (0)
				if (bitmap[byteIndex] & (1 << bitIndex)) == 0 {
					// Set the bit (mark as used)
					bitmap[byteIndex] |= (1 << bitIndex)
					
					// Update free count
					chunk.CiFreeCount--
					dev.SmFreeCount--
					
					// Calculate block address
					addr := chunk.CiAddr + uint64(k)
					
					// Write updated bitmap back to disk
					err = sm.writeChunkBitmap(chunk.CiBitmapAddr, bitmap)
					if err != nil {
						return 0, err
					}
					
					return addr, nil
				}
			}
		}
	}
	
	return 0, ErrNoFreeSpace
}

// getCIBBlock gets a chunk info block
func (sm *SpaceManager) getCIBBlock(tier uint32, index uint32) (*ChunkInfoBlock, error) {
	// Check cache first
	addr, err := sm.getCIBBlockAddr(tier, index)
	if err != nil {
		return nil, err
	}
	
	if cib, ok := sm.cibBlocks[addr]; ok {
		return cib, nil
	}
	
	// Read the block
	blockData, err := sm.container.readPhysicalObject(addr)
	if err != nil {
		return nil, err
	}
	
	// Parse the block
	cib := &ChunkInfoBlock{}
	err = parseObjectFromBytes(blockData, &cib.CibO)
	if err != nil {
		return nil, err
	}
	
	// Make sure it's a CIB
	if cib.CibO.GetObjectType() != ObjectTypeSpacemanCIB {
		return nil, errors.New("not a CIB block")
	}
	
	// Read index and count
	reader := bytes.NewReader(blockData[binary.Size(ObjectPhys{}):])
	binary.Read(reader, binary.LittleEndian, &cib.CibIndex)
	binary.Read(reader, binary.LittleEndian, &cib.CibChunkInfoCount)
	
	// Read chunk info entries
	cib.CibChunkInfo = make([]ChunkInfo, cib.CibChunkInfoCount)
	for i := uint32(0); i < cib.CibChunkInfoCount; i++ {
		binary.Read(reader, binary.LittleEndian, &cib.CibChunkInfo[i])
	}
	
	// Cache the block
	sm.cibBlocks[addr] = cib
	
	return cib, nil
}

// getCIBBlockAddr gets the address of a chunk info block
func (sm *SpaceManager) getCIBBlockAddr(tier uint32, index uint32) (uint64, error) {
	// Get device info
	dev := &sm.spaceman.Smdev[tier]
	
	// Check if index is valid
	if index >= dev.SmCibCount {
		return 0, fmt.Errorf("CIB index out of range: %d", index)
	}
	
	// Calculate CAB index and offset
	cabIndex := index / sm.spaceman.ChunksPerCib
	cibOffset := index % sm.spaceman.ChunksPerCib
	
	// Get CAB
	cab, err := sm.getCABBlock(tier, cabIndex)
	if err != nil {
		return 0, err
	}
	
	// Get CIB address
	if cibOffset >= uint32(len(cab.CabCibAddr)) {
		return 0, fmt.Errorf("CIB offset out of range: %d", cibOffset)
	}
	
	return cab.CabCibAddr[cibOffset], nil
}

// getCABBlock gets a chunk-info address block
func (sm *SpaceManager) getCABBlock(tier uint32, index uint32) (*CIBAddrBlock, error) {
	// Check cache first
	cacheKey := (tier << 16) | index
	if cab, ok := sm.cibAddrBlocks[cacheKey]; ok {
		return cab, nil
	}
	
	// Get device info
	dev := &sm.spaceman.Smdev[tier]
	
	// Check if index is valid
	if index >= dev.SmCabCount {
		return nil, fmt.Errorf("CAB index out of range: %d", index)
	}
	
	// Calculate address
	addrOffset := dev.SmAddrOffset + index
	
	// Read the block
	blockData, err := sm.container.readPhysicalObject(uint64(addrOffset))
	if err != nil {
		return nil, err
	}
	
	// Parse the block
	cab := &CIBAddrBlock{}
	err = parseObjectFromBytes(blockData, &cab.CabO)
	if err != nil {
		return nil, err
	}
	
	// Make sure it's a CAB
	if cab.CabO.GetObjectType() != ObjectTypeSpacemanCAB {
		return nil, errors.New("not a CAB block")
	}
	
	// Read index and count
	reader := bytes.NewReader(blockData[binary.Size(ObjectPhys{}):])
	binary.Read(reader, binary.LittleEndian, &cab.CabIndex)
	binary.Read(reader, binary.LittleEndian, &cab.CabCibCount)
	
	// Read CIB addresses
	cab.CabCibAddr = make([]uint64, cab.CabCibCount)
	for i := uint32(0); i < cab.CabCibCount; i++ {
		binary.Read(reader, binary.LittleEndian, &cab.CabCibAddr[i])
	}
	
	// Cache the block
	sm.cibAddrBlocks[cacheKey] = cab
	
	return cab, nil
}

// getChunkBitmap gets the bitmap for a chunk
func (sm *SpaceManager) getChunkBitmap(addr uint64) ([]byte, error) {
	// Check cache first
	if bitmap, ok := sm.bitmapBlocks[addr]; ok {
		return bitmap, nil
	}
	
	// Read the block
	blockData, err := sm.container.readPhysicalObject(addr)
	if err != nil {
		return nil, err
	}
	
	// Extract bitmap data
	// In a real implementation, we'd check if it's a bitmap block
	
	// Cache and return
	sm.bitmapBlocks[addr] = blockData
	return blockData, nil
}

// writeChunkBitmap writes the bitmap for a chunk
func (sm *SpaceManager) writeChunkBitmap(addr uint64, bitmap []byte) error {
	// In a real implementation, this would write the bitmap to disk
	// For now, just update the cache
	sm.bitmapBlocks[addr] = bitmap
	return nil
}

// FreeBlock frees a block back to the container
func (sm *SpaceManager) FreeBlock(addr uint64, immediate bool) error {
	// Check if the address is valid
	if addr == 0 || addr >= sm.container.superblock.BlockCount {
		return ErrInvalidAddress
	}
	
	// Check if it's an internal pool address
	if addr >= sm.spaceman.IPBase && addr < sm.spaceman.IPBase+uint64(sm.spaceman.IPBlockCount) {
		return sm.internalPool.FreeBlock(addr)
	}
	
	// For Fusion drives, determine which tier
	tier := SD_MAIN
	if (sm.container.superblock.IncompatFeatures & NX_INCOMPAT_FUSION) != 0 {
		// Check if it's on tier2
		tier2Marker := FUSION_TIER2_DEVICE_BLOCK_ADDR(sm.container.blockSize)
		if addr & tier2Marker != 0 {
			tier = SD_TIER2
			addr &= ^tier2Marker // Clear tier bit
		}
	}
	
	// If immediate, free directly to bitmap
	if immediate {
		return sm.freeToBitmap(addr, tier)
	}
	
	// Otherwise, add to free queue
	return sm.addToFreeQueue(addr, tier)
}

// freeToBitmap frees a block directly in the bitmap
func (sm *SpaceManager) freeToBitmap(addr uint64, tier uint32) error {
	// Find the chunk containing this address
	dev := &sm.spaceman.Smdev[tier]
	
	// Calculate chunk parameters
	blocksPerChunk := sm.spaceman.BlocksPerChunk
	chunkAddr := (addr / uint64(blocksPerChunk)) * uint64(blocksPerChunk)
	blockOffset := addr - chunkAddr
	
	// Find the chunk info
	var chunk *ChunkInfo
	var cib *ChunkInfoBlock
	
	// Search through CIBs
	for i := uint32(0); i < dev.SmCibCount; i++ {
		c, err := sm.getCIBBlock(tier, i)
		if err != nil {
			continue
		}
		
		// Check chunks in this CIB
		for j := uint32(0); j < c.CibChunkInfoCount; j++ {
			if c.CibChunkInfo[j].CiAddr == chunkAddr {
				chunk = &c.CibChunkInfo[j]
				cib = c
				break
			}
		}
		
		if chunk != nil {
			break
		}
	}
	
	if chunk == nil {
		return fmt.Errorf("chunk not found for address: %d", addr)
	}
	
	// Get the bitmap
	bitmap, err := sm.getChunkBitmap(chunk.CiBitmapAddr)
	if err != nil {
		return err
	}
	
	// Calculate bit position
	byteIndex := uint64(blockOffset) / 8
	bitIndex := uint64(blockOffset) % 8
	
	// Check if already free
	if (bitmap[byteIndex] & (1 << bitIndex)) == 0 {
		return ErrInvalidAddress
	}
	
	// Clear the bit (mark as free)
	bitmap[byteIndex] &= ^(1 << bitIndex)
	
	// Update free count
	chunk.CiFreeCount++
	dev.SmFreeCount++
	
	// Write updated bitmap back to disk
	return sm.writeChunkBitmap(chunk.CiBitmapAddr, bitmap)
}

// addToFreeQueue adds a block to the appropriate free queue
func (sm *SpaceManager) addToFreeQueue(addr uint64, tier uint32) error {
	// Determine which queue to use
	queueIndex := SFQ_MAIN
	if tier == SD_TIER2 {
		queueIndex = SFQ_TIER2
	}
	
	// Get the queue
	queue := &sm.spaceman.Sfq[queueIndex]
	
	// Increment queue count
	queue.SfqCount++
	
	// Get the current transaction ID
	xid := sm.container.checkpoint.XID
	
	// Get the queue for this XID
	xidQueue, ok := sm.freeQueueBlocks[uint64(queueIndex)]
	if !ok {
		xidQueue = make(map[uint64]uint64)
		sm.freeQueueBlocks[uint64(queueIndex)] = xidQueue
	}
	
	// Add the address to the queue
	xidQueue[xid] = addr
	
	// In a real implementation, this would update the B-tree
	// and potentially write to disk
	
	return nil
}

// AllocateBlock allocates a new block from the internal pool
func (ipm *InternalPoolManager) AllocateBlock() (uint64, error) {
	// Get the bitmap
	bitmap, err := ipm.getBitmap()
	if err != nil {
		return 0, err
	}
	
	// Find a free bit
	for i := uint32(0); i < ipm.bitmapSize * 8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		
		// Check if bit is free (0)
		if (bitmap[byteIndex] & (1 << bitIndex)) == 0 {
			// Set the bit (mark as used)
			bitmap[byteIndex] |= (1 << bitIndex)
			
			// Calculate block address
			addr := ipm.spaceman.spaceman.IPBase + uint64(i)
			
			// Write updated bitmap back to disk
			err = ipm.writeBitmap(bitmap)
			if err != nil {
				return 0, err
			}
			
			return addr, nil
		}
	}
	
	return 0, ErrNoFreeSpace
}

// FreeBlock frees a block back to the internal pool
func (ipm *InternalPoolManager) FreeBlock(addr uint64) error {
	// Check if address is in internal pool range
	if addr < ipm.spaceman.spaceman.IPBase || 
	   addr >= ipm.spaceman.spaceman.IPBase + uint64(ipm.spaceman.spaceman.IPBlockCount) {
		return ErrInvalidAddress
	}
	
	// Calculate offset in the internal pool
	offset := addr - ipm.spaceman.spaceman.IPBase
	
	// Get the bitmap
	bitmap, err := ipm.getBitmap()
	if err != nil {
		return err
	}
	
	// Calculate bit position
	byteIndex := offset / 8
	bitIndex := offset % 8
	
	// Check if already free
	if (bitmap[byteIndex] & (1 << bitIndex)) == 0 {
		return ErrInvalidAddress
	}
	
	// Clear the bit (mark as free)
	bitmap[byteIndex] &= ^(1 << bitIndex)
	
	// Write updated bitmap back to disk
	return ipm.writeBitmap(bitmap)
}

// getBitmap gets the internal pool bitmap
func (ipm *InternalPoolManager) getBitmap() ([]byte, error) {
	// Check if bitmap is already cached
	if bitmap, ok := ipm.spaceman.bitmapBlocks[ipm.bitmapBase]; ok {
		return bitmap, nil
	}
	
	// Read the bitmap
	blockData, err := ipm.spaceman.container.readPhysicalObject(ipm.bitmapBase)
	if err != nil {
		return nil, err
	}
	
	// Cache and return
	ipm.spaceman.bitmapBlocks[ipm.bitmapBase] = blockData
	return blockData, nil
}

// writeBitmap writes the internal pool bitmap back to disk
func (ipm *InternalPoolManager) writeBitmap(bitmap []byte) error {
	// In a real implementation, this would write the bitmap to disk
	// For now, just update the cache
	ipm.spaceman.bitmapBlocks[ipm.bitmapBase] = bitmap
	return nil
}

// AllocateBlocks allocates multiple contiguous blocks
func (sm *SpaceManager) AllocateBlocks(count uint32) (uint64, error) {
	// For small requests, try internal pool first (if it has enough space)
	if count <= 8 && sm.spaceman.IPBlockCount >= count {
		addr, err := sm.internalPool.AllocateContiguousBlocks(count)
		if err == nil {
			return addr, nil
		}
	}
	
	// For larger requests, use device allocation
	return sm.allocateContiguousBlocksFromDevice(SD_MAIN, count)
}

// allocateContiguousBlocksFromDevice allocates contiguous blocks from a device
func (sm *SpaceManager) allocateContiguousBlocksFromDevice(tier uint32, count uint32) (uint64, error) {
	// Get device info
	dev := &sm.spaceman.Smdev[tier]
	
	// Check if there's enough free space
	if dev.SmFreeCount < uint64(count) {
		return 0, ErrNoFreeSpace
	}
	
	// Try to find contiguous free blocks
	// This is a simple implementation; a real one would be more sophisticated
	for i := uint32(0); i < dev.SmCibCount; i++ {
		// Get CIB block
		cib, err := sm.getCIBBlock(tier, i)
		if err != nil {
			continue
		}
		
		// Check each chunk in the CIB
		for j := uint32(0); j < cib.CibChunkInfoCount; j++ {
			chunk := &cib.CibChunkInfo[j]
			
			// Skip if not enough free blocks
			if chunk.CiFreeCount < uint32(count) {
				continue
			}
			
			// Get the bitmap for this chunk
			bitmap, err := sm.getChunkBitmap(chunk.CiBitmapAddr)
			if err != nil {
				continue
			}
			
			// Find contiguous free bits
			start := uint32(0)
			run := uint32(0)
			
			for k := uint32(0); k < chunk.CiBlockCount; k++ {
				byteIndex := k / 8
				bitIndex := k % 8
				
				// Check if bit is free (0)
				if (bitmap[byteIndex] & (1 << bitIndex)) == 0 {
					// Extend run
					if run == 0 {
						start = k
					}
					run++
					
					// Check if we have enough blocks
					if run >= count {
						// Mark blocks as used
						for m := start; m < start+count; m++ {
							mByteIndex := m / 8
							mBitIndex := m % 8
							bitmap[mByteIndex] |= (1 << mBitIndex)
						}
						
						// Update free count
						chunk.CiFreeCount -= count
						dev.SmFreeCount -= uint64(count)
						
						// Calculate block address
						addr := chunk.CiAddr + uint64(start)
						
						// Write updated bitmap back to disk
						err = sm.writeChunkBitmap(chunk.CiBitmapAddr, bitmap)
						if err != nil {
							return 0, err
						}
						
						return addr, nil
					}
				} else {
					// Reset run
					run = 0
				}
			}
		}
	}
	
	return 0, ErrNoFreeSpace
}

// AllocateContiguousBlocks allocates contiguous blocks from the internal pool
func (ipm *InternalPoolManager) AllocateContiguousBlocks(count uint32) (uint64, error) {
	// Get the bitmap
	bitmap, err := ipm.getBitmap()
	if err != nil {
		return 0, err
	}
	
	// Find contiguous free bits
	start := uint32(0)
	run := uint32(0)
	
	for i := uint32(0); i < ipm.bitmapSize * 8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		
		// Check if bit is free (0)
		if (bitmap[byteIndex] & (1 << bitIndex)) == 0 {
			// Extend run
			if run == 0 {
				start = i
			}
			run++
			
			// Check if we have enough blocks
			if run >= count {
				// Mark blocks as used
				for j := start; j < start+count; j++ {
					jByteIndex := j / 8
					jBitIndex := j % 8
					bitmap[jByteIndex] |= (1 << jBitIndex)
				}
				
				// Calculate block address
				addr := ipm.spaceman.spaceman.IPBase + uint64(start)
				
				// Write updated bitmap back to disk
				err = ipm.writeBitmap(bitmap)
				if err != nil {
					return 0, err
				}
				
				return addr, nil
			}
		} else {
			// Reset run
			run = 0
		}
	}
	
	return 0, ErrNoFreeSpace
}

// IsBlockFree checks if a block is free
func (sm *SpaceManager) IsBlockFree(addr uint64) (bool, error) {
	// Check if the address is valid
	if addr == 0 || addr >= sm.container.superblock.BlockCount {
		return false, ErrInvalidAddress
	}
	
	// Check if it's an internal pool address
	if addr >= sm.spaceman.IPBase && addr < sm.spaceman.IPBase+uint64(sm.spaceman.IPBlockCount) {
		return sm.internalPool.IsBlockFree(addr)
	}
	
	// For Fusion drives, determine which tier
	tier := SD_MAIN
	if (sm.container.superblock.IncompatFeatures & NX_INCOMPAT_FUSION) != 0 {
		// Check if it's on tier2
		tier2Marker := FUSION_TIER2_DEVICE_BLOCK_ADDR(sm.container.blockSize)
		if addr & tier2Marker != 0 {
			tier = SD_TIER2
			addr &= ^tier2Marker // Clear tier bit
		}
	}
	
	// Find the chunk containing this address
	dev := &sm.spaceman.Smdev[tier]
	
	// Calculate chunk parameters
	blocksPerChunk := sm.spaceman.BlocksPerChunk
	chunkAddr := (addr / uint64(blocksPerChunk)) * uint64(blocksPerChunk)
	blockOffset := addr - chunkAddr
	
	// Find the chunk info
	var chunk *ChunkInfo
	
	// Search through CIBs
	for i := uint32(0); i < dev.SmCibCount; i++ {
		cib, err := sm.getCIBBlock(tier, i)
		if err != nil {
			continue
		}
		
		// Check chunks in this CIB
		for j := uint32(0); j < cib.CibChunkInfoCount; j++ {
			if cib.CibChunkInfo[j].CiAddr == chunkAddr {
				chunk = &cib.CibChunkInfo[j]
				break
			}
		}
		
		if chunk != nil {
			break
		}
	}
	
	if chunk == nil {
		return false, fmt.Errorf("chunk not found for address: %d", addr)
	}
	
	// Get the bitmap
	bitmap, err := sm.getChunkBitmap(chunk.CiBitmapAddr)
	if err != nil {
		return false, err
	}
	
	// Calculate bit position
	byteIndex := uint64(blockOffset) / 8
	bitIndex := uint64(blockOffset) % 8
	
	// Check if bit is free (0)
	return (bitmap[byteIndex] & (1 << bitIndex)) == 0, nil
}

// IsBlockFree checks if a block in the internal pool is free
func (ipm *InternalPoolManager) IsBlockFree(addr uint64) (bool, error) {
	// Check if address is in internal pool range
	if addr < ipm.spaceman.spaceman.IPBase || 
	   addr >= ipm.spaceman.spaceman.IPBase + uint64(ipm.spaceman.spaceman.IPBlockCount) {
		return false, ErrInvalidAddress
	}
	
	// Calculate offset in the internal pool
	offset := addr - ipm.spaceman.spaceman.IPBase
	
	// Get the bitmap
	bitmap, err := ipm.getBitmap()
	if err != nil {
		return false, err
	}
	
	// Calculate bit position
	byteIndex := offset / 8
	bitIndex := offset % 8
	
	// Check if bit is free (0)
	return (bitmap[byteIndex] & (1 << bitIndex)) == 0, nil
}

// GetFreeBlockCount returns the number of free blocks
func (sm *SpaceManager) GetFreeBlockCount() uint64 {
	total := uint64(0)
	
	// Add internal pool free count
	// (This would be calculated from the bitmap)
	
	// Add main device free count
	total += sm.spaceman.Smdev[SD_MAIN].SmFreeCount
	
	// Add tier2 device free count if Fusion
	if (sm.container.superblock.IncompatFeatures & NX_INCOMPAT_FUSION) != 0 {
		total += sm.spaceman.Smdev[SD_TIER2].SmFreeCount
	}
	
	return total
}

// GetTotalBlockCount returns the total number of blocks
func (sm *SpaceManager) GetTotalBlockCount() uint64 {
	return sm.container.superblock.BlockCount
}

// AllocateVolumeBlocks allocates blocks for a volume
func (sm *SpaceManager) AllocateVolumeBlocks(volume *VolumeManager, count uint64) (uint64, error) {
	// Check volume quota
	if volume.superblock.FSQuotaBlockCount > 0 {
		// Check if allocation would exceed quota
		newTotal := volume.superblock.FSAllocCount + count
		if newTotal > volume.superblock.FSQuotaBlockCount {
			return 0, ErrQuotaExceeded
		}
	}
	
	// Check volume reserve
	if volume.superblock.FSReserveBlockCount > 0 {
		// Check
