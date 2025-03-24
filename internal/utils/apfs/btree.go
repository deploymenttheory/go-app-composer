// btree.go
package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// BTree represents a B-tree in APFS
type BTree struct {
	container    *ContainerManager
	node         *BTreeNodePhys
	isRoot       bool
	nodeSize     uint32
	keySize      uint32
	valSize      uint32
	treeType     uint32
	treeSubType  uint32
	allowGhosts  bool
	fixedKVSize  bool
	nodeIsHashed bool
	isPhysical   bool
}

// BTreeNodePhys represents a B-tree node (btree_node_phys_t)
type BTreeNodePhys struct {
	BtnO           ObjectPhys // Object header
	BtnFlags       uint16     // Flags
	BtnLevel       uint16     // Level in the tree (0 = leaf)
	BtnNKeys       uint32     // Number of keys in this node
	BtnTableSpace  NLoc       // Table of contents location info
	BtnFreeSpace   NLoc       // Free space location info
	BtnKeyFreeList NLoc       // Free list for keys
	BtnValFreeList NLoc       // Free list for values
	BtnData        []byte     // Node data area
}

// BTreeInfoFixed represents static information about a B-tree (btree_info_fixed_t)
type BTreeInfoFixed struct {
	BtFlags    uint32 // B-tree flags
	BtNodeSize uint32 // Node size in bytes
	BtKeySize  uint32 // Key size in bytes (0 if variable)
	BtValSize  uint32 // Value size in bytes (0 if variable)
}

// BTreeInfo represents information about a B-tree (btree_info_t)
type BTreeInfo struct {
	BtFixed      BTreeInfoFixed // Fixed information
	BtLongestKey uint32         // Length of longest key
	BtLongestVal uint32         // Length of longest value
	BtKeyCount   uint64         // Number of keys in the tree
	BtNodeCount  uint64         // Number of nodes in the tree
}

// NLoc represents a location within a B-tree node (nloc_t)
type NLoc struct {
	Off uint16 // Offset
	Len uint16 // Length
}

// KVLoc represents the location of a key and value in a B-tree node (kvloc_t)
type KVLoc struct {
	K NLoc // Key location
	V NLoc // Value location
}

// KVOff represents the offset of a key and value in a B-tree node with fixed sizes (kvoff_t)
type KVOff struct {
	K uint16 // Key offset
	V uint16 // Value offset
}

// BtnIndexNodeVal represents the value used by hashed B-trees for non-leaf nodes
type BtnIndexNodeVal struct {
	BinvChildOID  uint64                     // Object ID of the child node
	BinvChildHash [BtreeNodeHashSizeMax]byte // Hash of the child node
}

// NewBTree creates a new B-tree from raw node data
func NewBTree(container *ContainerManager, data []byte) (*BTree, error) {
	node := &BTreeNodePhys{}
	err := node.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse B-tree node: %w", err)
	}

	// Check if this is a root node
	isRoot := node.BtnFlags&BtnodeRoot != 0

	// Get tree type and subtype
	treeType := node.BtnO.GetObjectType()
	treeSubType := node.BtnO.GetObjectSubtype()

	// Get tree info for root nodes
	var nodeSize, keySize, valSize uint32
	var allowGhosts, isPhysical bool

	if isRoot {
		// Get B-tree info from the end of the node
		treeInfo, err := parseBTreeInfo(node.BtnData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse B-tree info: %w", err)
		}

		nodeSize = treeInfo.BtFixed.BtNodeSize
		keySize = treeInfo.BtFixed.BtKeySize
		valSize = treeInfo.BtFixed.BtValSize
		allowGhosts = treeInfo.BtFixed.BtFlags&BtreeAllowGhosts != 0
		isPhysical = treeInfo.BtFixed.BtFlags&BtreePhysical != 0
	} else {
		// For non-root nodes, use the container's block size as node size
		nodeSize = container.blockSize

		// These will be set by the parent node when traversing
		keySize = 0
		valSize = 0
		allowGhosts = false
		isPhysical = false
	}

	// Check for fixed KV sizes
	fixedKVSize := node.BtnFlags&BtnodeFixedKVSize != 0
	nodeIsHashed := node.BtnFlags&BtnodeHashed != 0

	return &BTree{
		container:    container,
		node:         node,
		isRoot:       isRoot,
		nodeSize:     nodeSize,
		keySize:      keySize,
		valSize:      valSize,
		treeType:     treeType,
		treeSubType:  treeSubType,
		allowGhosts:  allowGhosts,
		fixedKVSize:  fixedKVSize,
		nodeIsHashed: nodeIsHashed,
		isPhysical:   isPhysical,
	}, nil
}

// parseBTreeInfo parses the B-tree info from a root node
func parseBTreeInfo(data []byte) (*BTreeInfo, error) {
	// B-tree info is at the end of the node
	if len(data) < binary.Size(BTreeInfo{}) {
		return nil, ErrStructTooShort
	}

	offset := len(data) - binary.Size(BTreeInfo{})
	info := &BTreeInfo{}
	err := binary.Read(bytes.NewReader(data[offset:]), binary.LittleEndian, info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// Parse parses a B-tree node from bytes
func (node *BTreeNodePhys) Parse(data []byte) error {
	// Parse the header
	headerSize := binary.Size(ObjectPhys{})
	if len(data) < headerSize {
		return ErrStructTooShort
	}

	// Parse object header
	err := node.BtnO.Parse(data[:headerSize])
	if err != nil {
		return err
	}

	// Parse fixed node fields
	if len(data) < headerSize+24 { // 24 = size of remaining fixed fields
		return ErrStructTooShort
	}

	node.BtnFlags = binary.LittleEndian.Uint16(data[headerSize:])
	node.BtnLevel = binary.LittleEndian.Uint16(data[headerSize+2:])
	node.BtnNKeys = binary.LittleEndian.Uint32(data[headerSize+4:])

	// Parse the NLoc structures
	parseNLoc := func(offset int) NLoc {
		return NLoc{
			Off: binary.LittleEndian.Uint16(data[offset:]),
			Len: binary.LittleEndian.Uint16(data[offset+2:]),
		}
	}

	node.BtnTableSpace = parseNLoc(headerSize + 8)
	node.BtnFreeSpace = parseNLoc(headerSize + 12)
	node.BtnKeyFreeList = parseNLoc(headerSize + 16)
	node.BtnValFreeList = parseNLoc(headerSize + 20)

	// Store the node data
	node.BtnData = make([]byte, len(data)-headerSize-24)
	copy(node.BtnData, data[headerSize+24:])

	return nil
}

// Serialize converts the B-tree node to bytes
func (node *BTreeNodePhys) Serialize() ([]byte, error) {
	// Calculate total size
	headerSize := binary.Size(ObjectPhys{})
	fixedSize := headerSize + 24 // 24 = size of remaining fixed fields
	totalSize := fixedSize + len(node.BtnData)

	// Create buffer
	buf := make([]byte, totalSize)

	// Serialize object header
	objBytes, err := node.BtnO.Serialize()
	if err != nil {
		return nil, err
	}
	copy(buf[:headerSize], objBytes)

	// Serialize fixed node fields
	binary.LittleEndian.PutUint16(buf[headerSize:], node.BtnFlags)
	binary.LittleEndian.PutUint16(buf[headerSize+2:], node.BtnLevel)
	binary.LittleEndian.PutUint32(buf[headerSize+4:], node.BtnNKeys)

	// Serialize NLoc structures
	writeNLoc := func(loc NLoc, offset int) {
		binary.LittleEndian.PutUint16(buf[offset:], loc.Off)
		binary.LittleEndian.PutUint16(buf[offset+2:], loc.Len)
	}

	writeNLoc(node.BtnTableSpace, headerSize+8)
	writeNLoc(node.BtnFreeSpace, headerSize+12)
	writeNLoc(node.BtnKeyFreeList, headerSize+16)
	writeNLoc(node.BtnValFreeList, headerSize+20)

	// Copy node data
	copy(buf[fixedSize:], node.BtnData)

	// Calculate and set checksum
	node.BtnO.SetChecksum(buf)
	objBytes, err = node.BtnO.Serialize()
	if err != nil {
		return nil, err
	}
	copy(buf[:headerSize], objBytes)

	return buf, nil
}

// IsLeaf returns true if this is a leaf node
func (node *BTreeNodePhys) IsLeaf() bool {
	return node.BtnFlags&BtnodeLeaf != 0
}

// GetTOC returns the table of contents entries for a node
func (bt *BTree) GetTOC() ([]KVLoc, []KVOff, error) {
	node := bt.node

	// Get the start and length of the table of contents
	tocOff := node.BtnTableSpace.Off
	tocLen := node.BtnTableSpace.Len

	if tocLen == 0 {
		return nil, nil, nil
	}

	if bt.fixedKVSize {
		// Fixed size keys and values
		entriesCount := tocLen / 4 // Each KVOff is 4 bytes
		tocData := node.BtnData[tocOff : tocOff+tocLen]

		toc := make([]KVOff, entriesCount)
		for i := uint16(0); i < uint16(entriesCount); i++ {
			toc[i] = KVOff{
				K: binary.LittleEndian.Uint16(tocData[i*4:]),
				V: binary.LittleEndian.Uint16(tocData[i*4+2:]),
			}
		}
		return nil, toc, nil
	} else {
		// Variable size keys and values
		entriesCount := tocLen / 8 // Each KVLoc is 8 bytes
		tocData := node.BtnData[tocOff : tocOff+tocLen]

		toc := make([]KVLoc, entriesCount)
		for i := uint16(0); i < uint16(entriesCount); i++ {
			toc[i] = KVLoc{
				K: NLoc{
					Off: binary.LittleEndian.Uint16(tocData[i*8:]),
					Len: binary.LittleEndian.Uint16(tocData[i*8+2:]),
				},
				V: NLoc{
					Off: binary.LittleEndian.Uint16(tocData[i*8+4:]),
					Len: binary.LittleEndian.Uint16(tocData[i*8+6:]),
				},
			}
		}
		return toc, nil, nil
	}
}

// GetKey returns the key at the specified index
func (bt *BTree) GetKey(index uint32) ([]byte, error) {
	if index >= bt.node.BtnNKeys {
		return nil, fmt.Errorf("key index %d out of range (0-%d)", index, bt.node.BtnNKeys-1)
	}

	// Get the table of contents
	kvloc, kvoff, err := bt.GetTOC()
	if err != nil {
		return nil, err
	}

	var keyOff, keyLen uint16

	if bt.fixedKVSize {
		// Fixed size keys
		keyOff = kvoff[index].K
		keyLen = bt.keySize
	} else {
		// Variable size keys
		keyOff = kvloc[index].K.Off
		keyLen = kvloc[index].K.Len
	}

	// Calculate the actual offset from the end of the table space
	tocEnd := bt.node.BtnTableSpace.Off + bt.node.BtnTableSpace.Len

	// Get the key data
	keyOff += tocEnd // Keys start after the TOC
	if int(keyOff+keyLen) > len(bt.node.BtnData) {
		return nil, fmt.Errorf("key at index %d extends beyond node data", index)
	}

	return bt.node.BtnData[keyOff : keyOff+keyLen], nil
}

// GetValue returns the value at the specified index
func (bt *BTree) GetValue(index uint32) ([]byte, error) {
	if index >= bt.node.BtnNKeys {
		return nil, fmt.Errorf("value index %d out of range (0-%d)", index, bt.node.BtnNKeys-1)
	}

	// Get the table of contents
	kvloc, kvoff, err := bt.GetTOC()
	if err != nil {
		return nil, err
	}

	var valOff, valLen uint16
	var isGhost bool

	if bt.fixedKVSize {
		// Fixed size values
		valOff = kvoff[index].V
		valLen = bt.valSize
		isGhost = valOff == BtoffInvalid
	} else {
		// Variable size values
		valOff = kvloc[index].V.Off
		valLen = kvloc[index].V.Len
		isGhost = valOff == BtoffInvalid
	}

	// Check if this is a ghost key (has no value)
	if isGhost {
		if bt.allowGhosts {
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected ghost value at index %d", index)
	}

	// Values are stored from the end of the node data
	valueOffset := uint16(len(bt.node.BtnData)) - valOff
	if int(valueOffset+valLen) > len(bt.node.BtnData) {
		return nil, fmt.Errorf("value at index %d extends beyond node data", index)
	}

	return bt.node.BtnData[valueOffset : valueOffset+valLen], nil
}

// Search searches for a key in the B-tree
func (bt *BTree) Search(key []byte) ([]byte, error) {
	return bt.search(key, bt.node, bt.isRoot)
}

// search performs the actual search on a B-tree node
func (bt *BTree) search(key []byte, node *BTreeNodePhys, isRoot bool) ([]byte, error) {
	// Check if this is a leaf node
	if node.IsLeaf() {
		// Find the key in this leaf node
		index, found, err := bt.findKey(node, key)
		if err != nil {
			return nil, err
		}

		if !found {
			return nil, ErrNotFound
		}

		// Get the value for this key
		return bt.GetValue(index)
	}

	// This is a non-leaf node, find the child node to search
	index, found, err := bt.findKey(node, key)
	if err != nil {
		return nil, err
	}

	// If the key was found exactly, use that child
	// If not found, use the child that would be just before it
	if !found && index > 0 {
		index--
	}

	// Get the child node's object ID
	valueBytes, err := bt.GetValue(index)
	if err != nil {
		return nil, err
	}

	var childOID uint64
	if bt.nodeIsHashed {
		// The value is a BtnIndexNodeVal with the child OID and hash
		if len(valueBytes) < binary.Size(uint64(0)) {
			return nil, ErrStructTooShort
		}
		childOID = binary.LittleEndian.Uint64(valueBytes)
	} else {
		// The value is just the child OID
		if len(valueBytes) < binary.Size(uint64(0)) {
			return nil, ErrStructTooShort
		}
		childOID = binary.LittleEndian.Uint64(valueBytes)
	}

	// Get latest transaction ID
	xid := bt.container.checkpoint.XID

	// Resolve the child node
	var childData []byte
	if bt.isPhysical {
		// Physical address
		childData, err = bt.container.readPhysicalObject(childOID)
	} else {
		// Virtual object
		childData, err = bt.container.resolveObject(childOID, xid)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to resolve child node: %w", err)
	}

	// Parse the child node
	childNode := &BTreeNodePhys{}
	err = childNode.Parse(childData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse child node: %w", err)
	}

	// Search in the child node
	return bt.search(key, childNode, false)
}

// findKey finds a key in a B-tree node
// Returns the index, a boolean indicating if the key was found, and any error
func (bt *BTree) findKey(node *BTreeNodePhys, key []byte) (uint32, bool, error) {
	// Binary search for the key
	left := uint32(0)
	right := node.BtnNKeys - 1

	// Special case for empty node
	if node.BtnNKeys == 0 {
		return 0, false, nil
	}

	// Temporary BTree struct for the current node
	nodeBt := &BTree{
		container:   bt.container,
		node:        node,
		isRoot:      false,
		nodeSize:    bt.nodeSize,
		keySize:     bt.keySize,
		valSize:     bt.valSize,
		fixedKVSize: node.BtnFlags&BtnodeFixedKVSize != 0,
		allowGhosts: bt.allowGhosts,
	}

	for left <= right {
		mid := (left + right) / 2

		// Get the key at this index
		midKey, err := nodeBt.GetKey(mid)
		if err != nil {
			return 0, false, err
		}

		// Compare keys
		cmp := bytes.Compare(midKey, key)

		if cmp == 0 {
			// Found the key
			return mid, true, nil
		} else if cmp < 0 {
			// Key is in right half
			left = mid + 1
		} else {
			// Key is in left half
			if mid == 0 {
				break
			}
			right = mid - 1
		}
	}

	// Key not found
	return left, false, nil
}

// IterateRange iterates over a range of keys in the B-tree
func (bt *BTree) IterateRange(startKey, endKey []byte, callback func(key, value []byte) bool) error {
	// Start by finding the leaf node that would contain the start key
	return bt.iterateRange(bt.node, startKey, endKey, callback)
}

// iterateRange performs the actual iteration on a B-tree node
func (bt *BTree) iterateRange(node *BTreeNodePhys, startKey, endKey []byte, callback func(key, value []byte) bool) error {
	// If this is a leaf node, iterate through its keys
	if node.IsLeaf() {
		// Create temporary BTree for this node
		nodeBt := &BTree{
			container:   bt.container,
			node:        node,
			isRoot:      false,
			nodeSize:    bt.nodeSize,
			keySize:     bt.keySize,
			valSize:     bt.valSize,
			fixedKVSize: node.BtnFlags&BtnodeFixedKVSize != 0,
			allowGhosts: bt.allowGhosts,
		}

		// Find the starting position
		startIndex, _, err := bt.findKey(node, startKey)
		if err != nil {
			return err
		}

		// Iterate through keys
		for i := startIndex; i < node.BtnNKeys; i++ {
			key, err := nodeBt.GetKey(i)
			if err != nil {
				return err
			}

			// If we've gone past the end key, stop iterating
			if endKey != nil && bytes.Compare(key, endKey) > 0 {
				break
			}

			// Get the value
			value, err := nodeBt.GetValue(i)
			if err != nil {
				return err
			}

			// Call the callback
			if !callback(key, value) {
				// Callback returned false, stop iterating
				return nil
			}
		}

		// Done with this leaf
		return nil
	}

	// This is a non-leaf node
	// Find the child node that would contain the start key
	startIndex, _, err := bt.findKey(node, startKey)
	if err != nil {
		return err
	}

	// If the key was not found and we're not at the beginning, go to the previous child
	if startIndex > 0 {
		startIndex--
	}

	// Create temporary BTree for this node
	nodeBt := &BTree{
		container:    bt.container,
		node:         node,
		isRoot:       false,
		nodeSize:     bt.nodeSize,
		keySize:      bt.keySize,
		valSize:      bt.valSize,
		fixedKVSize:  node.BtnFlags&BtnodeFixedKVSize != 0,
		allowGhosts:  bt.allowGhosts,
		nodeIsHashed: node.BtnFlags&BtnodeHashed != 0,
		isPhysical:   bt.isPhysical,
	}

	// Iterate through child nodes
	for i := startIndex; i < node.BtnNKeys; i++ {
		// Get the key at this index
		key, err := nodeBt.GetKey(i)
		if err != nil {
			return err
		}

		// If we've gone past the end key, stop iterating
		if endKey != nil && bytes.Compare(key, endKey) > 0 {
			break
		}

		// Get the child node object ID
		valueBytes, err := nodeBt.GetValue(i)
		if err != nil {
			return err
		}

		var childOID uint64
		if nodeBt.nodeIsHashed {
			// The value is a BtnIndexNodeVal with the child OID and hash
			if len(valueBytes) < binary.Size(uint64(0)) {
				return ErrStructTooShort
			}
			childOID = binary.LittleEndian.Uint64(valueBytes)
		} else {
			// The value is just the child OID
			if len(valueBytes) < binary.Size(uint64(0)) {
				return ErrStructTooShort
			}
			childOID = binary.LittleEndian.Uint64(valueBytes)
		}

		// Get latest transaction ID
		xid := bt.container.checkpoint.XID

		// Resolve the child node
		var childData []byte
		if bt.isPhysical {
			// Physical address
			childData, err = bt.container.readPhysicalObject(childOID)
		} else {
			// Virtual object
			childData, err = bt.container.resolveObject(childOID, xid)
		}

		if err != nil {
			return fmt.Errorf("failed to resolve child node: %w", err)
		}

		// Parse the child node
		childNode := &BTreeNodePhys{}
		err = childNode.Parse(childData)
		if err != nil {
			return fmt.Errorf("failed to parse child node: %w", err)
		}

		// Recursively iterate through the child node
		err = bt.iterateRange(childNode, startKey, endKey, callback)
		if err != nil {
			return err
		}
	}

	return nil
}

// Insert inserts a key-value pair into the B-tree
func (bt *BTree) Insert(tx *Transaction, key, value []byte) error {
	// Check if transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Need to implement transaction logic, node splitting, etc.
	return ErrNotImplemented
}

// Delete deletes a key from the B-tree
func (bt *BTree) Delete(tx *Transaction, key []byte) error {
	// Check if transaction is valid
	if tx == nil || tx.completed {
		return errors.New("invalid transaction")
	}

	// Need to implement transaction logic, node merging, etc.
	return ErrNotImplemented
}

// GetBTreeInfo returns the B-tree's info (for root nodes)
func (bt *BTree) GetBTreeInfo() (*BTreeInfo, error) {
	if !bt.isRoot {
		return nil, errors.New("not a root node")
	}

	// Parse the B-tree info from the end of the node
	return parseBTreeInfo(bt.node.BtnData)
}

// GetNodeLevel returns the B-tree node's level
func (bt *BTree) GetNodeLevel() uint16 {
	return bt.node.BtnLevel
}
