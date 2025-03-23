//
package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// BTree represents an APFS B-tree
type BTree struct {
	container  *ContainerManager
	rootNode   *BTreeNode
	info       *BTreeInfo
	treeType   uint32
	treeSubtype uint32
}

// BTreeNode represents a node in an APFS B-tree
type BTreeNode struct {
	tree       *BTree
	header     BTreeNodePhys
	data       []byte
	tableSpace []byte
	keySpace   []byte
	valueSpace []byte
	toc        []KVEntry
}

// KVEntry represents an entry in a B-tree node's table of contents
type KVEntry struct {
	Key    []byte
	Value  []byte
	KeyPos uint16  // Offset to the key from the start of the key space
	ValPos uint16  // Offset to the value from the end of the value space
}

// NewBTree creates a new B-tree from a root node block
func NewBTree(container *ContainerManager, rootNodeData []byte) (*BTree, error) {
	if len(rootNodeData) < binary.Size(BTreeNodePhys{}) {
		return nil, errors.New("data too short for BTree node")
	}

	// Create the B-tree
	tree := &BTree{
		container: container,
	}

	// Parse the root node
	rootNode, err := tree.parseNode(rootNodeData)
	if err != nil {
		return nil, err
	}

	// Verify that this is a root node
	if (rootNode.header.BtnFlags & BTNodeRoot) == 0 {
		return nil, errors.New("not a root node")
	}

	tree.rootNode = rootNode

	// Root nodes have B-tree info at the end
	treeInfo, err := tree.parseTreeInfo(rootNodeData)
	if err != nil {
		return nil, err
	}
	tree.info = treeInfo

	// Extract object type and subtype
	tree.treeType = rootNode.header.BtnO.Type
	tree.treeSubtype = rootNode.header.BtnO.Subtype

	return tree, nil
}

// parseNode parses a B-tree node from raw data
func (bt *BTree) parseNode(data []byte) (*BTreeNode, error) {
	node := &BTreeNode{
		tree: bt,
		data: data,
	}

	// Parse the node header
	headerSize := binary.Size(BTreeNodePhys{})
	if err := binary.Read(bytes.NewReader(data[:headerSize]), binary.LittleEndian, &node.header); err != nil {
		return nil, err
	}

	// Verify the checksum
	if !bt.container.verifyChecksum(data, node.header.BtnO.Checksum[:]) {
		return nil, ErrInvalidChecksum
	}

	// Calculate data areas
	tocOffset := headerSize
	tocSize := int(node.header.BtnTableSpace.Off)
	tocEnd := tocOffset + tocSize

	// Table of contents space
	node.tableSpace = data[tocOffset:tocEnd]

	// Key space starts after the table of contents
	keySpaceOffset := tocEnd
	keySpaceSize := int(node.header.BtnFreeSpace.Off)
	keySpaceEnd := keySpaceOffset + keySpaceSize
	node.keySpace = data[keySpaceOffset:keySpaceEnd]

	// Value space ends at the end of the node 
	// (or before the tree info if this is a root node)
	valueSpaceEnd := len(data)
	if (node.header.BtnFlags & BTNodeRoot) != 0 {
		// Root nodes have the tree info at the end
		valueSpaceEnd -= binary.Size(BTreeInfo{})
	}
	valueSpaceSize := int(node.header.BtnFreeSpace.Len)
	valueSpaceOffset := valueSpaceEnd - valueSpaceSize
	node.valueSpace = data[valueSpaceOffset:valueSpaceEnd]

	// Parse the table of contents
	if err := node.parseTableOfContents(); err != nil {
		return nil, err
	}

	return node, nil
}

// parseTableOfContents parses the B-tree node's table of contents
func (node *BTreeNode) parseTableOfContents() error {
	isFixedSize := (node.header.BtnFlags & BTNodeFixedKVSize) != 0
	
	// Determine number of entries and entry size
	entryCount := int(node.header.BtnNkeys)
	node.toc = make([]KVEntry, entryCount)

	if isFixedSize {
		// Fixed-size keys and values - table of contents has just the offsets
		entrySize := binary.Size(KVOff{})
		for i := 0; i < entryCount; i++ {
			off := KVOff{}
			err := binary.Read(bytes.NewReader(node.tableSpace[i*entrySize:]), binary.LittleEndian, &off)
			if err != nil {
				return err
			}

			// Get key
			keyPos := off.K
			var keyData []byte
			if i+1 < entryCount {
				// Get the next key offset to determine length
				nextOff := KVOff{}
				binary.Read(bytes.NewReader(node.tableSpace[(i+1)*entrySize:]), binary.LittleEndian, &nextOff)
				keyData = node.keySpace[keyPos:nextOff.K]
			} else {
				// Last key extends to the end of the key space
				keyData = node.keySpace[keyPos:]
			}

			// Get value
			valPos := off.V
			var valData []byte
			if i+1 < entryCount {
				// Get the next value offset to determine length
				nextOff := KVOff{}
				binary.Read(bytes.NewReader(node.tableSpace[(i+1)*entrySize:]), binary.LittleEndian, &nextOff)
				valData = node.valueSpace[valPos:nextOff.V]
			} else {
				// Last value extends to the end of the value space
				valData = node.valueSpace[valPos:]
			}

			node.toc[i] = KVEntry{
				Key:    keyData,
				Value:  valData,
				KeyPos: keyPos,
				ValPos: valPos,
			}
		}
	} else {
		// Variable-size keys and values - table of contents has offsets and lengths
		entrySize := binary.Size(KVLoc{})
		for i := 0; i < entryCount; i++ {
			loc := KVLoc{}
			err := binary.Read(bytes.NewReader(node.tableSpace[i*entrySize:]), binary.LittleEndian, &loc)
			if err != nil {
				return err
			}

			// Get key using offset and length
			keyPos := loc.K.Off
			keyLen := loc.K.Len
			keyData := node.keySpace[keyPos:keyPos+keyLen]

			// Get value using offset and length
			valPos := loc.V.Off
			valLen := loc.V.Len
			valData := node.valueSpace[valPos:valPos+valLen]

			node.toc[i] = KVEntry{
				Key:    keyData,
				Value:  valData,
				KeyPos: keyPos,
				ValPos: valPos,
			}
		}
	}

	return nil
}

// parseTreeInfo parses the BTreeInfo structure from a root node
func (bt *BTree) parseTreeInfo(data []byte) (*BTreeInfo, error) {
	// Tree info is at the end of the root node
	infoSize := binary.Size(BTreeInfo{})
	infoOffset := len(data) - infoSize

	info := &BTreeInfo{}
	err := binary.Read(bytes.NewReader(data[infoOffset:]), binary.LittleEndian, info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// Search searches the B-tree for a key
func (bt *BTree) Search(searchKey []byte) ([]byte, error) {
	// Start at the root node
	return bt.searchNode(bt.rootNode, searchKey)
}

// searchNode searches a specific node for a key
func (bt *BTree) searchNode(node *BTreeNode, searchKey []byte) ([]byte, error) {
	// Check if this is a leaf node
	if (node.header.BtnFlags & BTNodeLeaf) != 0 {
		// This is a leaf node, look for the key directly
		for _, entry := range node.toc {
			// Compare keys
			if bt.compareKeys(entry.Key, searchKey) == 0 {
				// Key found
				return entry.Value, nil
			}
		}
		// Key not found in leaf
		return nil, errors.New("key not found")
	}

	// This is an internal node, find the appropriate child
	childIndex := bt.findChildIndex(node, searchKey)
	if childIndex < 0 || childIndex >= len(node.toc) {
		return nil, errors.New("child index out of range")
	}

	// Read child node pointer from value
	var childOID uint64
	if err := binary.Read(bytes.NewReader(node.toc[childIndex].Value), binary.LittleEndian, &childOID); err != nil {
		return nil, err
	}

	// Get child node
	childNodeData, err := bt.container.resolveObject(childOID, 0) // 0 for current transaction
	if err != nil {
		return nil, err
	}

	// Parse child node
	childNode, err := bt.parseNode(childNodeData)
	if err != nil {
		return nil, err
	}

	// Recursively search the child node
	return bt.searchNode(childNode, searchKey)
}

// findChildIndex finds the index of the child node that would contain the key
func (bt *BTree) findChildIndex(node *BTreeNode, searchKey []byte) int {
	// For an internal node, find the last key that is <= the search key
	lastIndexLEQ := -1
	for i, entry := range node.toc {
		cmp := bt.compareKeys(entry.Key, searchKey)
		if cmp <= 0 {
			lastIndexLEQ = i
		} else {
			break
		}
	}

	// If no key is <= the search key, use the first child
	if lastIndexLEQ == -1 {
		return 0
	}
	return lastIndexLEQ
}

// compareKeys compares two B-tree keys
func (bt *BTree) compareKeys(a, b []byte) int {
	// The comparison depends on the tree subtype
	switch bt.treeSubtype {
	case ObjectTypeOMAP:
		// Object map keys are compared by OID then XID
		return bt.compareOMapKeys(a, b)
	case ObjectTypeFSTREE:
		// File system keys are compared based on their type
		return bt.compareFSKeys(a, b)
	default:
		// Default to byte-by-byte comparison
		return bytes.Compare(a, b)
	}
}

// compareOMapKeys compares two object map keys
func (bt *BTree) compareOMapKeys(a, b []byte) int {
	var keyA, keyB OMapKey
	if err := binary.Read(bytes.NewReader(a), binary.LittleEndian, &keyA); err != nil {
		return 0
	}
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &keyB); err != nil {
		return 0
	}

	// Compare OIDs
	if keyA.OkOID < keyB.OkOID {
		return -1
	} else if keyA.OkOID > keyB.OkOID {
		return 1
	}

	// OIDs are equal, compare XIDs
	if keyA.OkXID < keyB.OkXID {
		return -1
	} else if keyA.OkXID > keyB.OkXID {
		return 1
	}

	// Keys are equal
	return 0
}

// compareFSKeys compares two file system keys
func (bt *BTree) compareFSKeys(a, b []byte) int {
	// Read the object ID and type from the keys
	var keyHeaderA, keyHeaderB JKey
	if err := binary.Read(bytes.NewReader(a), binary.LittleEndian, &keyHeaderA); err != nil {
		return 0
	}
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &keyHeaderB); err != nil {
		return 0
	}

	// Extract object ID (removing the type bits)
	objIDA := keyHeaderA.ObjIDAndType & ObjIDMask
	objIDB := keyHeaderB.ObjIDAndType & ObjIDMask

	// Compare object IDs
	if objIDA < objIDB {
		return -1
	} else if objIDA > objIDB {
		return 1
	}

	// Object IDs are equal, compare types
	typeA := (keyHeaderA.ObjIDAndType & ObjTypeMask) >> ObjTypeShift
	typeB := (keyHeaderB.ObjIDAndType & ObjTypeMask) >> ObjTypeShift

	if typeA < typeB {
		return -1
	} else if typeA > typeB {
		return 1
	}

	// For certain types, we need to compare additional fields
	if typeA == APFSTypeDirRec || typeA == APFSTypeXattr {
		// Directory entries and xattrs have name fields
		// Skip the common header and compare the names
		return bt.compareNames(a[binary.Size(JKey{}):], b[binary.Size(JKey{}):])
	}

	// Types are equal and no additional comparison needed
	return 0
}

// compareNames compares two names from directory entries or xattrs
func (bt *BTree) compareNames(a, b []byte) int {
	// Read name lengths
	var lenA, lenB uint16
	if err := binary.Read(bytes.NewReader(a), binary.LittleEndian, &lenA); err != nil {
		return 0
	}
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &lenB); err != nil {
		return 0
	}

	// Extract names
	nameA := a[2:2+lenA]
	nameB := b[2:2+lenB]

	// Compare names
	return bytes.Compare(nameA, nameB)
}

// Iterate calls the given function for each key-value pair in the B-tree
func (bt *BTree) Iterate(fn func(key, value []byte) bool) error {
	return bt.iterateNode(bt.rootNode, fn)
}

// iterateNode iterates through a B-tree node and its children
func (bt *BTree) iterateNode(node *BTreeNode, fn func(key, value []byte) bool) error {
	if (node.header.BtnFlags & BTNodeLeaf) != 0 {
		// Leaf node - process all key-value pairs
		for _, entry := range node.toc {
			if !fn(entry.Key, entry.Value) {
				return nil // Iteration stopped by callback
			}
		}
		return nil
	}

	// Internal node - recurse into children
	for _, entry := range node.toc {
		// Read child node pointer from value
		var childOID uint64
		if err := binary.Read(bytes.NewReader(entry.Value), binary.LittleEndian, &childOID); err != nil {
			return err
		}

		// Get child node
		childNodeData, err := bt.container.resolveObject(childOID, 0) // 0 for current transaction
		if err != nil {
			return err
		}

		// Parse child node
		childNode, err := bt.parseNode(childNodeData)
		if err != nil {
			return err
		}

		// Recursively iterate the child node
		if err := bt.iterateNode(childNode, fn); err != nil {
			return err
		}
	}

	return nil
}

// IterateRange iterates through keys in a specific range
func (bt *BTree) IterateRange(startKey, endKey []byte, fn func(key, value []byte) bool) error {
	return bt.iterateNodeRange(bt.rootNode, startKey, endKey, fn)
}

// iterateNodeRange iterates through a range of keys in a B-tree node and its children
func (bt *BTree) iterateNodeRange(node *BTreeNode, startKey, endKey []byte, fn func(key, value []byte) bool) error {
	if (node.header.BtnFlags & BTNodeLeaf) != 0 {
		// Leaf node - process key-value pairs in range
		for _, entry := range node.toc {
			// Skip keys less than startKey
			if startKey != nil && bt.compareKeys(entry.Key, startKey) < 0 {
				continue
			}
			// Stop at keys greater than endKey
			if endKey != nil && bt.compareKeys(entry.Key, endKey) > 0 {
				return nil
			}
			
			if !fn(entry.Key, entry.Value) {
				return nil // Iteration stopped by callback
			}
		}
		return nil
	}

	// Internal node - find relevant children and recurse
	for i, entry := range node.toc {
		// Skip children whose key range is entirely before startKey
		if i+1 < len(node.toc) && startKey != nil && bt.compareKeys(node.toc[i+1].Key, startKey) <= 0 {
			continue
		}
		
		// Stop at children whose key range is entirely after endKey
		if endKey != nil && bt.compareKeys(entry.Key, endKey) > 0 {
			return nil
		}

		// Read child node pointer from value
		var childOID uint64
		if err := binary.Read(bytes.NewReader(entry.Value), binary.LittleEndian, &childOID); err != nil {
			return err
		}

		// Get child node
		childNodeData, err := bt.container.resolveObject(childOID, 0) // 0 for current transaction
		if err != nil {
			return err
		}

		// Parse child node
		childNode, err := bt.parseNode(childNodeData)
		if err != nil {
			return err
		}

		// Recursively iterate the child node
		if err := bt.iterateNodeRange(childNode, startKey, endKey, fn); err != nil {
			return err
		}
	}

	return nil
}

// GetTreeInfo returns information about the B-tree
func (bt *BTree) GetTreeInfo() BTreeInfo {
	return *bt.info
}

// GetNodeCount returns the number of nodes in the B-tree
func (bt *BTree) GetNodeCount() uint64 {
	return bt.info.BtNodeCount
}

// GetKeyCount returns the number of keys in the B-tree
func (bt *BTree) GetKeyCount() uint64 {
	return bt.info.BtKeyCount
}

// IsFixedKV returns true if the B-tree uses fixed-size keys and values
func (bt *BTree) IsFixedKV() bool {
	return bt.info.BtFixed.BtKeySize > 0 && bt.info.BtFixed.BtValSize > 0
}

// GetTreeType returns the B-tree's type
func (bt *BTree) GetTreeType() uint32 {
	return bt.treeType
}

// GetTreeSubtype returns the B-tree's subtype
func (bt *BTree) GetTreeSubtype() uint32 {
	return bt.treeSubtype
}
