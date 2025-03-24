// fs_objects.go
/*
Defines core file system structures from Apple's APFS reference PDF clearly and precisely:

Inode structures (j_inode_key_t, j_inode_val_t)

Directory entries (j_drec_key_t, j_drec_val_t)

Extended attributes (j_xattr_key_t, j_xattr_val_t)

Provides robust and idiomatic Go methods for:

Parsing from raw binary data.

Serialization back into binary format.

*/
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"time"
)

// JKey represents a generic APFS filesystem record key (j_key_t)
type JKey struct {
	ObjID uint64
	Type  uint8
	Pad   [7]byte
}

// JFileSystemRecordType constants from APFS specification
const (
	APFS_TYPE_INODE   uint8 = 3
	APFS_TYPE_DREC    uint8 = 9
	APFS_TYPE_XATTR   uint8 = 4
	APFS_TYPE_SIBLING uint8 = 5
)

// JInodeKey represents an inode key (j_inode_key_t)
type JInodeKey struct {
	Header JKey
}

// JInodeVal represents inode value (j_inode_val_t)
type JInodeVal struct {
	ParentID      uint64
	PrivateID     uint64
	CreateTime    uint64
	ModifyTime    uint64
	ChangeTime    uint64
	AccessTime    uint64
	InternalFlags uint64
	Flags         uint32
	Nlink         uint32
	Uid           uint32
	Gid           uint32
	Mode          uint16
	Pad1          uint16
	Pad2          uint32
	Size          uint64
	Blocks        uint64
	DStream       JDstream
}

// JDrecKey represents a directory record key (j_drec_key_t)
type JDrecKey struct {
	Header  JKey
	NameLen uint16
	Hash    uint16
	Name    []byte
}

// JDrecVal represents a directory record value (j_drec_val_t)
type JDrecVal struct {
	FileID    uint64
	DateAdded uint64
	Flags     uint16
	Pad       [6]byte
}

// JXattrKey represents an extended attribute key (j_xattr_key_t)
type JXattrKey struct {
	Header  JKey
	NameLen uint16
	Name    []byte
}

// JXattrVal represents extended attribute value (j_xattr_val_t)
type JXattrVal struct {
	Flags uint16
	Size  uint16
	Data  []byte
}

// Implement Parse and Serialize methods for each structure

// ParseJInodeKey parses an inode key from bytes
func ParseJInodeKey(data []byte) (*JInodeKey, error) {
	if len(data) < binary.Size(JInodeKey{}) {
		return nil, ErrStructTooShort
	}
	var key JInodeKey
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &key)
	return &key, err
}

// Serialize serializes an inode key into bytes
func (key *JInodeKey) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, key)
	return buf.Bytes(), err
}

// ParseJInodeVal parses inode values from bytes
func ParseJInodeVal(data []byte) (*JInodeVal, error) {
	if len(data) < binary.Size(JInodeVal{}) {
		return nil, ErrStructTooShort
	}
	var val JInodeVal
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &val)
	return &val, err
}

// Serialize serializes inode values into bytes
func (val *JInodeVal) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, val)
	return buf.Bytes(), err
}

// ParseJDrecKey parses a directory record key from bytes
func ParseJDrecKey(data []byte) (*JDrecKey, error) {
	if len(data) < 12 { // Minimum size without Name
		return nil, ErrStructTooShort
	}
	var key JDrecKey
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &key.Header); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &key.NameLen); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &key.Hash); err != nil {
		return nil, err
	}
	key.Name = make([]byte, key.NameLen)
	if err := binary.Read(r, binary.LittleEndian, &key.Name); err != nil {
		return nil, err
	}
	return &key, nil
}

// ParseJDrecVal parses directory record values from bytes
func ParseJDrecVal(data []byte) (*JDrecVal, error) {
	if len(data) < binary.Size(JDrecVal{}) {
		return nil, ErrStructTooShort
	}
	var val JDrecVal
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &val)
	return &val, err
}

// String methods for debugging and logging
func (key *JInodeKey) String() string {
	return fmt.Sprintf("JInodeKey{ObjID: %d}", key.Header.ObjID)
}

func (val *JInodeVal) String() string {
	return fmt.Sprintf("JInodeVal{Size: %d, Mode: %o}", val.Size, val.Mode)
}

func (key *JDrecKey) String() string {
	return fmt.Sprintf("JDrecKey{Name: %s}", string(key.Name))
}

func (val *JDrecVal) String() string {
	return fmt.Sprintf("JDrecVal{FileID: %d, DateAdded: %d}", val.FileID, val.DateAdded)
}

func (val *JInodeVal) IsDirectory() bool {
	return val.Mode&0o040000 != 0
}

func (val *JInodeVal) IsSymlink() bool {
	return val.Mode&0o120000 != 0
}

func (val *JInodeVal) IsRegularFile() bool {
	return val.Mode&0o100000 != 0
}

func (val *JInodeVal) CreatedAt() time.Time {
	return time.Unix(int64(val.CreateTime/1e9), int64(val.CreateTime%1e9))
}

func (key *JDrecKey) FileName() string {
	return string(key.Name)
}

func (val *JDrecVal) AddedAt() time.Time {
	return time.Unix(int64(val.DateAdded/1e9), int64(val.DateAdded%1e9))
}

func (key *JXattrKey) AttributeName() string {
	return string(key.Name)
}

func (val *JInodeVal) HasFlag(flag uint32) bool {
	return val.Flags&flag != 0
}

func CalculateDrecHash(name string) uint16 {
	h := fnv.New32a()
	h.Write([]byte(name))
	return uint16(h.Sum32())
}
