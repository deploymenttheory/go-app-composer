//
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Constants from APFS specification
const (
	// Magic values
	NXMagic   uint32 = 0x4253584E // 'BSXN'
	APFSMagic uint32 = 0x42535041 // 'BSPA'

	// Block sizes
	MinBlockSize   uint32 = 4096
	DefaultBlockSize uint32 = 4096
	MaxBlockSize   uint32 = 65536

	// Common constants
	MaxChecksumSize = 8
	OIDInvalid      uint64 = 0
	OIDNXSuperblock uint64 = 1
	OIDReservedCount uint64 = 1024
)

// ObjectType masks and values
const (
	ObjectTypeMask       uint32 = 0x0000ffff
	ObjectTypeFlagsMask  uint32 = 0xffff0000
	ObjStorageTypeMask   uint32 = 0xc0000000
	
	// Storage types
	ObjVirtual     uint32 = 0x00000000
	ObjEphemeral   uint32 = 0x80000000
	ObjPhysical    uint32 = 0x40000000
	
	// Object flags
	ObjNoheader    uint32 = 0x20000000
	ObjEncrypted   uint32 = 0x10000000
	ObjNonpersistent uint32 = 0x08000000
	
	// Object types
	ObjectTypeNXSuperblock uint32 = 0x00000001
	ObjectTypeBtree        uint32 = 0x00000002
	ObjectTypeBtreeNode    uint32 = 0x00000003
	ObjectTypeSpaceman     uint32 = 0x00000005
	ObjectTypeFS           uint32 = 0x0000000d
	// ... other object types as needed
)

// File system record types
const (
	APFSTypeAny           uint64 = 0
	APFSTypeSnapMetadata  uint64 = 1
	APFSTypeExtent        uint64 = 2
	APFSTypeInode         uint64 = 3
	APFSTypeXattr         uint64 = 4
	APFSTypeSiblingLink   uint64 = 5
	APFSTypeDstreamID     uint64 = 6
	APFSTypeCryptoState   uint64 = 7
	APFSTypeFileExtent    uint64 = 8
	APFSTypeDirRec        uint64 = 9
	APFSTypeDirStats      uint64 = 10
	APFSTypeSnapName      uint64 = 11
	APFSTypeSiblingMap    uint64 = 12
	APFSTypeFileInfo      uint64 = 13
	// ... other record types as needed
)

// ObjectPhys is the common header for all APFS objects
type ObjectPhys struct {
	Checksum    [MaxChecksumSize]byte
	OID         uint64 // Object identifier
	XID         uint64 // Transaction identifier
	Type        uint32 // Object type and flags
	Subtype     uint32 // Object subtype
}

// NXSuperblock represents the container superblock
type NXSuperblock struct {
	NXO                  ObjectPhys
	Magic                uint32
	BlockSize            uint32
	BlockCount           uint64
	Features             uint64
	ReadOnlyCompatFeatures uint64
	IncompatFeatures     uint64
	UUID                 [16]byte
	NextOID              uint64
	NextXID              uint64
	XPDescBlocks         uint32
	XPDataBlocks         uint32
	XPDescBase           uint64 // paddr_t
	XPDataBase           uint64 // paddr_t
	XPDescNext           uint32
	XPDataNext           uint32
	XPDescIndex          uint32
	XPDescLen            uint32
	XPDataIndex          uint32
	XPDataLen            uint32
	SpacemanOID          uint64
	OMapOID              uint64
	ReaperOID            uint64
	TestType             uint32
	MaxFileSystems       uint32
	FSOID                [100]uint64 // NX_MAX_FILE_SYSTEMS
	Counters             [32]uint64  // NX_NUM_COUNTERS
	BlockedOutPRangeStart uint64
	BlockedOutPRangeBlocks uint64
	EvictMappingTreeOID  uint64
	Flags                uint64
	EFIJumpStart         uint64 // paddr_t
	FusionUUID           [16]byte
	KeyLocker            struct {
		Start uint64 // paddr_t
		Blocks uint64
	}
	EphemeralInfo       [4]uint64 // NX_EPH_INFO_COUNT
	TestOID             uint64
	FusionMTOID         uint64
	FusionWBCOID        uint64
	FusionWBC           struct {
		Start uint64 // paddr_t
		Blocks uint64
	}
	NewestMountedVersion uint64
	MKBLocker           struct {
		Start uint64 // paddr_t
		Blocks uint64
	}
}

// APFSSuperblock represents the volume superblock
type APFSSuperblock struct {
	APFSO                ObjectPhys
	Magic                uint32
	FSIndex              uint32
	Features             uint64
	ReadOnlyCompatFeatures uint64
	IncompatFeatures     uint64
	UnmountTime          uint64
	FSReserveBlockCount  uint64
	FSQuotaBlockCount    uint64
	FSAllocCount         uint64
	MetaCrypto           WrappedMetaCryptoState
	RootTreeType         uint32
	ExtentrefTreeType    uint32
	SnapMetaTreeType     uint32
	OMapOID              uint64
	RootTreeOID          uint64
	ExtentrefTreeOID     uint64
	SnapMetaTreeOID      uint64
	RevertToXID          uint64
	RevertToSblockOID    uint64
	NextObjID            uint64
	NumFiles             uint64
	NumDirectories       uint64
	NumSymlinks          uint64
	NumOtherFSObjects    uint64
	NumSnapshots         uint64
	TotalBlocksAlloced   uint64
	TotalBlocksFreed     uint64
	VolUUID              [16]byte
	LastModTime          uint64
	FSFlags              uint64
	FormattedBy          APFSModifiedBy
	ModifiedBy           [8]APFSModifiedBy // APFS_MAX_HIST
	VolName              [256]byte         // APFS_VOLNAME_LEN
	NextDocID            uint32
	Role                 uint16
	Reserved             uint16
	RootToXID            uint64
	ERStateOID           uint64
	CloneinfoIDEpoch     uint64
	CloneinfoXID         uint64
	SnapMetaExtOID       uint64
	VolumeGroupID        [16]byte
	IntegrityMetaOID     uint64
	FextTreeOID          uint64
	FextTreeType         uint32
	ReservedType         uint32
	ReservedOID          uint64
}

// APFSModifiedBy contains information about software that modified the volume
type APFSModifiedBy struct {
	ID        [32]byte // APFS_MODIFIED_NAMELEN
	Timestamp uint64
	LastXID   uint64
}

// WrappedMetaCryptoState contains information about volume encryption
type WrappedMetaCryptoState struct {
	MajorVersion  uint16
	MinorVersion  uint16
	CPFlags       uint32 // crypto_flags_t
	PersistentClass uint32 // cp_key_class_t
	KeyOSVersion  uint32 // cp_key_os_version_t
	KeyRevision   uint16 // cp_key_revision_t
	Unused        uint16
}

// CheckPointMappingBlock represents a checkpoint mapping block
type CheckPointMappingBlock struct {
	CpmO      ObjectPhys
	CpmFlags  uint32
	CpmCount  uint32
	CpmMap    []CheckPointMapping
}

// CheckPointMapping maps an ephemeral object to its location
type CheckPointMapping struct {
	CpmType   uint32
	CpmSubtype uint32
	CpmSize   uint32
	CpmPad    uint32
	CpmFsOID  uint64
	CpmOID    uint64
	CpmPaddr  uint64 // paddr_t
}

// OMapPhys represents an object map
type OMapPhys struct {
	OmO                ObjectPhys
	OmFlags            uint32
	OmSnapCount        uint32
	OmTreeType         uint32
	OmSnapshotTreeType uint32
	OmTreeOID          uint64
	OmSnapshotTreeOID  uint64
	OmMostRecentSnap   uint64
	OmPendingRevertMin uint64
	OmPendingRevertMax uint64
}

// OMapKey is a key in the object map
type OMapKey struct {
	OkOID uint64
	OkXID uint64
}

// OMapVal is a value in the object map
type OMapVal struct {
	OvFlags uint32
	OvSize  uint32
	OvPaddr uint64 // paddr_t
}

// BTreeNodePhys represents a B-tree node
type BTreeNodePhys struct {
	BtnO           ObjectPhys
	BtnFlags       uint16
	BtnLevel       uint16
	BtnNkeys       uint32
	BtnTableSpace  NLoc
	BtnFreeSpace   NLoc
	BtnKeyFreeList NLoc
	BtnValFreeList NLoc
	// BtnData is variable length and handled separately
}

// NLoc represents a location within a B-tree node
type NLoc struct {
	Off uint16
	Len uint16
}

// KVLoc represents the location of a key-value pair in a B-tree node
type KVLoc struct {
	K NLoc
	V NLoc
}

// KVOff represents the location of a fixed-size key-value pair
type KVOff struct {
	K uint16
	V uint16
}

// BTreeInfoFixed contains static information about a B-tree
type BTreeInfoFixed struct {
	BtFlags    uint32
	BtNodeSize uint32
	BtKeySize  uint32
	BtValSize  uint32
}

// BTreeInfo contains information about a B-tree
type BTreeInfo struct {
	BtFixed      BTreeInfoFixed
	BtLongestKey uint32
	BtLongestVal uint32
	BtKeyCount   uint64
	BtNodeCount  uint64
}

// Parse reads a nx_superblock_t from a byte array
func (sb *NXSuperblock) Parse(data []byte) error {
	if len(data) < binary.Size(NXSuperblock{}) {
		return fmt.Errorf("data too short to contain NXSuperblock")
	}

	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, sb); err != nil {
		return err
	}

	// Verify magic number
	if sb.Magic != NXMagic {
		return fmt.Errorf("invalid NX magic number: %x, expected %x", sb.Magic, NXMagic)
	}

	return nil
}

// Parse reads an apfs_superblock_t from a byte array
func (sb *APFSSuperblock) Parse(data []byte) error {
	if len(data) < binary.Size(APFSSuperblock{}) {
		return fmt.Errorf("data too short to contain APFSSuperblock")
	}

	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, sb); err != nil {
		return err
	}

	// Verify magic number
	if sb.Magic != APFSMagic {
		return fmt.Errorf("invalid APFS magic number: %x, expected %x", sb.Magic, APFSMagic)
	}

	return nil
}

// IsVirtual returns true if the object is virtual
func (o *ObjectPhys) IsVirtual() bool {
	return (o.Type & ObjStorageTypeMask) == ObjVirtual
}

// IsEphemeral returns true if the object is ephemeral
func (o *ObjectPhys) IsEphemeral() bool {
	return (o.Type & ObjStorageTypeMask) == ObjEphemeral
}

// IsPhysical returns true if the object is physical
func (o *ObjectPhys) IsPhysical() bool {
	return (o.Type & ObjStorageTypeMask) == ObjPhysical
}

// GetObjectType returns the base object type without flags
func (o *ObjectPhys) GetObjectType() uint32 {
	return o.Type & ObjectTypeMask
}

// IsEncrypted returns true if the object is encrypted
func (o *ObjectPhys) IsEncrypted() bool {
	return (o.Type & ObjEncrypted) != 0
}

// HasHeader returns true if the object has a header
func (o *ObjectPhys) HasHeader() bool {
	return (o.Type & ObjNoheader) == 0
}

// File system record structures

// JKey is the base type for all file system record keys
type JKey struct {
	ObjIDAndType uint64
}

// ObjIDMask is used to extract the object ID from ObjIDAndType
const ObjIDMask uint64 = 0x0fffffffffffffffULL

// ObjTypeMask is used to extract the object type from ObjIDAndType
const ObjTypeMask uint64 = 0xf000000000000000ULL

// ObjTypeShift is the bit shift to get the object type
const ObjTypeShift uint64 = 60

// SystemObjIDMark is the smallest object ID used by the system volume
const SystemObjIDMark uint64 = 0x0fffffff00000000ULL

// JInodeKey is the key for an inode record
type JInodeKey struct {
	Hdr JKey
}

// JInodeVal is the value for an inode record
type JInodeVal struct {
	ParentID              uint64
	PrivateID             uint64
	CreateTime            uint64
	ModTime               uint64
	ChangeTime            uint64
	AccessTime            uint64
	InternalFlags         uint64
	NChildren             int32  // Union with NLink
	DefaultProtectionClass uint32
	WriteGenerationCounter uint32
	BSDFlags              uint32
	Owner                 uint32
	Group                 uint32
	Mode                  uint16
	Pad1                  uint16
	UncompressedSize      uint64
	// XFields variable length, handled separately
}

// JDrecKey is the key half of a directory entry record
type JDrecKey struct {
	Hdr     JKey
	NameLen uint16
	// Name variable length, handled separately
}

// JDrecHashedKey is the key half of a directory entry with a hash
type JDrecHashedKey struct {
	Hdr            JKey
	NameLenAndHash uint32
	// Name variable length, handled separately
}

// JDrecHashMask is used to extract the hash from NameLenAndHash
const JDrecHashMask uint32 = 0xfffff400

// JDrecLenMask is used to extract the name length from NameLenAndHash
const JDrecLenMask uint32 = 0x000003ff

// JDrecHashShift is the bit shift to get the hash
const JDrecHashShift uint32 = 10

// JDrecVal is the value half of a directory entry record
type JDrecVal struct {
	FileID     uint64
	DateAdded  uint64
	Flags      uint16
	// XFields variable length, handled separately
}

// JDirStatsKey is the key half of a directory statistics record
type JDirStatsKey struct {
	Hdr JKey
}

// JDirStatsVal is the value half of a directory statistics record
type JDirStatsVal struct {
	NumChildren uint64
	TotalSize   uint64
	ChainedKey  uint64
	GenCount    uint64
}

// JXattrKey is the key half of an extended attribute record
type JXattrKey struct {
	Hdr     JKey
	NameLen uint16
	// Name variable length, handled separately
}

// JXattrVal is the value half of an extended attribute record
type JXattrVal struct {
	Flags    uint16
	XDataLen uint16
	// XData variable length, handled separately
}

// XattrFlags are the flags for extended attributes
const (
	XattrDataStream    uint16 = 0x0001
	XattrDataEmbedded  uint16 = 0x0002
	XattrFileSystemOwned uint16 = 0x0004
	XattrReserved8     uint16 = 0x0008
)

// JPhysExtKey is the key half of a physical extent record
type JPhysExtKey struct {
	Hdr JKey
}

// JPhysExtVal is the value half of a physical extent record
type JPhysExtVal struct {
	LenAndKind    uint64
	OwningObjID   uint64
	RefCnt        int32
}

// PextLenMask is used to extract the length from LenAndKind
const PextLenMask uint64 = 0x0fffffffffffffffULL

// PextKindMask is used to extract the kind from LenAndKind
const PextKindMask uint64 = 0xf000000000000000ULL

// PextKindShift is the bit shift to get the kind
const PextKindShift uint64 = 60

// JFileExtentKey is the key half of a file extent record
type JFileExtentKey struct {
	Hdr         JKey
	LogicalAddr uint64
}

// JFileExtentVal is the value half of a file extent record
type JFileExtentVal struct {
	LenAndFlags   uint64
	PhysBlockNum  uint64
	CryptoID      uint64
}

// JFileExtentLenMask is used to extract the length from LenAndFlags
const JFileExtentLenMask uint64 = 0x00ffffffffffffffULL

// JFileExtentFlagMask is used to extract the flags from LenAndFlags
const JFileExtentFlagMask uint64 = 0xff00000000000000ULL

// JFileExtentFlagShift is the bit shift to get the flags
const JFileExtentFlagShift uint64 = 56

// JDstreamIDKey is the key half of a data stream record
type JDstreamIDKey struct {
	Hdr JKey
}

// JDstreamIDVal is the value half of a data stream record
type JDstreamIDVal struct {
	RefCnt uint32
}

// JXattrDstream is a data stream for extended attributes
type JXattrDstream struct {
	XattrObjID uint64
	Dstream    JDstream
}

// JDstream contains information about a data stream
type JDstream struct {
	Size              uint64
	AllocedSize       uint64
	DefaultCryptoID   uint64
	TotalBytesWritten uint64
	TotalBytesRead    uint64
}

// JSiblingKey is the key half of a sibling record
type JSiblingKey struct {
	Hdr       JKey
	SiblingID uint64
}

// JSiblingVal is the value half of a sibling record
type JSiblingVal struct {
	ParentID uint64
	NameLen  uint16
	// Name variable length, handled separately
}

// JSiblingMapKey is the key half of a sibling map record
type JSiblingMapKey struct {
	Hdr JKey
}

// JSiblingMapVal is the value half of a sibling map record
type JSiblingMapVal struct {
	FileID uint64
}

// JSnapMetadataKey is the key half of a snapshot metadata record
type JSnapMetadataKey struct {
	Hdr JKey
}

// JSnapMetadataVal is the value half of a snapshot metadata record
type JSnapMetadataVal struct {
	ExtentrefTreeOID   uint64
	SblockOID          uint64
	CreateTime         uint64
	ChangeTime         uint64
	Inum               uint64
	ExtentrefTreeType  uint32
	Flags              uint32
	NameLen            uint16
	// Name variable length, handled separately
}

// JSnapNameKey is the key half of a snapshot name record
type JSnapNameKey struct {
	Hdr     JKey
	NameLen uint16
	// Name variable length, handled separately
}

// JSnapNameVal is the value half of a snapshot name record
type JSnapNameVal struct {
	SnapXID uint64
}

// Encryption structures

// WrappedCryptoState is a wrapped key used for per-file encryption
type WrappedCryptoState struct {
	MajorVersion    uint16
	MinorVersion    uint16
	CPFlags         uint32 // crypto_flags_t
	PersistentClass uint32 // cp_key_class_t
	KeyOSVersion    uint32 // cp_key_os_version_t
	KeyRevision     uint16 // cp_key_revision_t
	KeyLen          uint16
	// PersistentKey variable length, handled separately
}

// CPMaxWrappedKeySize is the size of the largest possible key
const CPMaxWrappedKeySize = 128

// JCryptoKey is the key half of a per-file encryption state record
type JCryptoKey struct {
	Hdr JKey
}

// JCryptoVal is the value half of a per-file encryption state record
type JCryptoVal struct {
	RefCnt uint32
	State  WrappedCryptoState
}

// Protection classes
const (
	ProtectionClassDirNone uint32 = 0
	ProtectionClassA      uint32 = 1
	ProtectionClassB      uint32 = 2
	ProtectionClassC      uint32 = 3
	ProtectionClassD      uint32 = 4
	ProtectionClassF      uint32 = 6
	ProtectionClassM      uint32 = 14
	CPEffectiveClassMask  uint32 = 0x0000001f
)

// Keybag structures

// KBLocker is a keybag
type KBLocker struct {
	KlVersion uint16
	KlNkeys   uint16
	KlNbytes  uint32
	Padding   [8]byte
	// KlEntries variable length, handled separately
}

// KeybagEntry is an entry in a keybag
type KeybagEntry struct {
	KeUUID   [16]byte
	KeTag    uint16
	KeKeylen uint16
	Padding  [4]byte
	// KeKeydata variable length, handled separately
}

// APFSKeybagVersion is the first version of the keybag
const APFSKeybagVersion = 2

// APFSVolKeybagEntryMaxSize is the largest size of a keybag entry
const APFSVolKeybagEntryMaxSize = 512

// APFSFVPersonalRecoveryKeyUUID is the UUID for personal recovery keys
const APFSFVPersonalRecoveryKeyUUID = "EBC6C064-0000-11AA-AA11-00306543ECAC"

// Keybag tags
const (
	KBTagUnknown             = 0
	KBTagReserved1           = 1
	KBTagVolumeKey           = 2
	KBTagVolumeUnlockRecords = 3
	KBTagVolumePassphraseHint = 4
	KBTagWrappingMKey        = 5
	KBTagVolumeMKey          = 6
	KBTagReservedF8          = 0xF8
)

// MediaKeybag is a keybag wrapped up as a container-layer object
type MediaKeybag struct {
	MkObj    ObjectPhys
	MkLocker KBLocker
}

// File system constants

// The constants for inode numbers
const (
	InvalidInoNum       = 0
	RootDirParent       = 1
	RootDirInoNum       = 2
	PrivDirInoNum       = 3
	SnapDirInoNum       = 6
	PurgeableDirInoNum  = 7
	MinUserInoNum       = 16
	UnifiedIDSpaceMark  = 0x0800000000000000
)

// Extended attribute constants
const (
	XattrMaxEmbeddedSize     = 3804
	SymlinkEAName            = "com.apple.fs.symlink"
	FirmlinkEAName           = "com.apple.fs.firmlink"
	APFSCowExemptCountName   = "com.apple.fs.cow-exempt-file-count"
)

// Inode flags
const (
	InodeIsAPFSPrivate          uint64 = 0x00000001
	InodeMaintainDirStats       uint64 = 0x00000002
	InodeDirStatsOrigin         uint64 = 0x00000004
	InodeProtClassExplicit      uint64 = 0x00000008
	InodeWasCloned              uint64 = 0x00000010
	InodeFlagUnused             uint64 = 0x00000020
	InodeHasSecurityEA          uint64 = 0x00000040
	InodeBeingTruncated         uint64 = 0x00000080
	InodeHasFinderInfo          uint64 = 0x00000100
	InodeIsSparse               uint64 = 0x00000200
	InodeWasEverCloned          uint64 = 0x00000400
	InodeActiveFileTrimmed      uint64 = 0x00000800
	InodePinnedToMain           uint64 = 0x00001000
	InodePinnedToTier2          uint64 = 0x00002000
	InodeHasRsrcFork            uint64 = 0x00004000
	InodeNoRsrcFork             uint64 = 0x00008000
	InodeAllocationSpilledover  uint64 = 0x00010000
	InodeFastPromote            uint64 = 0x00020000
	InodeHasUncompressedSize    uint64 = 0x00040000
	InodeIsPurgeable            uint64 = 0x00080000
	InodeWantsToBePurgeable     uint64 = 0x00100000
	InodeIsSyncRoot             uint64 = 0x00200000
	InodeSnapshotCowExemption   uint64 = 0x00400000
)

// File modes
const (
	SIfmt  uint16 = 0170000
	SIfifo uint16 = 0010000
	SIfchr uint16 = 0020000
	SIfdir uint16 = 0040000
	SIfblk uint16 = 0060000
	SIfreg uint16 = 0100000
	SIflnk uint16 = 0120000
	SIfsock uint16 = 0140000
	SIfwht uint16 = 0160000
)

// Directory entry file types
const (
	DTUnknown = 0
	DTFifo    = 1
	DTChr     = 2
	DTDir     = 4
	DTBlk     = 6
	DTReg     = 8
	DTLnk     = 10
	DTSock    = 12
	DTWht     = 14
)

// Extended field types
const (
	DrecExtTypeSiblingID       = 1
	InoExtTypeSnapXID          = 1
	InoExtTypeDeltaTreeOID     = 2
	InoExtTypeDocumentID       = 3
	InoExtTypeName             = 4
	InoExtTypePrevFsize        = 5
	InoExtTypeReserved6        = 6
	InoExtTypeFinderInfo       = 7
	InoExtTypeDstream          = 8
	InoExtTypeReserved9        = 9
	InoExtTypeDirStatsKey      = 10
	InoExtTypeFSUUID           = 11
	InoExtTypeReserved12       = 12
	InoExtTypeSparseBytes      = 13
	InoExtTypeRdev             = 14
	InoExtTypePurgeableFlags   = 15
	InoExtTypeOrigSyncRootID   = 16
)

// Extended field flags
const (
	XFDataDependent    uint16 = 0x0001
	XFDoNotCopy        uint16 = 0x0002
	XFReserved4        uint16 = 0x0004
	XFChildrenInherit  uint16 = 0x0008
	XFUserField        uint16 = 0x0010
	XFSystemField      uint16 = 0x0020
	XFReserved40       uint16 = 0x0040
	XFReserved80       uint16 = 0x0080
)

// B-tree flags
const (
	BTREEUint64Keys       uint32 = 0x00000001
	BTREESequentialInsert uint32 = 0x00000002
	BTREEAllowGhosts      uint32 = 0x00000004
	BTREEEphemeral        uint32 = 0x00000008
	BTREEPhysical         uint32 = 0x00000010
	BTREENonpersistent    uint32 = 0x00000020
	BTREEKvNonaligned     uint32 = 0x00000040
	BTREEHashed           uint32 = 0x00000080
	BTREENoheader         uint32 = 0x00000100
)

// B-tree node flags
const (
	BTNodeRoot             uint16 = 0x0001
	BTNodeLeaf             uint16 = 0x0002
	BTNodeFixedKVSize      uint16 = 0x0004
	BTNodeHashed           uint16 = 0x0008
	BTNodeNoheader         uint16 = 0x0010
	BTNodeCheckKoffInval   uint16 = 0x8000
)

// APFS volume flags
const (
	APFSFSUnencrypted         uint64 = 0x00000001
	APFSFSReserved2           uint64 = 0x00000002
	APFSFSReserved4           uint64 = 0x00000004
	APFSFSOnekey              uint64 = 0x00000008
	APFSFSSpilledover         uint64 = 0x00000010
	APFSFSRunSpilloverCleaner uint64 = 0x00000020
	APFSFSAlwaysCheckExtentref uint64 = 0x00000040
	APFSFSReserved80          uint64 = 0x00000080
	APFSFSReserved100         uint64 = 0x00000100
)

// APFS volume roles
const (
	APFSVolRoleNone       uint16 = 0x0000
	APFSVolRoleSystem     uint16 = 0x0001
	APFSVolRoleUser       uint16 = 0x0002
	APFSVolRoleRecovery   uint16 = 0x0004
	APFSVolRoleVM         uint16 = 0x0008
	APFSVolRolePreboot    uint16 = 0x0010
	APFSVolRoleInstaller  uint16 = 0x0020
	APFSVolumeEnumShift   uint16 = 6
	APFSVolRoleData       uint16 = 1 << APFSVolumeEnumShift
	APFSVolRoleBaseband   uint16 = 2 << APFSVolumeEnumShift
	APFSVolRoleUpdate     uint16 = 3 << APFSVolumeEnumShift
	APFSVolRoleXart       uint16 = 4 << APFSVolumeEnumShift
	APFSVolRoleHardware   uint16 = 5 << APFSVolumeEnumShift
	APFSVolRoleBackup     uint16 = 6 << APFSVolumeEnumShift
	APFSVolRoleReserved7  uint16 = 7 << APFSVolumeEnumShift
	APFSVolRoleReserved8  uint16 = 8 << APFSVolumeEnumShift
	APFSVolRoleEnterprise uint16 = 9 << APFSVolumeEnumShift
	APFSVolRoleReserved10 uint16 = 10 << APFSVolumeEnumShift
	APFSVolRolePrelogin   uint16 = 11 << APFSVolumeEnumShift
)

// APFS feature flags
const (
	APFSFeatureDefragPrerelease   uint64 = 0x00000001
	APFSFeatureHardlinkMapRecords uint64 = 0x00000002
	APFSFeatureDefrag             uint64 = 0x00000004
	APFSFeatureStrictatime        uint64 = 0x00000008
	APFSFeatureVolgrpSystemInoSpace uint64 = 0x00000010
)

// APFS incompatible feature flags
const (
	APFSIncompatCaseInsensitive      uint64 = 0x00000001
	APFSIncompatDatalessSnaps        uint64 = 0x00000002
	APFSIncompatEncRolled            uint64 = 0x00000004
	APFSIncompatNormalizationInsensitive uint64 = 0x00000008
	APFSIncompatIncompleteRestore    uint64 = 0x00000010
	APFSIncompatSealedVolume         uint64 = 0x00000020
	APFSIncompatReserved40           uint64 = 0x00000040
)

// Sealed volume structures

// IntegrityMetaPhys contains integrity metadata for a sealed volume
type IntegrityMetaPhys struct {
	ImO            ObjectPhys
	ImVersion      uint32
	ImFlags        uint32
	ImHashType     uint32 // apfs_hash_type_t
	ImRootHashOffset uint32
	ImBrokenXid    uint64
	ImReserved     [9]uint64
}

// Integrity metadata version constants
const (
	IntegrityMetaVersionInvalid = 0
	IntegrityMetaVersion1       = 1
	IntegrityMetaVersion2       = 2
	IntegrityMetaVersionHighest = IntegrityMetaVersion2
)

// Integrity metadata flags
const (
	APFSSealBroken uint32 = 1 << 0
)

// Hash type constants
const (
	APFSHashInvalid    uint32 = 0
	APFSHashSHA256     uint32 = 0x1
	APFSHashSHA512_256 uint32 = 0x2
	APFSHashSHA384     uint32 = 0x3
	APFSHashSHA512     uint32 = 0x4
)

// Hash size constants
const (
	APFSHashCCSHA256Size     = 32
	APFSHashCCSHA512_256Size = 32
	APFSHashCCSHA384Size     = 48
	APFSHashCCSHA512Size     = 64
	APFSHashMaxSize          = 64
)

// XfBlob is a collection of extended attributes
type XfBlob struct {
	XfNumExts  uint16
	XfUsedData uint16
	// XfData variable length, handled separately
}

// XField is an extended field's metadata
type XField struct {
	XType  uint8
	XFlags uint8
	XSize  uint16
}
