// types.go
// Package apfs provides Go types and functions for working with Apple File System (APFS).
package apfs

import (
	"errors"
)

// Common error definitions
var (
	ErrInvalidChecksum       = errors.New("invalid checksum")
	ErrInvalidMagic          = errors.New("invalid magic number")
	ErrInvalidBlockSize      = errors.New("invalid block size")
	ErrUnsupportedVersion    = errors.New("unsupported APFS version")
	ErrInvalidBlockAddress   = errors.New("invalid block address")
	ErrNoValidCheckpoint     = errors.New("no valid checkpoint found")
	ErrStructTooShort        = errors.New("data too short for structure")
	ErrInvalidObjectType     = errors.New("invalid object type")
	ErrInvalidNameLength     = errors.New("invalid name length")
	ErrVariableLengthMissing = errors.New("variable length field missing")
)

// Magic values from APFS specification
const (
	NXMagic           uint32 = 0x4253584E // 'NXSB' (reversed due to little endian)
	APFSMagic         uint32 = 0x42535041 // 'APSB' (reversed due to little endian)
	EFIJumpstartMagic uint32 = 0x5244534A // 'JSDR' (reversed due to little endian)
)

// Block size constants from APFS specification
const (
	MinimumBlockSize     uint32 = 4096
	DefaultBlockSize     uint32 = 4096
	MaximumBlockSize     uint32 = 65536
	MinimumContainerSize uint64 = 1048576
)

// Common constants from APFS specification
const (
	MaxChecksumSize         = 8
	OIDInvalid       uint64 = 0
	OIDNXSuperblock  uint64 = 1
	OIDReservedCount uint64 = 1024
)

// Object type masks and values
const (
	ObjectTypeMask             uint32 = 0x0000ffff
	ObjectTypeFlagsMask        uint32 = 0xffff0000
	ObjStorageTypeMask         uint32 = 0xc0000000
	ObjectTypeFlagsDefinedMask uint32 = 0xf8000000

	// Storage types
	ObjVirtual   uint32 = 0x00000000
	ObjEphemeral uint32 = 0x80000000
	ObjPhysical  uint32 = 0x40000000

	// Object flags
	ObjNoheader      uint32 = 0x20000000
	ObjEncrypted     uint32 = 0x10000000
	ObjNonpersistent uint32 = 0x08000000

	// Object types
	ObjectTypeInvalid           uint32 = 0x00000000
	ObjectTypeNXSuperblock      uint32 = 0x00000001
	ObjectTypeBtree             uint32 = 0x00000002
	ObjectTypeBtreeNode         uint32 = 0x00000003
	ObjectTypeSpaceman          uint32 = 0x00000005
	ObjectTypeSpacemanCAB       uint32 = 0x00000006
	ObjectTypeSpacemanCIB       uint32 = 0x00000007
	ObjectTypeSpacemanBitmap    uint32 = 0x00000008
	ObjectTypeSpacemanFreeQueue uint32 = 0x00000009
	ObjectTypeExtentListTree    uint32 = 0x0000000a
	ObjectTypeOMAP              uint32 = 0x0000000b
	ObjectTypeCheckpointMap     uint32 = 0x0000000c
	ObjectTypeFS                uint32 = 0x0000000d
	ObjectTypeFSTree            uint32 = 0x0000000e
	ObjectTypeBlockreftree      uint32 = 0x0000000f
	ObjectTypeSnapMetatree      uint32 = 0x00000010
	ObjectTypeNXReaper          uint32 = 0x00000011
	ObjectTypeNXReapList        uint32 = 0x00000012
	ObjectTypeOMAPSnapshot      uint32 = 0x00000013
	ObjectTypeEFIJumpstart      uint32 = 0x00000014
	ObjectTypeFusionMiddleTree  uint32 = 0x00000015
	ObjectTypeNXFusionWBC       uint32 = 0x00000016
	ObjectTypeNXFusionWBCList   uint32 = 0x00000017
	ObjectTypeERState           uint32 = 0x00000018
	ObjectTypeGbitmap           uint32 = 0x00000019
	ObjectTypeGbitmapTree       uint32 = 0x0000001a
	ObjectTypeGbitmapBlock      uint32 = 0x0000001b
	ObjectTypeERRecoveryBlock   uint32 = 0x0000001c
	ObjectTypeSnapMetaExt       uint32 = 0x0000001d
	ObjectTypeIntegrityMeta     uint32 = 0x0000001e
	ObjectTypeFextTree          uint32 = 0x0000001f
	ObjectTypeReserved20        uint32 = 0x00000020
	ObjectTypeTest              uint32 = 0x000000ff
	ObjectTypeContainerKeybag   uint32 = 0x6B657973 // 'keys'
	ObjectTypeVolumeKeybag      uint32 = 0x72656373 // 'recs'
	ObjectTypeMediaKeybag       uint32 = 0x6D6B6579 // 'mkey'
)

// File system record types
const (
	APFSTypeAny          uint64 = 0
	APFSTypeSnapMetadata uint64 = 1
	APFSTypeExtent       uint64 = 2
	APFSTypeInode        uint64 = 3
	APFSTypeXattr        uint64 = 4
	APFSTypeSiblingLink  uint64 = 5
	APFSTypeDstreamID    uint64 = 6
	APFSTypeCryptoState  uint64 = 7
	APFSTypeFileExtent   uint64 = 8
	APFSTypeDirRec       uint64 = 9
	APFSTypeDirStats     uint64 = 10
	APFSTypeSnapName     uint64 = 11
	APFSTypeSiblingMap   uint64 = 12
	APFSTypeFileInfo     uint64 = 13
	APFSTypeMaxValid     uint64 = 13
	APFSTypeMax          uint64 = 15
	APFSTypeInvalid      uint64 = 15
)

// J_obj_kinds - record kind values for file system records
const (
	APFSKindAny          uint8 = 0
	APFSKindNew          uint8 = 1
	APFSKindUpdate       uint8 = 2
	APFSKindDead         uint8 = 3
	APFSKindUpdateRefcnt uint8 = 4
	APFSKindInvalid      uint8 = 255
)

// Container flag constants
const (
	NXReserved1 uint64 = 0x00000001
	NXReserved2 uint64 = 0x00000002
	NXCryptoSW  uint64 = 0x00000004
)

// Optional container feature flags
const (
	NXFeatureDefrag         uint64 = 0x0000000000000001
	NXFeatureLCFD           uint64 = 0x0000000000000002
	NXSupportedFeaturesMask uint64 = NXFeatureDefrag | NXFeatureLCFD
)

// Incompatible container feature flags
const (
	NXIncompatVersion1      uint64 = 0x0000000000000001
	NXIncompatVersion2      uint64 = 0x0000000000000002
	NXIncompatFusion        uint64 = 0x0000000000000100
	NXSupportedIncompatMask uint64 = NXIncompatVersion2 | NXIncompatFusion
)

// Checkpoint constants
const (
	CheckpointMapLast uint32 = 0x00000001
)

// Object map constants
const (
	OmapManuallyManaged  uint32 = 0x00000001
	OmapEncrypting       uint32 = 0x00000002
	OmapDecrypting       uint32 = 0x00000004
	OmapKeyrolling       uint32 = 0x00000008
	OmapCryptoGeneration uint32 = 0x00000010
	OmapValidFlags       uint32 = 0x0000001f
)

// Object map value flags
const (
	OmapValDeleted          uint32 = 0x00000001
	OmapValSaved            uint32 = 0x00000002
	OmapValEncrypted        uint32 = 0x00000004
	OmapValNoheader         uint32 = 0x00000008
	OmapValCryptoGeneration uint32 = 0x00000010
)

// Snapshot flags
const (
	OmapSnapshotDeleted  uint32 = 0x00000001
	OmapSnapshotReverted uint32 = 0x00000002
)

// Object map reaper phases
const (
	OmapReapPhaseMapTree      uint32 = 1
	OmapReapPhaseSnapshotTree uint32 = 2
)

// Max snapshot count
const (
	OmapMaxSnapCount uint32 = 0xffffffff
)

// B-tree flags
const (
	BtreeUint64Keys       uint32 = 0x00000001
	BtreeSequentialInsert uint32 = 0x00000002
	BtreeAllowGhosts      uint32 = 0x00000004
	BtreeEphemeral        uint32 = 0x00000008
	BtreePhysical         uint32 = 0x00000010
	BtreeNonpersistent    uint32 = 0x00000020
	BtreeKVNonaligned     uint32 = 0x00000040
	BtreeHashed           uint32 = 0x00000080
	BtreeNoheader         uint32 = 0x00000100
)

// B-tree table of contents constants
const (
	BtreeTOCEntryIncrement = 8
	BtreeTOCEntryMaxUnused = 2 * BtreeTOCEntryIncrement
)

// B-tree node flags
const (
	BtnodeRoot           uint16 = 0x0001
	BtnodeLeaf           uint16 = 0x0002
	BtnodeFixedKVSize    uint16 = 0x0004
	BtnodeHashed         uint16 = 0x0008
	BtnodeNoheader       uint16 = 0x0010
	BtnodeCheckKoffInval uint16 = 0x8000
)

// B-tree node constants
const (
	BtreeNodeSizeDefault   uint32 = 4096
	BtreeNodeMinEntryCount uint32 = 4
	BtreeNodeHashSizeMax          = 64
	BtoffInvalid           uint16 = 0xffff
)

// Inode numbers
const (
	InvalidInoNum      uint64 = 0
	RootDirParent      uint64 = 1
	RootDirInoNum      uint64 = 2
	PrivDirInoNum      uint64 = 3
	SnapDirInoNum      uint64 = 6
	PurgeableDirInoNum uint64 = 7
	MinUserInoNum      uint64 = 16
	UnifiedIDSpaceMark uint64 = 0x0800000000000000
)

// APFS volume flags
const (
	APFSFSUnencrypted          uint64 = 0x00000001
	APFSFSReserved2            uint64 = 0x00000002
	APFSFSReserved4            uint64 = 0x00000004
	APFSFSOnekey               uint64 = 0x00000008
	APFSFSSpilledover          uint64 = 0x00000010
	APFSFSRunSpilloverCleaner  uint64 = 0x00000020
	APFSFSAlwaysCheckExtentref uint64 = 0x00000040
	APFSFSReserved80           uint64 = 0x00000080
	APFSFSReserved100          uint64 = 0x00000100
	APFSFSFlagsValidMask       uint64 = APFSFSUnencrypted | APFSFSReserved2 | APFSFSReserved4 | APFSFSOnekey |
		APFSFSSpilledover | APFSFSRunSpilloverCleaner | APFSFSAlwaysCheckExtentref |
		APFSFSReserved80 | APFSFSReserved100
	APFSFSCryptoFlags uint64 = APFSFSUnencrypted | APFSFSReserved2 | APFSFSOnekey
)

// APFS volume roles
const (
	APFSVolumeEnumShift uint16 = 6

	APFSVolRoleNone       uint16 = 0x0000
	APFSVolRoleSystem     uint16 = 0x0001
	APFSVolRoleUser       uint16 = 0x0002
	APFSVolRoleRecovery   uint16 = 0x0004
	APFSVolRoleVM         uint16 = 0x0008
	APFSVolRolePreboot    uint16 = 0x0010
	APFSVolRoleInstaller  uint16 = 0x0020
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

// APFS volume feature flags
const (
	APFSFeatureDefragPrerelease     uint64 = 0x00000001
	APFSFeatureHardlinkMapRecords   uint64 = 0x00000002
	APFSFeatureDefrag               uint64 = 0x00000004
	APFSFeatureStrictatime          uint64 = 0x00000008
	APFSFeatureVolgrpSystemInoSpace uint64 = 0x00000010
	APFSSupportedFeaturesMask       uint64 = APFSFeatureDefrag |
		APFSFeatureDefragPrerelease |
		APFSFeatureHardlinkMapRecords |
		APFSFeatureStrictatime |
		APFSFeatureVolgrpSystemInoSpace
)

// APFS read-only compatible volume feature flags
const (
	APFSSupportedROCompatMask uint64 = 0x0
)

// APFS incompatible volume feature flags
const (
	APFSIncompatCaseInsensitive          uint64 = 0x00000001
	APFSIncompatDatalessSnaps            uint64 = 0x00000002
	APFSIncompatEncRolled                uint64 = 0x00000004
	APFSIncompatNormalizationInsensitive uint64 = 0x00000008
	APFSIncompatIncompleteRestore        uint64 = 0x00000010
	APFSIncompatSealedVolume             uint64 = 0x00000020
	APFSIncompatReserved40               uint64 = 0x00000040
	APFSSupportedIncompatMask            uint64 = APFSIncompatCaseInsensitive |
		APFSIncompatDatalessSnaps |
		APFSIncompatEncRolled |
		APFSIncompatNormalizationInsensitive |
		APFSIncompatIncompleteRestore |
		APFSIncompatSealedVolume |
		APFSIncompatReserved40
)

// Extended attribute constants
const (
	XattrMaxEmbeddedSize   = 3804
	SymlinkEAName          = "com.apple.fs.symlink"
	FirmlinkEAName         = "com.apple.fs.firmlink"
	APFSCowExemptCountName = "com.apple.fs.cow-exempt-file-count"
)

// Extended attribute flags
const (
	XattrDataStream      uint16 = 0x0001
	XattrDataEmbedded    uint16 = 0x0002
	XattrFileSystemOwned uint16 = 0x0004
	XattrReserved8       uint16 = 0x0008
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
	InodeInheritedInternalFlags uint64 = InodeMaintainDirStats | InodeSnapshotCowExemption
	InodeClonedInternalFlags    uint64 = InodeHasRsrcFork | InodeNoRsrcFork | InodeHasFinderInfo | InodeSnapshotCowExemption
	APFSValidInternalInodeFlags uint64 = InodeIsAPFSPrivate | InodeMaintainDirStats | InodeDirStatsOrigin |
		InodeProtClassExplicit | InodeWasCloned | InodeHasSecurityEA |
		InodeBeingTruncated | InodeHasFinderInfo | InodeIsSparse |
		InodeWasEverCloned | InodeActiveFileTrimmed | InodePinnedToMain |
		InodePinnedToTier2 | InodeHasRsrcFork | InodeNoRsrcFork |
		InodeAllocationSpilledover | InodeFastPromote | InodeHasUncompressedSize |
		InodeIsPurgeable | InodeWantsToBePurgeable | InodeIsSyncRoot |
		InodeSnapshotCowExemption
	APFSInodePinnedMask uint64 = InodePinnedToMain | InodePinnedToTier2
)

// File modes (from <sys/stat.h>)
const (
	SIfmt   uint16 = 0170000
	SIfifo  uint16 = 0010000
	SIfchr  uint16 = 0020000
	SIfdir  uint16 = 0040000
	SIfblk  uint16 = 0060000
	SIfreg  uint16 = 0100000
	SIflnk  uint16 = 0120000
	SIfsock uint16 = 0140000
	SIfwht  uint16 = 0160000
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

// Directory record flags
const (
	DrecTypeMask uint16 = 0x000f
	Reserved10   uint16 = 0x0010
)

// Extended field types
const (
	DrecExtTypeSiblingID     = 1
	InoExtTypeSnapXID        = 1
	InoExtTypeDeltaTreeOID   = 2
	InoExtTypeDocumentID     = 3
	InoExtTypeName           = 4
	InoExtTypePrevFsize      = 5
	InoExtTypeReserved6      = 6
	InoExtTypeFinderInfo     = 7
	InoExtTypeDstream        = 8
	InoExtTypeReserved9      = 9
	InoExtTypeDirStatsKey    = 10
	InoExtTypeFSUUID         = 11
	InoExtTypeReserved12     = 12
	InoExtTypeSparseBytes    = 13
	InoExtTypeRdev           = 14
	InoExtTypePurgeableFlags = 15
	InoExtTypeOrigSyncRootID = 16
)

// Extended field flags
const (
	XFDataDependent   uint8 = 0x0001
	XFDoNotCopy       uint8 = 0x0002
	XFReserved4       uint8 = 0x0004
	XFChildrenInherit uint8 = 0x0008
	XFUserField       uint8 = 0x0010
	XFSystemField     uint8 = 0x0020
	XFReserved40      uint8 = 0x0040
	XFReserved80      uint8 = 0x0080
)

// Directory entry hash masks and shifts
const (
	JDrecLenMask   uint32 = 0x000003ff
	JDrecHashMask  uint32 = 0xfffff400
	JDrecHashShift uint32 = 10
)

// File extent masks and shifts
const (
	JFileExtentLenMask   uint64 = 0x00ffffffffffffff
	JFileExtentFlagMask  uint64 = 0xff00000000000000
	JFileExtentFlagShift uint64 = 56
	FextCryptoIDIsTweak  uint8  = 0x01
)

// Physical extent masks and shifts
const (
	PextLenMask   uint64 = 0x0fffffffffffffff
	PextKindMask  uint64 = 0xf000000000000000
	PextKindShift uint64 = 60
)

// Integrity metadata versions
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
	APFSHashMin        uint32 = APFSHashSHA256
	APFSHashMax        uint32 = APFSHashSHA512
	APFSHashDefault    uint32 = APFSHashSHA256
)

// Hash size constants
const (
	APFSHashCCSHA256Size     = 32
	APFSHashCCSHA512_256Size = 32
	APFSHashCCSHA384Size     = 48
	APFSHashCCSHA512Size     = 64
	APFSHashMaxSize          = 64
)

// Encryption constants
const (
	CryptoSWID             uint64 = 4
	CryptoReserved5        uint64 = 5
	APFSUnassignedCryptoID uint64 = ^uint64(0)
)

// Protection classes
const (
	ProtectionClassDirNone uint32 = 0
	ProtectionClassA       uint32 = 1
	ProtectionClassB       uint32 = 2
	ProtectionClassC       uint32 = 3
	ProtectionClassD       uint32 = 4
	ProtectionClassF       uint32 = 6
	ProtectionClassM       uint32 = 14
	CPEffectiveClassMask   uint32 = 0x0000001f
)

// Keybag constants
const (
	APFSKeybagVersion             uint16 = 2
	APFSVolKeybagEntryMaxSize     uint16 = 512
	APFSFVPersonalRecoveryKeyUUID        = "EBC6C064-0000-11AA-AA11-00306543ECAC"

	// Keybag tags
	KBTagUnknown              uint16 = 0
	KBTagReserved1            uint16 = 1
	KBTagVolumeKey            uint16 = 2
	KBTagVolumeUnlockRecords  uint16 = 3
	KBTagVolumePassphraseHint uint16 = 4
	KBTagWrappingMKey         uint16 = 5
	KBTagVolumeMKey           uint16 = 6
	KBTagReservedF8           uint16 = 0xF8
)

// Document ID
const (
	MinDocID uint32 = 3
)

// File system constants
const (
	OwningObjIDInvalid uint64 = ^uint64(0)
	OwningObjIDUnknown uint64 = ^uint64(1)
	JobjMaxKeySize     uint32 = 832
	JobjMaxValueSize   uint32 = 3808
)

// Space manager constants
const (
	// SFQ indexes
	SFQIp    = 0
	SFQMain  = 1
	SFQTier2 = 2
	SFQCount = 3

	// Device indexes
	SDMain  = 0
	SDTier2 = 1
	SDCount = 2

	// Chunk info block constants
	CICountMask         uint32 = 0x000fffff
	CICountReservedMask uint32 = 0xfff00000

	// Internal pool bitmap
	SpacemanIPBMTXMultiplier  = 16
	SpacemanIPBMIndexInvalid  = 0xffff
	SpacemanIPBMBlockCountMax = 0xfffe
)

// EFI jumpstart constants
const (
	EFIJumpstartVersion = 1
)

// Nx superblock constants
const (
	NXMaxFileSystemEphStructs = 4
	NXEphInfoCount            = 4
	NXEphMinBlockCount        = 8
	NXMaxFileSystems          = 100
	NXTxMinCheckpointCount    = 4
	NXEphInfoVersion1         = 1
)

// NX counter IDs
const (
	NXCntrObjCksumSet = iota
	NXCntrObjCksumFail
	NXNumCounters = 32
)

// Crypto constants
const (
	CPMaxWrappedKeySize = 128
)

// Snapshot metadata flags
const (
	SnapMetaPendingDataless uint32 = 0x00000001
	SnapMetaMergeInProgress uint32 = 0x00000002
)

// Reaper states
const (
	APFSReapPhaseStart uint32 = iota
	APFSReapPhaseSnapshots
	APFSReapPhaseActiveFS
	APFSReapPhaseDestroyOmap
	APFSReapPhaseDone
)

// Reaper flags
const (
	NRBhmFlag  uint32 = 0x00000001
	NRContinue uint32 = 0x00000002
)

// Reaper list entry flags
const (
	NRLEValid        uint32 = 0x00000001
	NRLEReapIDRecord uint32 = 0x00000002
	NRLECall         uint32 = 0x00000004
	NRLECompletion   uint32 = 0x00000008
	NRLECleanup      uint32 = 0x00000010
)
