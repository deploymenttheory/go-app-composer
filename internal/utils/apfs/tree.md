# apfs util file tree map

apfs/
├── types.go                  # Core type definitions and constants
├── object.go                 # Object-related structures (obj_phys_t, etc.)
├── container.go              # Container structures (nx_superblock_t, etc.)
├── volume.go                 # Volume structures (apfs_superblock_t, etc.)
├── btree.go                  # B-tree structures
├── fs_objects.go             # File system object structures (inodes, etc.)
├── data_streams.go           # Structures for file data
├── encryption.go             # Encryption-related structures
├── extended_fields.go        # Extended field handling
├── snapshots.go              # Snapshot-related structures
├── space_manager.go          # Space manager structures
├── reaper.go                 # Reaper-related structures
├── fusion.go                 # Fusion drive structures
├── parsing.go                # Parsing functions for all structures
├── checksum.go               # Checksum implementation
└── utils.go                  # Utility functions