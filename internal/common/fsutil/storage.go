package fsutil

import (
	"syscall"
)

// GetFreeDiskSpace returns the available disk space in bytes for a given path
func GetFreeDiskSpace(path string) (uint64, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

// HasEnoughDiskSpace checks if there is sufficient free space for a file operation
func HasEnoughDiskSpace(path string, requiredBytes uint64) (bool, error) {
	freeSpace, err := GetFreeDiskSpace(path)
	if err != nil {
		return false, err
	}
	return freeSpace >= requiredBytes, nil
}
