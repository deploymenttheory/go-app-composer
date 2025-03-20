// fsutil/directory.go
package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DirEntry represents an entry in a directory (file or subdirectory)
type DirEntry struct {
	Path     string
	Name     string
	IsDir    bool
	Size     int64
	Mode     os.FileMode
	ModTime  time.Time
	FullPath string
}

// DirExists checks if a directory exists
func DirExists(path string) bool {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// CreateDir creates a directory if it doesn't exist
func CreateDir(path string, perm os.FileMode) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check again under lock
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		return nil // Directory already exists
	}
	return os.MkdirAll(path, perm)
}

// CreateDirIfNotExists creates a directory with standard permissions if it doesn't exist
func CreateDirIfNotExists(path string) error {
	return CreateDir(path, 0755)
}

// DeleteDir removes an empty directory
func DeleteDir(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check under lock
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil // Directory doesn't exist, nothing to do
	}
	return os.Remove(path)
}

// DeleteDirRecursive removes a directory and all its contents
func DeleteDirRecursive(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check under lock
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil // Directory doesn't exist, nothing to do
	}
	return os.RemoveAll(path)
}

// CleanDir removes all contents from a directory without removing the directory itself
func CleanDir(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check under lock
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("directory does not exist: %s", path)
	}

	// Read directory entries
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	// Remove each entry
	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			// Release parent directory lock to avoid deadlocks during recursive deletion
			mu.Unlock()
			err := DeleteDirRecursive(entryPath)
			mu.Lock() // Reacquire lock for parent directory
			if err != nil {
				return err
			}
		} else {
			// For files, we can just remove while holding the parent directory lock
			if err := os.Remove(entryPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// CopyDir recursively copies a directory and its contents
func CopyDir(src, dst string) error {
	// Lock both source and destination to prevent concurrent modifications
	unlock := acquireMutexes(src, dst)
	defer unlock()

	// Get info about the source directory
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}

	// Create the destination directory
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	// Get directory contents
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		// Release locks to avoid deadlocks during recursive operations
		unlock()

		var err error
		if entry.IsDir() {
			// Recursively copy subdirectory
			err = CopyDir(srcPath, dstPath)
		} else {
			// Copy file
			err = CopyFile(srcPath, dstPath)
		}

		// Reacquire locks
		unlock = acquireMutexes(src, dst)

		if err != nil {
			return err
		}
	}

	return nil
}

// MoveDir moves a directory from source to destination
func MoveDir(src, dst string) error {
	// Lock both source and destination
	unlock := acquireMutexes(src, dst)
	defer unlock()

	// Try the atomic rename operation first
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// If rename fails (e.g., cross-device), release locks to prevent deadlocks
	unlock()

	// Fall back to copy and delete
	if err := CopyDir(src, dst); err != nil {
		return err
	}

	return DeleteDirRecursive(src)
}

// ListDir returns a list of all files and directories in a directory (non-recursive)
func ListDir(path string) ([]DirEntry, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check under lock
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("directory does not exist: %s", path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	result := make([]DirEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}

		fullPath := filepath.Join(path, entry.Name())
		result = append(result, DirEntry{
			Path:     path,
			Name:     entry.Name(),
			IsDir:    entry.IsDir(),
			Size:     info.Size(),
			Mode:     info.Mode(),
			ModTime:  info.ModTime(),
			FullPath: fullPath,
		})
	}

	return result, nil
}

// ListFiles returns a list of files in a directory (non-recursive, no directories)
func ListFiles(path string) ([]DirEntry, error) {
	entries, err := ListDir(path)
	if err != nil {
		return nil, err
	}

	files := make([]DirEntry, 0)
	for _, entry := range entries {
		if !entry.IsDir {
			files = append(files, entry)
		}
	}

	return files, nil
}

// ListDirs returns a list of subdirectories in a directory (non-recursive, no files)
func ListDirs(path string) ([]DirEntry, error) {
	entries, err := ListDir(path)
	if err != nil {
		return nil, err
	}

	dirs := make([]DirEntry, 0)
	for _, entry := range entries {
		if entry.IsDir {
			dirs = append(dirs, entry)
		}
	}

	return dirs, nil
}

// WalkDir walks a directory recursively and calls a function for each entry
func WalkDir(root string, fn func(path string, info fs.FileInfo, err error) error) error {
	// For WalkDir, we need a more complex approach since we'll be traversing
	// multiple directories. We'll use a visitor pattern that acquires and releases
	// locks for each directory as it's processed.

	visitor := func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fn(path, info, err)
		}

		// Lock the current path
		mu := GetPathMutex(path)
		mu.Lock()
		defer mu.Unlock()

		// If path no longer exists, report it
		if _, statErr := os.Stat(path); statErr != nil {
			return fn(path, info, statErr)
		}

		// Call the user-provided function with the lock held
		return fn(path, info, nil)
	}

	return filepath.Walk(root, visitor)
}

// FindFiles finds all files matching a pattern in a directory (recursive)
func FindFiles(root, pattern string) ([]string, error) {
	var matches []string
	var mu sync.Mutex // Mutex to protect concurrent writes to matches slice

	err := WalkDir(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			match, err := filepath.Match(pattern, filepath.Base(path))
			if err != nil {
				return err
			}
			if match {
				mu.Lock()
				matches = append(matches, path)
				mu.Unlock()
			}
		}
		return nil
	})
	return matches, err
}

// FindFilesByExt finds all files with a specific extension in a directory (recursive)
func FindFilesByExt(root, ext string) ([]string, error) {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	var matches []string
	var mu sync.Mutex // Mutex to protect concurrent writes to matches slice

	err := WalkDir(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext)) {
			mu.Lock()
			matches = append(matches, path)
			mu.Unlock()
		}
		return nil
	})
	return matches, err
}

// IsDirEmpty checks if a directory is empty
func IsDirEmpty(path string) (bool, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check under lock
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false, fmt.Errorf("directory does not exist: %s", path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}

	return len(entries) == 0, nil
}

// GetDir returns the directory of a given file path
// This is a pure path operation that doesn't access the filesystem, so no locking needed
func GetDir(path string) string {
	return filepath.Dir(path)
}

// GetDirSize calculates the total size of a directory and its contents
func GetDirSize(path string) (int64, error) {
	var size int64
	var mu sync.Mutex // Mutex to protect the size counter

	err := WalkDir(path, func(_ string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			mu.Lock()
			size += info.Size()
			mu.Unlock()
		}
		return nil
	})
	return size, err
}

// GetNewestFile finds the most recently modified file in a directory (non-recursive)
func GetNewestFile(path string) (*DirEntry, error) {
	files, err := ListFiles(path)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, errors.New("no files found in directory")
	}

	// Sort by modification time (newest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.After(files[j].ModTime)
	})

	return &files[0], nil
}

// GetOldestFile finds the oldest file in a directory (non-recursive)
func GetOldestFile(path string) (*DirEntry, error) {
	files, err := ListFiles(path)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, errors.New("no files found in directory")
	}

	// Sort by modification time (oldest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.Before(files[j].ModTime)
	})

	return &files[0], nil
}

// EnsureEmptyDir ensures a directory exists and is empty
func EnsureEmptyDir(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// If directory exists, clean it
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		// Release lock to avoid deadlock in CleanDir
		mu.Unlock()
		err := CleanDir(path)
		mu.Lock() // Reacquire lock
		return err
	}

	// Create new directory
	return os.MkdirAll(path, 0755)
}

// CopyDirContents copies the contents of a directory without recreating the source directory
func CopyDirContents(src, dst string) error {
	// Lock both source and destination
	unlock := acquireMutexes(src, dst)
	defer unlock()

	// Create destination if it doesn't exist
	info, err := os.Stat(dst)
	if err != nil || !info.IsDir() {
		if err := os.MkdirAll(dst, 0755); err != nil {
			return err
		}
	}

	// Get source contents
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		// Release locks to avoid deadlocks during recursive operations
		unlock()

		var err error
		if entry.IsDir() {
			err = CopyDir(srcPath, dstPath)
		} else {
			err = CopyFile(srcPath, dstPath)
		}

		// Reacquire locks
		unlock = acquireMutexes(src, dst)

		if err != nil {
			return err
		}
	}

	return nil
}

// IsSymlink checks if a path is a symlink
func IsSymlink(path string) (bool, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}

	return info.Mode()&os.ModeSymlink != 0, nil
}

// CreateTempDir creates a temporary directory with a prefix
func CreateTempDir(prefix string) (string, error) {
	// No need to lock here as os.MkdirTemp handles atomicity
	return os.MkdirTemp("", prefix)
}

// CreateTempDirIn creates a temporary directory with a prefix in a specific directory
func CreateTempDirIn(dir, prefix string) (string, error) {
	mu := GetPathMutex(dir)
	mu.Lock()
	defer mu.Unlock()

	// Check if directory exists and create if needed
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", err
		}
	}

	return os.MkdirTemp(dir, prefix)
}

// CopySymlink copies a symlink from source to destination
func CopySymlink(src, dst string) error {
	// Lock both source and destination
	unlock := acquireMutexes(src, dst)
	defer unlock()

	// Read the target of the symlink
	target, err := os.Readlink(src)
	if err != nil {
		return err
	}

	// Create parent directory if needed
	parentDir := filepath.Dir(dst)
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return err
		}
	}

	// Remove destination if it exists
	if _, err := os.Lstat(dst); err == nil {
		if err := os.Remove(dst); err != nil {
			return err
		}
	}

	// Create the symlink
	return os.Symlink(target, dst)
}
