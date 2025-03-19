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
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// CreateDir creates a directory if it doesn't exist
func CreateDir(path string, perm os.FileMode) error {
	if DirExists(path) {
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
	if !DirExists(path) {
		return nil // Directory doesn't exist, nothing to do
	}
	return os.Remove(path)
}

// DeleteDirRecursive removes a directory and all its contents
func DeleteDirRecursive(path string) error {
	if !DirExists(path) {
		return nil // Directory doesn't exist, nothing to do
	}
	return os.RemoveAll(path)
}

// CleanDir removes all contents from a directory without removing the directory itself
func CleanDir(path string) error {
	if !DirExists(path) {
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
			if err := DeleteDirRecursive(entryPath); err != nil {
				return err
			}
		} else {
			if err := os.Remove(entryPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// CopyDir recursively copies a directory and its contents
func CopyDir(src, dst string) error {
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

		if entry.IsDir() {
			// Recursively copy subdirectory
			if err := CopyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy file
			if err := CopyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// MoveDir moves a directory from source to destination
func MoveDir(src, dst string) error {
	// Try the atomic rename operation first
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// If rename fails (e.g., cross-device), fall back to copy and delete
	if err := CopyDir(src, dst); err != nil {
		return err
	}

	return DeleteDirRecursive(src)
}

// ListDir returns a list of all files and directories in a directory (non-recursive)
func ListDir(path string) ([]DirEntry, error) {
	if !DirExists(path) {
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
	return filepath.Walk(root, fn)
}

// FindFiles finds all files matching a pattern in a directory (recursive)
func FindFiles(root, pattern string) ([]string, error) {
	var matches []string
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
				matches = append(matches, path)
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
	err := WalkDir(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext)) {
			matches = append(matches, path)
		}
		return nil
	})
	return matches, err
}

// IsDirEmpty checks if a directory is empty
func IsDirEmpty(path string) (bool, error) {
	if !DirExists(path) {
		return false, fmt.Errorf("directory does not exist: %s", path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}

	return len(entries) == 0, nil
}

// GetDirSize calculates the total size of a directory and its contents
func GetDirSize(path string) (int64, error) {
	var size int64
	err := WalkDir(path, func(_ string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
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
	// If directory exists, clean it
	if DirExists(path) {
		return CleanDir(path)
	}

	// Create new directory
	return CreateDirIfNotExists(path)
}

// CopyDirContents copies the contents of a directory without recreating the source directory
func CopyDirContents(src, dst string) error {
	// Create destination if it doesn't exist
	if err := CreateDirIfNotExists(dst); err != nil {
		return err
	}

	// Get source contents
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := CopyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := CopyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// IsSymlink checks if a path is a symlink
func IsSymlink(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}

	return info.Mode()&os.ModeSymlink != 0, nil
}

// CreateTempDir creates a temporary directory with a prefix
func CreateTempDir(prefix string) (string, error) {
	return os.MkdirTemp("", prefix)
}

// CreateTempDirIn creates a temporary directory with a prefix in a specific directory
func CreateTempDirIn(dir, prefix string) (string, error) {
	if !DirExists(dir) {
		if err := CreateDirIfNotExists(dir); err != nil {
			return "", err
		}
	}

	return os.MkdirTemp(dir, prefix)
}

// CopySymlink copies a symlink from source to destination
func CopySymlink(src, dst string) error {
	// Read the target of the symlink
	target, err := os.Readlink(src)
	if err != nil {
		return err
	}

	// Create parent directory if needed
	if err := CreateDirIfNotExists(filepath.Dir(dst)); err != nil {
		return err
	}

	// Remove destination if it exists
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Create the symlink
	return os.Symlink(target, dst)
}
