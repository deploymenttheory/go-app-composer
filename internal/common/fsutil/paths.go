// fsutil/paths.go
package fsutil

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/common/osutil"
)

// PathSeparator returns the OS-specific path separator character
func PathSeparator() string {
	return string(os.PathSeparator)
}

// IsAbsPath checks if a path is absolute
func IsAbsPath(path string) bool {
	return filepath.IsAbs(path)
}

// ToAbsPath converts a relative path to an absolute path
func ToAbsPath(path string) (string, error) {
	if IsAbsPath(path) {
		return path, nil
	}
	return filepath.Abs(path)
}

// JoinPath joins path elements using the OS-specific separator
func JoinPath(elem ...string) string {
	return filepath.Join(elem...)
}

// SplitPath splits a path into directory and file components
func SplitPath(path string) (dir, file string) {
	return filepath.Split(path)
}

// CleanPath cleans a path by removing redundant separators and resolving ".." and "."
func CleanPath(path string) string {
	return filepath.Clean(path)
}

// NormalizePath normalizes a path for the current OS
// This is particularly useful when dealing with paths that might
// have been created on a different OS
func NormalizePath(path string) string {
	// Replace both types of slashes with the OS separator
	result := strings.ReplaceAll(path, "\\", PathSeparator())
	result = strings.ReplaceAll(result, "/", PathSeparator())
	return CleanPath(result)
}

// GetWorkingDir returns the current working directory
func GetWorkingDir() (string, error) {
	return os.Getwd()
}

// RelativePath returns a relative path from base to target
func RelativePath(basePath, targetPath string) (string, error) {
	return filepath.Rel(basePath, targetPath)
}

// GetExtension returns the file extension with the dot (e.g., ".txt")
func GetExtension(path string) string {
	return filepath.Ext(path)
}

// GetFileNameWithoutExt returns the file name without its extension
func GetFileNameWithoutExt(path string) string {
	baseName := filepath.Base(path)
	extension := filepath.Ext(baseName)
	return baseName[:len(baseName)-len(extension)]
}

// IsWindowsPath checks if a path appears to be a Windows-style path
func IsWindowsPath(path string) bool {
	// Check for drive letter (e.g., C:)
	if len(path) >= 2 && path[1] == ':' {
		return true
	}

	// Check for UNC path (e.g., \\server\share)
	if len(path) >= 2 && path[0] == '\\' && path[1] == '\\' {
		return true
	}

	return false
}

// IsUnixPath checks if a path appears to be a Unix-style path
func IsUnixPath(path string) bool {
	// Unix paths start with / and don't have drive letters or backslashes
	return len(path) > 0 && path[0] == '/' && !strings.Contains(path, "\\")
}

// ConvertToOSPath converts a path to use the current OS path format
func ConvertToOSPath(path string) string {
	// If the path already matches the current OS format, return it
	if osutil.IsWindows() && IsWindowsPath(path) {
		return path
	} else if osutil.IsUnix() && IsUnixPath(path) {
		return path
	}

	// Otherwise, normalize it
	return NormalizePath(path)
}

// GetPathDepth returns the number of path components (levels of depth)
func GetPathDepth(path string) int {
	// Clean and split the path
	cleaned := CleanPath(path)
	parts := strings.Split(cleaned, PathSeparator())

	// Filter out empty parts
	count := 0
	for _, part := range parts {
		if part != "" {
			count++
		}
	}

	return count
}

// ExpandTilde expands the tilde in paths to the user's home directory
func ExpandTilde(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		if path == "~" {
			return home, nil
		}

		// Replace just the ~ prefix with home directory
		return filepath.Join(home, path[2:]), nil
	}

	return path, nil
}
