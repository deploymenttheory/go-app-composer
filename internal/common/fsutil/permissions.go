// fsutil/permissions.go
package fsutil

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-app-composer/internal/common/osutil"
)

// PermissionMode represents a file permission mode
type PermissionMode uint32

// Permission constants
const (
	PermUserRead  PermissionMode = 0400
	PermUserWrite PermissionMode = 0200
	PermUserExec  PermissionMode = 0100
	PermUserRWX   PermissionMode = 0700

	PermGroupRead  PermissionMode = 0040
	PermGroupWrite PermissionMode = 0020
	PermGroupExec  PermissionMode = 0010
	PermGroupRWX   PermissionMode = 0070

	PermOtherRead  PermissionMode = 0004
	PermOtherWrite PermissionMode = 0002
	PermOtherExec  PermissionMode = 0001
	PermOtherRWX   PermissionMode = 0007

	PermAllRead   PermissionMode = 0444
	PermAllWrite  PermissionMode = 0222
	PermAllExec   PermissionMode = 0111
	PermAllRWX    PermissionMode = 0777
	PermStandard  PermissionMode = 0644
	PermStdExec   PermissionMode = 0755
	PermDirectory PermissionMode = 0755
)

// GetPermissions retrieves the permissions of a file or directory
func GetPermissions(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Mode().Perm(), nil
}

// SetPermissions sets the permissions of a file or directory
func SetPermissions(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// IsReadable checks if a file or directory is readable by the current user
func IsReadable(path string) bool {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

// IsWritable checks if a file or directory is writable by the current user
func IsWritable(path string) bool {
	// For directories, check if we can create a temporary file
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	if info.IsDir() {
		testFile := filepath.Join(path, ".permission_test_"+strconv.FormatInt(int64(os.Getpid()), 10))
		file, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return false
		}
		file.Close()
		os.Remove(testFile)
		return true
	}

	// For files, check if we can open for writing
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

// IsExecutable checks if a file is executable by the current user
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// On Windows, check file extension
	if osutil.IsWindows() {
		ext := strings.ToLower(filepath.Ext(path))
		return ext == ".exe" || ext == ".bat" || ext == ".cmd"
	}

	// On Unix-like systems, check executable permission
	return info.Mode().Perm()&0111 != 0
}

// GetOwner gets the owner of a file or directory
func GetOwner(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	// On Windows, this is not well supported, so we return empty
	if osutil.IsWindows() {
		return "", fmt.Errorf("getting file owner not supported on Windows")
	}

	// On Unix-like systems
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := stat.Uid
		user, err := user.LookupId(fmt.Sprintf("%d", uid))
		if err != nil {
			return "", err
		}
		return user.Username, nil
	}

	return "", fmt.Errorf("unable to get file owner")
}

// SetOwner sets the owner of a file or directory
func SetOwner(path string, username string) error {
	// Not supported on Windows
	if osutil.IsWindows() {
		return fmt.Errorf("setting file owner not supported on Windows")
	}

	u, err := user.Lookup(username)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}

	return os.Chown(path, uid, gid)
}

// GetGroup gets the group of a file or directory
func GetGroup(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	// On Windows, this is not well supported, so we return empty
	if osutil.IsWindows() {
		return "", fmt.Errorf("getting file group not supported on Windows")
	}

	// On Unix-like systems
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		gid := stat.Gid
		group, err := user.LookupGroupId(fmt.Sprintf("%d", gid))
		if err != nil {
			return "", err
		}
		return group.Name, nil
	}

	return "", fmt.Errorf("unable to get file group")
}

// SetGroup sets the group of a file or directory
func SetGroup(path string, groupname string) error {
	// Not supported on Windows
	if osutil.IsWindows() {
		return fmt.Errorf("setting file group not supported on Windows")
	}

	g, err := user.LookupGroup(groupname)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}

	// Get current owner
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unable to get file stats")
	}

	return os.Chown(path, int(stat.Uid), gid)
}

// MakeReadOnly makes a file or directory read-only
func MakeReadOnly(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode()
	// Remove all write permissions
	newMode := mode &^ os.FileMode(0222)

	return os.Chmod(path, newMode)
}

// MakeWritable makes a file or directory writable
func MakeWritable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode()
	// Add write permissions where read permissions exist
	newMode := mode | (mode&0444)>>2

	return os.Chmod(path, newMode)
}

// SetRecursivePermissions sets permissions recursively on a directory
func SetRecursivePermissions(path string, dirMode, fileMode os.FileMode) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return os.Chmod(name, dirMode)
		}
		return os.Chmod(name, fileMode)
	})
}

// IsSymlinkTo checks if a path is a symlink pointing to a specific target
func IsSymlinkTo(path, target string) (bool, error) {
	linkTarget, err := os.Readlink(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	// Normalize paths for comparison
	linkTarget = filepath.Clean(linkTarget)
	target = filepath.Clean(target)

	return linkTarget == target, nil
}

// GetFileAttributes gets platform-specific file attributes
func GetFileAttributes(path string) (string, error) {
	// For Windows, we could implement using syscall but keeping it simple
	if osutil.IsWindows() {
		return "Not implemented for Windows", nil
	}

	// For Unix, return the formatted permissions
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	// Use the String() method directly
	return info.Mode().String(), nil
}
