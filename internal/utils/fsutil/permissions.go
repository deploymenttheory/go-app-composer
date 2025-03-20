// fsutil/permissions.go
package fsutil

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/osutil"
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

// WindowsFileAttributes represents common Windows file attributes
type WindowsFileAttributes uint32

// Windows attribute constants - defined with their actual values
// even though we won't use golang.org/x/sys/windows
const (
	WinAttrReadOnly  WindowsFileAttributes = 0x1
	WinAttrHidden    WindowsFileAttributes = 0x2
	WinAttrSystem    WindowsFileAttributes = 0x4
	WinAttrDirectory WindowsFileAttributes = 0x10
	WinAttrArchive   WindowsFileAttributes = 0x20
	WinAttrNormal    WindowsFileAttributes = 0x80
)

// GetPermissions retrieves the permissions of a file or directory
func GetPermissions(path string) (os.FileMode, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		if os.IsPermission(err) {
			return 0, fmt.Errorf("%w: %s", errors.ErrPermissionDenied, path)
		}
		return 0, fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}
	return info.Mode().Perm(), nil
}

// SetPermissions sets the permissions of a file or directory
func SetPermissions(path string, mode os.FileMode) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	err := os.Chmod(path, mode)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("%w: %s", errors.ErrPermissionDenied, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrFilePermissionError, path)
	}
	return nil
}

// IsReadable checks if a file or directory is readable by the current user
func IsReadable(path string) bool {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

// IsWritable checks if a file or directory is writable by the current user
func IsWritable(path string) bool {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

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
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// On Windows, check file extension
	if osutil.IsWindows() {
		ext := strings.ToLower(filepath.Ext(path))
		return ext == ".exe" || ext == ".bat" || ext == ".cmd" || ext == ".ps1"
	}

	// On Unix-like systems, check executable permission
	return info.Mode().Perm()&0111 != 0
}

// GetOwner gets the owner of a file or directory
func GetOwner(path string) (string, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		if os.IsPermission(err) {
			return "", fmt.Errorf("%w: %s", errors.ErrPermissionDenied, path)
		}
		return "", fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	if osutil.IsWindows() {
		// Release lock for external command execution to avoid deadlocks
		mu.Unlock()
		owner, err := getWindowsOwner(path)
		mu.Lock() // Reacquire lock
		return owner, err
	}

	// On Unix-like systems
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := stat.Uid
		user, err := user.LookupId(fmt.Sprintf("%d", uid))
		if err != nil {
			return "", fmt.Errorf("%w: unable to lookup user", errors.ErrInvalidArgument)
		}
		return user.Username, nil
	}

	return "", fmt.Errorf("%w: unable to get file owner", errors.ErrUnsupportedFile)
}

// getWindowsOwner gets the owner of a file on Windows
func getWindowsOwner(path string) (string, error) {
	// This function is called internally with mutex protection

	// Convert to absolute path to ensure proper resolution
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: failed to resolve path", errors.ErrPathNotAccessible)
	}

	// Check if the file exists
	if _, err := os.Stat(absPath); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", errors.ErrFileNotFound, absPath)
		}
		return "", fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, absPath)
	}

	// If PowerShell is available, use it to get the owner
	if hasPowerShell() {
		output, err := exec.Command("powershell", "-Command",
			fmt.Sprintf("(Get-Acl '%s').Owner", absPath)).Output()
		if err == nil && len(output) > 0 {
			owner := strings.TrimSpace(string(output))
			if owner != "" {
				return owner, nil
			}
		}
	}

	// For regular files in Windows, we return the current user as a fallback
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("%w: unable to determine current user", errors.ErrInvalidArgument)
	}

	return currentUser.Username, nil
}

// hasPowerShell checks if PowerShell is available on the system
func hasPowerShell() bool {
	_, err := exec.LookPath("powershell")
	return err == nil
}

// SetOwner sets the owner of a file or directory
func SetOwner(path string, username string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Not fully supported on Windows, but we'll provide a better error
	if osutil.IsWindows() {
		return fmt.Errorf("%w: changing file ownership on Windows requires special privileges. Use icacls.exe or PowerShell Set-Acl", errors.ErrOSNotSupported)
	}

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("%w: user %s not found", errors.ErrInvalidArgument, username)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("%w: invalid user ID", errors.ErrInvalidArgument)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("%w: invalid group ID", errors.ErrInvalidArgument)
	}

	if err := os.Chown(path, uid, gid); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w: insufficient permissions to change ownership", errors.ErrPermissionDenied)
		}
		return fmt.Errorf("%w: failed to change ownership", errors.ErrFilePermissionError)
	}

	return nil
}

// GetGroup gets the group of a file or directory
func GetGroup(path string) (string, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		if os.IsPermission(err) {
			return "", fmt.Errorf("%w: %s", errors.ErrPermissionDenied, path)
		}
		return "", fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	if osutil.IsWindows() {
		// Release lock before external command execution
		mu.Unlock()
		group, err := getWindowsGroup(path)
		mu.Lock() // Reacquire lock
		return group, err
	}

	// On Unix-like systems
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		gid := stat.Gid
		group, err := user.LookupGroupId(fmt.Sprintf("%d", gid))
		if err != nil {
			return "", fmt.Errorf("%w: unable to lookup group", errors.ErrInvalidArgument)
		}
		return group.Name, nil
	}

	return "", fmt.Errorf("%w: unable to get file group", errors.ErrUnsupportedFile)
}

// getWindowsGroup gets the primary group associated with a file on Windows
func getWindowsGroup(path string) (string, error) {
	// This function is called with mutex handling by the caller

	// If PowerShell is available, try to get primary group
	if hasPowerShell() {
		output, err := exec.Command("powershell", "-Command",
			fmt.Sprintf("(Get-Acl '%s').Group", filepath.Clean(path))).Output()
		if err == nil && len(output) > 0 {
			group := strings.TrimSpace(string(output))
			if group != "" {
				return group, nil
			}
		}
	}

	// In Windows, return "Users" as a default group for normal files
	return "Users", nil
}

// SetGroup sets the group of a file or directory
func SetGroup(path string, groupname string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	if osutil.IsWindows() {
		return fmt.Errorf("%w: changing file group on Windows requires special privileges. Use icacls.exe or PowerShell Set-Acl", errors.ErrOSNotSupported)
	}

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	g, err := user.LookupGroup(groupname)
	if err != nil {
		return fmt.Errorf("%w: group %s not found", errors.ErrInvalidArgument, groupname)
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("%w: invalid group ID", errors.ErrInvalidArgument)
	}

	// Get current owner
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: unable to get file stats", errors.ErrUnsupportedFile)
	}

	if err := os.Chown(path, int(stat.Uid), gid); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w: insufficient permissions to change group", errors.ErrPermissionDenied)
		}
		return fmt.Errorf("%w: failed to change group", errors.ErrFilePermissionError)
	}

	return nil
}

// MakeReadOnly makes a file or directory read-only
func MakeReadOnly(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	if osutil.IsWindows() {
		// Release lock for external command
		mu.Unlock()
		err := setWindowsReadOnly(path, true)
		mu.Lock() // Reacquire lock
		return err
	}

	// For Unix systems
	mode := info.Mode()
	// Remove all write permissions
	newMode := mode &^ os.FileMode(0222)

	if err := os.Chmod(path, newMode); err != nil {
		return fmt.Errorf("%w: failed to set read-only mode", errors.ErrFilePermissionError)
	}

	return nil
}

// setWindowsReadOnly sets or clears the read-only attribute on Windows
func setWindowsReadOnly(path string, readOnly bool) error {
	// This function is called with mutex handling by the caller

	if readOnly {
		// Use attrib command to set read-only flag
		cmd := exec.Command("attrib", "+r", path)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%w: failed to set read-only attribute", errors.ErrFilePermissionError)
		}
	} else {
		// Use attrib command to clear read-only flag
		cmd := exec.Command("attrib", "-r", path)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%w: failed to clear read-only attribute", errors.ErrFilePermissionError)
		}
	}
	return nil
}

// MakeWritable makes a file or directory writable
func MakeWritable(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	if osutil.IsWindows() {
		// Release lock for external command
		mu.Unlock()
		err := setWindowsReadOnly(path, false)
		mu.Lock() // Reacquire lock
		return err
	}

	// For Unix systems
	mode := info.Mode()
	// Add write permissions where read permissions exist
	newMode := mode | (mode&0444)>>2

	if err := os.Chmod(path, newMode); err != nil {
		return fmt.Errorf("%w: failed to set writable mode", errors.ErrFilePermissionError)
	}

	return nil
}

// SetRecursivePermissions sets permissions recursively on a directory
func SetRecursivePermissions(path string, dirMode, fileMode os.FileMode) error {
	// Lock the root path
	rootMu := GetPathMutex(path)
	rootMu.Lock()

	// Check if directory exists
	info, err := os.Stat(path)
	if err != nil {
		rootMu.Unlock()
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrDirNotFound, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	if !info.IsDir() {
		rootMu.Unlock()
		return fmt.Errorf("%w: %s is not a directory", errors.ErrInvalidArgument, path)
	}

	// Release root lock before walking to avoid deadlocks
	rootMu.Unlock()

	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Lock each path individually during walk
		mu := GetPathMutex(name)
		mu.Lock()
		defer mu.Unlock()

		var chmodErr error
		if info.IsDir() {
			chmodErr = os.Chmod(name, dirMode)
		} else {
			chmodErr = os.Chmod(name, fileMode)
		}

		if chmodErr != nil {
			if os.IsPermission(chmodErr) {
				return fmt.Errorf("%w: insufficient permissions to modify %s", errors.ErrPermissionDenied, name)
			}
			return fmt.Errorf("%w: failed to set permissions on %s", errors.ErrFilePermissionError, name)
		}

		return nil
	})
}

// IsSymlinkTo checks if a path is a symlink pointing to a specific target
func IsSymlinkTo(path, target string) (bool, error) {
	// Lock both paths to ensure consistency
	unlock := acquireMutexes(path, target)
	defer unlock()

	linkTarget, err := os.Readlink(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	// Normalize paths for comparison
	linkTarget = filepath.Clean(linkTarget)
	target = filepath.Clean(target)

	return linkTarget == target, nil
}

// GetFileAttributes gets platform-specific file attributes
func GetFileAttributes(path string) (string, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	if osutil.IsWindows() {
		// Release lock for external command
		mu.Unlock()
		attrs, err := getWindowsFileAttributes(path)
		mu.Lock() // Reacquire lock
		return attrs, err
	}

	// For Unix, return the formatted permissions
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return "", fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	// Use the String() method directly
	return info.Mode().String(), nil
}

// getWindowsFileAttributes returns Windows-specific file attributes as a string
func getWindowsFileAttributes(path string) (string, error) {
	// This function is called with mutex handling by the caller

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return "", fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	// Use dir command to get attributes
	cmd := exec.Command("cmd", "/c", "dir", "/a", path)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: failed to get file attributes", errors.ErrPathNotAccessible)
	}

	// Parse the output to extract attributes
	outputStr := string(output)
	attributes := []string{}

	// Check for common attributes in the dir output
	if strings.Contains(outputStr, "<DIR>") {
		attributes = append(attributes, "Directory")
	}
	if strings.Contains(outputStr, "A") {
		attributes = append(attributes, "Archive")
	}
	if strings.Contains(outputStr, "H") {
		attributes = append(attributes, "Hidden")
	}
	if strings.Contains(outputStr, "R") {
		attributes = append(attributes, "ReadOnly")
	}
	if strings.Contains(outputStr, "S") {
		attributes = append(attributes, "System")
	}

	if len(attributes) == 0 {
		attributes = append(attributes, "Normal")
	}

	return strings.Join(attributes, ", "), nil
}

// GetWindowsAttributes returns Windows-specific file attributes as a uint32
func GetWindowsAttributes(path string) (WindowsFileAttributes, error) {
	if !osutil.IsWindows() {
		return 0, fmt.Errorf("%w: Windows attributes are only available on Windows", errors.ErrOSNotSupported)
	}

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return 0, fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	// Use PowerShell to get attributes if available
	if hasPowerShell() {
		output, err := exec.Command("powershell", "-Command",
			fmt.Sprintf("(Get-Item '%s' -Force).Attributes.value__", filepath.Clean(path))).Output()
		if err == nil {
			attrValue, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 32)
			if err == nil {
				return WindowsFileAttributes(attrValue), nil
			}
		}
	}

	// Fallback to checking individual attributes
	var attrs WindowsFileAttributes = 0

	// Check if readonly
	if isReadOnly, _ := isFileReadOnly(path); isReadOnly {
		attrs |= WinAttrReadOnly
	}

	// Check if hidden
	if isHidden, _ := IsHidden(path); isHidden {
		attrs |= WinAttrHidden
	}

	// Check if directory
	info, _ := os.Stat(path)
	if info.IsDir() {
		attrs |= WinAttrDirectory
	}

	// If no other attributes, it's normal
	if attrs == 0 {
		attrs = WinAttrNormal
	}

	return attrs, nil
}

// isFileReadOnly checks if a file is read-only on Windows
func isFileReadOnly(path string) (bool, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	// Try to open the file for writing
	file, err := os.OpenFile(path, os.O_WRONLY, info.Mode())
	if err != nil {
		// Check if the error is due to read-only status
		if os.IsPermission(err) {
			return true, nil
		}
		return false, err
	}

	file.Close()
	return false, nil
}

// SetWindowsAttributes sets Windows-specific file attributes
func SetWindowsAttributes(path string, attrs WindowsFileAttributes) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	if !osutil.IsWindows() {
		return fmt.Errorf("%w: Windows attributes are only available on Windows", errors.ErrOSNotSupported)
	}

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	// Release lock for external commands
	mu.Unlock()

	// Handle read-only attribute
	if attrs&WinAttrReadOnly != 0 {
		if err := setWindowsReadOnly(path, true); err != nil {
			mu.Lock() // Reacquire lock
			return err
		}
	} else {
		if err := setWindowsReadOnly(path, false); err != nil {
			mu.Lock() // Reacquire lock
			return err
		}
	}

	// Handle hidden attribute using attrib
	if attrs&WinAttrHidden != 0 {
		if err := exec.Command("attrib", "+h", path).Run(); err != nil {
			mu.Lock() // Reacquire lock
			return fmt.Errorf("%w: failed to set hidden attribute", errors.ErrFilePermissionError)
		}
	} else {
		if err := exec.Command("attrib", "-h", path).Run(); err != nil {
			mu.Lock() // Reacquire lock
			return fmt.Errorf("%w: failed to clear hidden attribute", errors.ErrFilePermissionError)
		}
	}

	// Handle system attribute using attrib
	if attrs&WinAttrSystem != 0 {
		if err := exec.Command("attrib", "+s", path).Run(); err != nil {
			mu.Lock() // Reacquire lock
			return fmt.Errorf("%w: failed to set system attribute", errors.ErrFilePermissionError)
		}
	} else {
		if err := exec.Command("attrib", "-s", path).Run(); err != nil {
			mu.Lock() // Reacquire lock
			return fmt.Errorf("%w: failed to clear system attribute", errors.ErrFilePermissionError)
		}
	}

	// Handle archive attribute using attrib
	if attrs&WinAttrArchive != 0 {
		if err := exec.Command("attrib", "+a", path).Run(); err != nil {
			mu.Lock() // Reacquire lock
			return fmt.Errorf("%w: failed to set archive attribute", errors.ErrFilePermissionError)
		}
	} else {
		if err := exec.Command("attrib", "-a", path).Run(); err != nil {
			mu.Lock() // Reacquire lock
			return fmt.Errorf("%w: failed to clear archive attribute", errors.ErrFilePermissionError)
		}
	}

	mu.Lock() // Reacquire lock
	return nil
}

// IsHidden checks if a file is hidden
func IsHidden(path string) (bool, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	if osutil.IsWindows() {
		// Release lock for external command
		mu.Unlock()

		// On Windows, use attrib command to check if hidden
		cmd := exec.Command("attrib", path)
		output, err := cmd.Output()

		mu.Lock() // Reacquire lock

		if err != nil {
			return false, fmt.Errorf("%w: failed to get file attributes", errors.ErrPathNotAccessible)
		}

		return strings.Contains(string(output), "H"), nil
	}

	// On Unix systems, hidden files start with a dot
	base := filepath.Base(path)
	return strings.HasPrefix(base, "."), nil
}

// MakeHidden makes a file hidden
func MakeHidden(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	if osutil.IsWindows() {
		// Release lock for external command
		mu.Unlock()

		// On Windows, use attrib command to set hidden attribute
		err := exec.Command("attrib", "+h", path).Run()

		mu.Lock() // Reacquire lock

		if err != nil {
			return fmt.Errorf("%w: failed to set hidden attribute", errors.ErrFilePermissionError)
		}
		return nil
	}

	// On Unix systems, rename the file to have a dot prefix
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	if !strings.HasPrefix(base, ".") {
		newPath := filepath.Join(dir, "."+base)

		// Need to lock the new path as well for rename
		newMu := GetPathMutex(newPath)
		newMu.Lock()
		defer newMu.Unlock()

		if err := os.Rename(path, newPath); err != nil {
			return fmt.Errorf("%w: failed to rename file", errors.ErrFilePermissionError)
		}
	}

	return nil
}
