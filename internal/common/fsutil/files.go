// fsutil/files.go
package fsutil

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// FileInfo represents metadata about a file
type FileInfo struct {
	Path        string
	Size        int64
	Mode        os.FileMode
	IsDir       bool
	ModTime     time.Time
	ContentType string
}

// FileExists checks if a file exists and is not a directory
func FileExists(path string) bool {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// GetFileInfo retrieves file information
func GetFileInfo(path string) (*FileInfo, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("error getting file info: %w", err)
	}

	return &FileInfo{
		Path:    path,
		Size:    info.Size(),
		Mode:    info.Mode(),
		IsDir:   info.IsDir(),
		ModTime: info.ModTime(),
	}, nil
}

// ReadFile reads an entire file into memory
func ReadFile(path string) ([]byte, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	return os.ReadFile(path)
}

// ReadFileString reads a file and returns its contents as a string
func ReadFileString(path string) (string, error) {
	data, err := ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteFile writes data to a file, creating it if necessary
func WriteFile(path string, data []byte, perm os.FileMode) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(path)
	dirMu := GetPathMutex(dir)
	dirMu.Lock()
	defer dirMu.Unlock()

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, perm)
}

// WriteFileString writes a string to a file
func WriteFileString(path string, content string, perm os.FileMode) error {
	return WriteFile(path, []byte(content), perm)
}

// AppendToFile appends data to an existing file
func AppendToFile(path string, data []byte) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

// AppendStringToFile appends a string to an existing file
func AppendStringToFile(path string, content string) error {
	return AppendToFile(path, []byte(content))
}

// CopyFile copies a file from source to destination
func CopyFile(src, dst string) error {
	// Lock both source and destination to prevent concurrent modifications
	unlock := acquireMutexes(src, dst)
	defer unlock()

	// Open source file
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening source file: %w", err)
	}
	defer sourceFile.Close()

	// Get file information
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("error getting source file info: %w", err)
	}

	// Create destination directory if it doesn't exist
	destDir := filepath.Dir(dst)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("error creating destination directory: %w", err)
	}

	// Create destination file
	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}
	defer destFile.Close()

	// Copy the content
	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("error copying file: %w", err)
	}

	// Set the same permissions
	if err = os.Chmod(dst, sourceInfo.Mode()); err != nil {
		return fmt.Errorf("error setting file permissions: %w", err)
	}

	return nil
}

// MoveFile moves a file from source to destination
func MoveFile(src, dst string) error {
	// Lock both source and destination
	unlock := acquireMutexes(src, dst)
	defer unlock()

	// First try the atomic rename operation
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// If rename fails (e.g., cross-device), release locks to avoid deadlocks
	unlock()

	// Fall back to copy and delete
	if err := CopyFile(src, dst); err != nil {
		return err
	}

	return DeleteFile(src)
}

// DeleteFile deletes a file if it exists
func DeleteFile(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check if file exists under lock
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil // File doesn't exist or is a directory, nothing to do
	}
	return os.Remove(path)
}

// ReadLines reads a file line by line and returns an array of strings
func ReadLines(path string) ([]string, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// ReadFileChunked reads a file in chunks, calling the provided function for each chunk
func ReadFileChunked(path string, chunkSize int, processChunk func([]byte) error) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	buffer := make([]byte, chunkSize)
	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		// Process the chunk while holding the lock
		// If the processing function is long-running, consider releasing the lock
		// and reacquiring it after processing each chunk
		if err := processChunk(buffer[:bytesRead]); err != nil {
			return err
		}
	}

	return nil
}

// GetFileHash calculates a file's hash using the specified algorithm
func GetFileHash(path string, hashType string) (string, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hash string

	switch hashType {
	case "md5":
		h := md5.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(h.Sum(nil))

	case "sha1":
		h := sha1.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(h.Sum(nil))

	case "sha256":
		h := sha256.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(h.Sum(nil))

	default:
		return "", errors.New("unsupported hash type")
	}

	return hash, nil
}

// TouchFile updates a file's access and modification times, creating it if it doesn't exist
func TouchFile(path string) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Check if file exists
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		// Create an empty file
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		return file.Close()
	} else if err != nil {
		return err
	}

	// File exists, update timestamp
	currentTime := time.Now().Local()
	return os.Chtimes(path, currentTime, currentTime)
}

// IsFileExecutable checks if a file is executable
func IsFileExecutable(path string) bool {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if the execute bit is set for user
	return info.Mode()&0100 != 0
}

// SetFileExecutable sets or removes the executable bit on a file
func SetFileExecutable(path string, executable bool) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode()
	if executable {
		mode |= 0111 // add execute bit for user, group, and others
	} else {
		mode &^= 0111 // remove execute bit for user, group, and others
	}

	return os.Chmod(path, mode)
}

// IsFileEmpty checks if a file is empty (size of 0 bytes)
func IsFileEmpty(path string) (bool, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	return info.Size() == 0, nil
}

// IsFileBinary makes a best-effort determination of whether a file is binary or text
func IsFileBinary(path string) (bool, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	// Read a small chunk of the file to analyze
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Read the first 512 bytes to check for NUL bytes
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}

	// Check for NUL bytes, which typically indicate binary content
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true, nil
		}
	}

	return false, nil
}

// ReadFileHeader reads the first n bytes of a file
func ReadFileHeader(path string, n int) ([]byte, error) {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buffer := make([]byte, n)
	bytesRead, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return buffer[:bytesRead], nil
}

// ReadFileChunkedWithLimit reads a file in chunks, stopping after maxBytes or EOF
func ReadFileChunkedWithLimit(path string, chunkSize int, maxBytes int64, processChunk func([]byte, int64) error) error {
	mu := GetPathMutex(path)
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	buffer := make([]byte, chunkSize)
	var totalBytesRead int64 = 0

	for {
		// Check if we've read enough already
		if maxBytes > 0 && totalBytesRead >= maxBytes {
			break
		}

		// Calculate remaining bytes to read
		remainingBytes := chunkSize
		if maxBytes > 0 {
			remainingToLimit := maxBytes - totalBytesRead
			if int64(remainingBytes) > remainingToLimit {
				remainingBytes = int(remainingToLimit)
			}
		}

		// Read the next chunk
		bytesRead, err := file.Read(buffer[:remainingBytes])
		if bytesRead > 0 {
			totalBytesRead += int64(bytesRead)

			// Process this chunk
			if err := processChunk(buffer[:bytesRead], totalBytesRead); err != nil {
				return err
			}
		}

		// Handle EOF or other errors
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	return nil
}
