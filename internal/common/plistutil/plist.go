// Package plistutil provides utilities for working with property list files
package plistutil

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/common/errors"
	"github.com/deploymenttheory/go-app-composer/internal/common/fsutil"
	"howett.net/plist"
)

// Format represents the plist format
type Format int

const (
	// FormatXML is the XML plist format
	FormatXML Format = iota
	// FormatBinary is the binary plist format
	FormatBinary
	// FormatOpenStep is the OpenStep plist format
	FormatOpenStep
	// FormatGNUStep is the GNUStep plist format
	FormatGNUStep
	// FormatAuto will auto-detect the format when reading
	FormatAuto
)

// PlistInfo contains information about a property list
type PlistInfo struct {
	Path   string
	Format Format
	Data   map[string]interface{}
}

// ReadPlist reads a property list file and returns its contents as a map
func ReadPlist(path string) (map[string]interface{}, error) {
	data, err := fsutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("%w: %s", errors.ErrPermissionDenied, path)
		}
		return nil, fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	// Decode the plist data
	var result map[string]interface{}
	decoder := plist.NewDecoder(bytes.NewReader(data))
	err = decoder.Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
	}

	return result, nil
}

// WritePlist writes data to a property list file in the specified format
func WritePlist(path string, data map[string]interface{}, format Format) error {
	// Ensure the directory exists
	dir, _ := fsutil.SplitPath(path)
	if err := fsutil.CreateDirIfNotExists(dir); err != nil {
		return fmt.Errorf("%w: failed to create directory", errors.ErrPathNotAccessible)
	}

	// Create or truncate the file
	file, err := os.Create(path)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w: %s", errors.ErrPermissionDenied, path)
		}
		return fmt.Errorf("%w: %s", errors.ErrFileWriteError, path)
	}
	defer file.Close()

	// Create encoder with the specified format
	var encoder *plist.Encoder
	switch format {
	case FormatXML:
		encoder = plist.NewEncoderForFormat(file, plist.XMLFormat)
	case FormatBinary:
		encoder = plist.NewEncoderForFormat(file, plist.BinaryFormat)
	case FormatOpenStep:
		encoder = plist.NewEncoderForFormat(file, plist.OpenStepFormat)
	case FormatGNUStep:
		encoder = plist.NewEncoderForFormat(file, plist.GNUStepFormat)
	default:
		// Default to XML for safety
		encoder = plist.NewEncoderForFormat(file, plist.XMLFormat)
	}

	// Encode the data
	err = encoder.Encode(data)
	if err != nil {
		return fmt.Errorf("%w: %s", errors.ErrFileWriteError, err.Error())
	}

	return nil
}

// DetectFormat detects the format of a plist file
func DetectFormat(path string) (Format, error) {
	// Use our new ReadFileHeader function to get the first 8 bytes
	header, err := fsutil.ReadFileHeader(path, 8)
	if err != nil {
		if os.IsNotExist(err) {
			return FormatXML, fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
		}
		if os.IsPermission(err) {
			return FormatXML, fmt.Errorf("%w: %s", errors.ErrPermissionDenied, path)
		}
		return FormatXML, fmt.Errorf("%w: %s", errors.ErrPathNotAccessible, path)
	}

	// Check for XML
	if bytes.HasPrefix(header, []byte("<?xml")) || bytes.HasPrefix(header, []byte("<!DOCTYPE")) {
		return FormatXML, nil
	}

	// Check for binary (bplist00)
	if bytes.HasPrefix(header, []byte("bplist00")) {
		return FormatBinary, nil
	}

	// Check for OpenStep/GNUStep format (usually starts with (, {, or /)
	if bytes.HasPrefix(header, []byte("{")) || bytes.HasPrefix(header, []byte("(")) || bytes.HasPrefix(header, []byte("/")) {
		// Simple heuristic - OpenStep is more common on macOS
		return FormatOpenStep, nil
	}

	// Default to XML if can't determine
	return FormatXML, nil
}

// GetValue retrieves a value from the plist using a dot-notation path
func GetValue(data map[string]interface{}, path string) (interface{}, bool) {
	keys := strings.Split(path, ".")
	current := data

	// Navigate through the nested structure
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - return the value
			val, ok := current[key]
			return val, ok
		}

		// Not the last key - move to the next level
		nextLevel, ok := current[key]
		if !ok {
			return nil, false
		}

		// Check if the next level is a map
		nextMap, ok := nextLevel.(map[string]interface{})
		if !ok {
			// If we hit a non-map before the last key, the path is invalid
			return nil, false
		}

		current = nextMap
	}

	return nil, false
}

// SetValue sets a value in the plist using a dot-notation path
func SetValue(data map[string]interface{}, path string, value interface{}) error {
	keys := strings.Split(path, ".")
	current := data

	// Navigate through the nested structure
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - set the value
			current[key] = value
			return nil
		}

		// Not the last key - move to the next level
		nextLevel, ok := current[key]
		if !ok {
			// Key doesn't exist, create a new map
			nextMap := make(map[string]interface{})
			current[key] = nextMap
			current = nextMap
			continue
		}

		// Check if the next level is a map
		nextMap, ok := nextLevel.(map[string]interface{})
		if !ok {
			// If we hit a non-map before the last key, we need to replace it
			nextMap = make(map[string]interface{})
			current[key] = nextMap
		}

		current = nextMap
	}

	return nil
}

// DeleteValue removes a value from the plist using a dot-notation path
func DeleteValue(data map[string]interface{}, path string) bool {
	keys := strings.Split(path, ".")
	current := data

	// Navigate through the nested structure
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - delete the value
			_, exists := current[key]
			if exists {
				delete(current, key)
				return true
			}
			return false
		}

		// Not the last key - move to the next level
		nextLevel, ok := current[key]
		if !ok {
			// Key doesn't exist, nothing to delete
			return false
		}

		// Check if the next level is a map
		nextMap, ok := nextLevel.(map[string]interface{})
		if !ok {
			// If we hit a non-map before the last key, the path is invalid
			return false
		}

		current = nextMap
	}

	return false
}

// FormatToString converts a Format enum to a string
func FormatToString(format Format) string {
	switch format {
	case FormatXML:
		return "XML"
	case FormatBinary:
		return "Binary"
	case FormatOpenStep:
		return "OpenStep"
	case FormatGNUStep:
		return "GNUStep"
	case FormatAuto:
		return "Auto"
	default:
		return "Unknown"
	}
}

// StringToFormat converts a string to a Format enum
func StringToFormat(formatStr string) Format {
	switch strings.ToLower(formatStr) {
	case "xml":
		return FormatXML
	case "binary":
		return FormatBinary
	case "openstep":
		return FormatOpenStep
	case "gnustep":
		return FormatGNUStep
	case "auto":
		return FormatAuto
	default:
		return FormatXML // Default to XML
	}
}

// ConvertFormat converts a plist file from one format to another
func ConvertFormat(srcPath, dstPath string, dstFormat Format) error {
	// Read the source plist
	data, err := ReadPlist(srcPath)
	if err != nil {
		return err
	}

	// Write to the destination in the specified format
	return WritePlist(dstPath, data, dstFormat)
}

// Validate checks if a file is a valid plist
func Validate(path string) error {
	// Try to read the plist
	_, err := ReadPlist(path)
	return err
}

// MergePlists merges two plists, with the second one taking precedence
func MergePlists(base, overlay map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy all keys from base
	for k, v := range base {
		result[k] = v
	}

	// Overlay with the second plist, handling nested maps
	for k, v := range overlay {
		if baseVal, ok := result[k]; ok {
			// Check if both values are maps and can be merged
			if baseMap, ok := baseVal.(map[string]interface{}); ok {
				if overlayMap, ok := v.(map[string]interface{}); ok {
					// Both are maps, recursively merge them
					result[k] = MergePlists(baseMap, overlayMap)
					continue
				}
			}
		}
		// Not maps or only one is a map, just override
		result[k] = v
	}

	return result
}
