package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"
)

// JSONFormat represents the formatting style for JSON files
type JSONFormat int

const (
	// FormatStandard uses standard JSON formatting
	FormatStandard JSONFormat = iota
	// FormatIndented uses indented JSON with 2-space indentation
	FormatIndented
	// FormatMinified removes all whitespace
	FormatMinified
)

// JSONOptions provides configuration for JSON operations
type JSONOptions struct {
	Format       JSONFormat
	IndentPrefix string
	IndentSize   int
}

// DefaultJSONOptions provides default settings for JSON formatting
var DefaultJSONOptions = JSONOptions{
	Format:       FormatIndented,
	IndentPrefix: "",
	IndentSize:   2,
}

// ReadJSON reads a JSON file and unmarshals its contents into a map
func ReadJSON(path string) (map[string]interface{}, error) {
	if !fsutil.FileExists(path) {
		return nil, fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
	}

	data, err := fsutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrFileReadError, err.Error())
	}

	var result map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber() // Preserve numeric precision
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
	}

	return result, nil
}

// WriteJSON writes a map to a JSON file with specified formatting
func WriteJSON(path string, data map[string]interface{}, options ...JSONOptions) error {
	if !fsutil.DirExists(fsutil.GetDir(path)) {
		return fmt.Errorf("%w: %s", errors.ErrDirNotFound, path)
	}

	// Use default options if not provided
	opts := DefaultJSONOptions
	if len(options) > 0 {
		opts = options[0]
	}

	var jsonData []byte
	var err error

	switch opts.Format {
	case FormatIndented:
		jsonData, err = json.MarshalIndent(data, opts.IndentPrefix, strings.Repeat(" ", opts.IndentSize))
	case FormatMinified:
		jsonData, err = json.Marshal(data)
	default:
		// Standard formatting
		jsonData, err = json.MarshalIndent(data, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("%w: %s", errors.ErrFileWriteError, err.Error())
	}

	return fsutil.WriteFile(path, jsonData, 0644)
}

// GetValue retrieves a value from JSON using a dot-notation path
func GetValue(data map[string]interface{}, path string) (interface{}, bool) {
	keys := strings.Split(path, ".")
	current := data

	for i, key := range keys {
		if i == len(keys)-1 {
			val, ok := current[key]
			return val, ok
		}

		next, ok := current[key].(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = next
	}
	return nil, false
}

// SetValue sets a value in JSON using a dot-notation path
func SetValue(data map[string]interface{}, path string, value interface{}) error {
	keys := strings.Split(path, ".")
	current := data

	for i, key := range keys {
		if i == len(keys)-1 {
			current[key] = value
			return nil
		}

		next, ok := current[key].(map[string]interface{})
		if !ok {
			next = make(map[string]interface{})
			current[key] = next
		}
		current = next
	}
	return nil
}

// DeleteValue removes a value from JSON using a dot-notation path
func DeleteValue(data map[string]interface{}, path string) bool {
	keys := strings.Split(path, ".")
	current := data

	for i, key := range keys {
		if i == len(keys)-1 {
			_, exists := current[key]
			if exists {
				delete(current, key)
				return true
			}
			return false
		}

		next, ok := current[key].(map[string]interface{})
		if !ok {
			return false
		}
		current = next
	}
	return false
}

// MergeJSON merges two JSON objects, with the second one taking precedence
func MergeJSON(base, overlay map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for k, v := range base {
		result[k] = v
	}

	for k, v := range overlay {
		if baseMap, ok := result[k].(map[string]interface{}); ok {
			if overlayMap, ok := v.(map[string]interface{}); ok {
				result[k] = MergeJSON(baseMap, overlayMap)
				continue
			}
		}
		result[k] = v
	}

	return result
}

// Validate checks if a file contains valid JSON
func Validate(path string) error {
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %s", errors.ErrFileNotFound, err.Error())
	}
	defer file.Close()

	// Create a JSON decoder
	decoder := json.NewDecoder(file)
	decoder.UseNumber() // Preserve numeric precision

	// Try to read the first token
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%w: invalid JSON", errors.ErrUnsupportedFile)
	}

	// Ensure no additional tokens remain
	if decoder.More() {
		return fmt.Errorf("%w: multiple JSON objects", errors.ErrUnsupportedFile)
	}

	return nil
}

// PrettyPrint converts a map to a formatted JSON string
func PrettyPrint(data map[string]interface{}) (string, error) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrFileWriteError, err.Error())
	}
	return string(jsonData), nil
}

// Clone creates a deep copy of a JSON map
func Clone(data map[string]interface{}) (map[string]interface{}, error) {
	// Marshal the original map to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrFileWriteError, err.Error())
	}

	// Unmarshal back into a new map
	var clonedData map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(jsonData))
	decoder.UseNumber() // Preserve numeric precision
	if err := decoder.Decode(&clonedData); err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
	}

	return clonedData, nil
}
