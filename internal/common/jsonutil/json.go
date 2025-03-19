package jsonutil

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/common/errors"
	"github.com/deploymenttheory/go-app-composer/internal/common/fsutil"
)

// ReadJSONFile reads a JSON file and unmarshals its contents into a map
func ReadJSONFile(path string) (map[string]interface{}, error) {
	if !fsutil.FileExists(path) {
		return nil, fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
	}

	data, err := fsutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrFileReadError, err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
	}

	return result, nil
}

// WriteJSONFile writes a map to a JSON file with indentation
func WriteJSONFile(path string, data map[string]interface{}) error {
	if !fsutil.DirExists(fsutil.GetDir(path)) {
		return fmt.Errorf("%w: %s", errors.ErrDirNotFound, path)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
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
