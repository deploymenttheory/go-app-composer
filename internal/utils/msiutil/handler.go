// Package msiutil provides utilities for working with Windows Installer (.msi) files
package msiutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/logger"
	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"
	"github.com/deploymenttheory/go-app-composer/internal/utils/osutil"
)

// MSIHandler provides methods for MSI file operations
type MSIHandler struct{}

// NewMSIHandler creates a new MSI handler
func NewMSIHandler() *MSIHandler {
	return &MSIHandler{}
}

// validateWindowsOS checks if the current OS supports MSI operations
func (h *MSIHandler) validateWindowsOS() error {
	if !osutil.IsWindows() {
		return fmt.Errorf("%w: MSI operations are only supported on Windows", errors.ErrOSNotSupported)
	}
	return nil
}

// ensureMsiToolsAvailable checks if required MSI tools are installed
func (h *MSIHandler) ensureMsiToolsAvailable() error {
	requiredTools := []string{"msiinfo", "msiextract", "msidump"}

	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			logger.LogError("MSI tool not found", err, map[string]interface{}{
				"tool": tool,
			})
			return fmt.Errorf("%w: MSI tool '%s' not found", errors.ErrFileNotFound, tool)
		}
	}

	return nil
}

// ExtractMSI extracts contents of an MSI file
func (h *MSIHandler) ExtractMSI(msiPath, outputDir string, listOnly bool) error {
	// Validate Windows OS and tool availability
	if err := h.validateWindowsOS(); err != nil {
		logger.LogError("Windows OS validation failed", err, nil)
		return err
	}
	if err := h.ensureMsiToolsAvailable(); err != nil {
		logger.LogError("MSI tools not available", err, nil)
		return err
	}

	// Ensure output directory exists
	if err := fsutil.CreateDirIfNotExists(outputDir); err != nil {
		logger.LogError("Failed to create output directory", err, map[string]interface{}{
			"path": outputDir,
		})
		return err
	}

	// Use path mutex for thread-safe file access
	mu := fsutil.GetPathMutex(msiPath)
	mu.Lock()
	defer mu.Unlock()

	// Validate MSI file exists
	if _, err := os.Stat(msiPath); os.IsNotExist(err) {
		logger.LogError("MSI file not found", err, map[string]interface{}{
			"path": msiPath,
		})
		return fmt.Errorf("%w: %s", errors.ErrFileNotFound, msiPath)
	}

	// Prepare extraction command
	args := []string{"msiextract", "--directory", outputDir}
	if listOnly {
		args = append(args, "--list")
	}
	args = append(args, msiPath)

	// Execute extraction
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.LogError("MSI extraction failed", err, map[string]interface{}{
			"output": string(output),
		})
		return fmt.Errorf("%w: extracting MSI contents", errors.ErrExtractionFailed)
	}

	logger.LogInfo("MSI extraction completed", map[string]interface{}{
		"source": msiPath,
		"dest":   outputDir,
	})
	return nil
}

// ExtractMSIStream extracts a specific stream from an MSI file
func (h *MSIHandler) ExtractMSIStream(msiPath, streamName, outputPath string) error {
	// Validate Windows OS and tool availability
	if err := h.validateWindowsOS(); err != nil {
		logger.LogError("Windows OS validation failed", err, nil)
		return err
	}
	if err := h.ensureMsiToolsAvailable(); err != nil {
		logger.LogError("MSI tools not available", err, nil)
		return err
	}

	// Use path mutex for thread-safe file access
	mu := fsutil.GetPathMutex(msiPath)
	mu.Lock()
	defer mu.Unlock()

	// Validate MSI file exists
	if _, err := os.Stat(msiPath); os.IsNotExist(err) {
		logger.LogError("MSI file not found", err, map[string]interface{}{
			"path": msiPath,
		})
		return fmt.Errorf("%w: %s", errors.ErrFileNotFound, msiPath)
	}

	// Ensure output directory exists if output path is specified
	if outputPath != "" {
		if err := fsutil.CreateDirIfNotExists(filepath.Dir(outputPath)); err != nil {
			logger.LogError("Failed to create output directory", err, map[string]interface{}{
				"path": filepath.Dir(outputPath),
			})
			return err
		}
	}

	// Prepare stream extraction command
	cmd := exec.Command("msiinfo", "extract", msiPath, streamName)

	// Handle output based on whether an output path is provided
	var err error
	if outputPath != "" {
		var outputFile *os.File
		outputFile, err = os.Create(outputPath)
		if err != nil {
			logger.LogError("Failed to create output file", err, map[string]interface{}{
				"path": outputPath,
			})
			return fmt.Errorf("%w: creating output file", errors.ErrFileCreateFailed)
		}
		defer outputFile.Close()
		cmd.Stdout = outputFile
		err = cmd.Run()
	} else {
		_, err = cmd.CombinedOutput()
	}

	// Check for errors
	if err != nil {
		logger.LogError("Stream extraction failed", err, map[string]interface{}{
			"msi":    msiPath,
			"stream": streamName,
		})
		return fmt.Errorf("%w: extracting MSI stream", errors.ErrExtractionFailed)
	}

	logger.LogInfo("Stream extracted successfully", map[string]interface{}{
		"msi":    msiPath,
		"stream": streamName,
	})
	return nil
}

// ListMSITables retrieves the list of tables in an MSI file
func (h *MSIHandler) ListMSITables(msiPath string) ([]string, error) {
	// Validate Windows OS and tool availability
	if err := h.validateWindowsOS(); err != nil {
		logger.LogError("Windows OS validation failed", err, nil)
		return nil, err
	}
	if err := h.ensureMsiToolsAvailable(); err != nil {
		logger.LogError("MSI tools not available", err, nil)
		return nil, err
	}

	// Use path mutex for thread-safe file access
	mu := fsutil.GetPathMutex(msiPath)
	mu.Lock()
	defer mu.Unlock()

	// Validate MSI file exists
	if _, err := os.Stat(msiPath); os.IsNotExist(err) {
		logger.LogError("MSI file not found", err, map[string]interface{}{
			"path": msiPath,
		})
		return nil, fmt.Errorf("%w: %s", errors.ErrFileNotFound, msiPath)
	}

	// Run msiinfo to list tables
	cmd := exec.Command("msiinfo", "tables", msiPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.LogError("Failed to list MSI tables", err, nil)
		return nil, fmt.Errorf("%w: listing MSI tables", errors.ErrFileReadError)
	}

	// Parse and return tables
	return strings.Fields(string(output)), nil
}
