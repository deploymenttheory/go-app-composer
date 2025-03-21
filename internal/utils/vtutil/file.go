package vtutil

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/logger"
	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"

	vt "github.com/VirusTotal/vt-go"
)

// File hash types
const (
	HashTypeMD5    = "md5"
	HashTypeSHA1   = "sha1"
	HashTypeSHA256 = "sha256"
)

// FileScanStatus represents the status of a file scan
type FileScanStatus string

// File scan status constants
const (
	FileScanStatusQueued     FileScanStatus = "queued"
	FileScanStatusInProgress FileScanStatus = "in_progress"
	FileScanStatusCompleted  FileScanStatus = "completed"
	FileScanStatusError      FileScanStatus = "error"
)

// FileScanResult represents the result of a file scan
type FileScanResult struct {
	FileInfo      FileInfo                `json:"file_info"`
	ScanID        string                  `json:"scan_id"`
	Status        FileScanStatus          `json:"status"`
	Resource      string                  `json:"resource"`
	Permalink     string                  `json:"permalink"`
	PositiveCount int                     `json:"positive_count"`
	TotalCount    int                     `json:"total_count"`
	ScanDate      time.Time               `json:"scan_date"`
	EngineResults map[string]EngineResult `json:"engine_results"`
	Categories    []string                `json:"categories"`
	Tags          []string                `json:"tags"`
	Error         string                  `json:"error,omitempty"`
}

// FileInfo contains information about a scanned file
type FileInfo struct {
	Name         string            `json:"name"`
	Size         int64             `json:"size"`
	Type         string            `json:"type"`
	MD5          string            `json:"md5"`
	SHA1         string            `json:"sha1"`
	SHA256       string            `json:"sha256"`
	LastModified time.Time         `json:"last_modified"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// EngineResult represents the result from a single antivirus engine
type EngineResult struct {
	Category      string `json:"category"`
	Result        string `json:"result"`
	Method        string `json:"method"`
	EngineVersion string `json:"engine_version"`
	EngineUpdate  string `json:"engine_update"`
}

// FileScanOptions represents options for file scanning
type FileScanOptions struct {
	EnableCache       bool              // Whether to use caching
	SkipEngineDetail  bool              // Skip detailed engine results to reduce response size
	WaitForCompletion bool              // Wait for scan completion (may take time)
	PollingInterval   time.Duration     // Interval for polling scan results
	PollingTimeout    time.Duration     // Maximum time to wait for scan completion
	CustomName        string            // Custom name for the file
	CustomTags        []string          // Custom tags for the file
	ProgressCallback  func(float32)     // Callback for upload progress
	AdditionalParams  map[string]string // Additional API parameters
}

// DefaultFileScanOptions returns default options for file scanning
func DefaultFileScanOptions() FileScanOptions {
	return FileScanOptions{
		EnableCache:       true,
		SkipEngineDetail:  false,
		WaitForCompletion: false,
		PollingInterval:   time.Second * 15,
		PollingTimeout:    time.Minute * 10,
		ProgressCallback:  nil,
		AdditionalParams:  make(map[string]string),
	}
}

// calculateFileHashes calculates MD5, SHA1, and SHA256 hashes for a file
func calculateFileHashes(filePath string) (md5Hash, sha1Hash, sha256Hash string, err error) {
	// Use fsutil for thread-safe file operations
	fileMutex := fsutil.GetPathMutex(filePath)
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %s", errors.ErrFileReadError, err.Error())
	}
	defer file.Close()

	// Create hash instances
	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()

	// Create a multi-writer to write to all hashers simultaneously
	multiWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)

	// Copy file data to the multi-writer
	if _, err := io.Copy(multiWriter, file); err != nil {
		return "", "", "", fmt.Errorf("%w: %s", errors.ErrFileReadError, err.Error())
	}

	// Get hash values
	md5Hash = hex.EncodeToString(md5Hasher.Sum(nil))
	sha1Hash = hex.EncodeToString(sha1Hasher.Sum(nil))
	sha256Hash = hex.EncodeToString(sha256Hasher.Sum(nil))

	return md5Hash, sha1Hash, sha256Hash, nil
}

// GetFileInfo retrieves detailed information about a file
func GetFileInfo(filePath string) (*FileInfo, error) {
	// Use fsutil for thread-safe file operations
	fileMutex := fsutil.GetPathMutex(filePath)
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", errors.ErrFileNotFound, filePath)
		}
		return nil, fmt.Errorf("%w: %s", errors.ErrFileReadError, err.Error())
	}

	// Calculate file hashes
	md5Hash, sha1Hash, sha256Hash, err := calculateFileHashes(filePath)
	if err != nil {
		return nil, err
	}

	// Get file extension and determine basic file type
	fileExt := strings.ToLower(filepath.Ext(filePath))
	fileType := determineFileType(fileExt)

	// Create file info
	result := &FileInfo{
		Name:         fileInfo.Name(),
		Size:         fileInfo.Size(),
		Type:         fileType,
		MD5:          md5Hash,
		SHA1:         sha1Hash,
		SHA256:       sha256Hash,
		LastModified: fileInfo.ModTime(),
		Metadata:     make(map[string]string),
	}

	// Add additional metadata
	result.Metadata["path"] = filePath
	result.Metadata["extension"] = fileExt

	return result, nil
}

// determineFileType returns a basic file type based on extension
func determineFileType(ext string) string {
	// Remove the leading dot
	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}

	ext = strings.ToLower(ext)

	// Map common extensions to generic file types
	switch ext {
	case "exe", "msi", "dll", "sys", "com", "bat", "cmd":
		return "executable"
	case "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt":
		return "document"
	case "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "svg":
		return "image"
	case "mp3", "wav", "ogg", "flac", "aac", "wma":
		return "audio"
	case "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm":
		return "video"
	case "zip", "rar", "7z", "tar", "gz", "bz2", "xz":
		return "archive"
	case "html", "htm", "css", "js", "json", "xml", "csv", "txt":
		return "text"
	case "iso", "img", "dmg":
		return "disk_image"
	case "apk", "ipa":
		return "mobile_app"
	default:
		return "unknown"
	}
}

// ScanFile uploads and scans a file with VirusTotal
func ScanFile(filePath string, options ...func(*FileScanOptions)) (*FileScanResult, error) {
	// Create options with defaults and apply provided options
	opts := DefaultFileScanOptions()
	for _, option := range options {
		option(&opts)
	}

	// Get client
	client, err := GetClient()
	if err != nil {
		return nil, err
	}

	// Get file info
	fileInfo, err := GetFileInfo(filePath)
	if err != nil {
		return nil, err
	}

	// Check cache if enabled
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("file_scan:%s", fileInfo.SHA256)
		if cachedResult, found := client.getCachedResult(cacheKey); found {
			logger.LogInfo("Retrieved file scan result from cache", map[string]interface{}{
				"file":   filepath.Base(filePath),
				"sha256": fileInfo.SHA256,
			})
			return cachedResult.(*FileScanResult), nil
		}
	}

	// Initialize scan result
	result := &FileScanResult{
		FileInfo:      *fileInfo,
		Status:        FileScanStatusQueued,
		Resource:      fileInfo.SHA256,
		EngineResults: make(map[string]EngineResult),
	}

	// Try to get report first (file might have been previously scanned)
	report, err := LookupFileByHash(fileInfo.SHA256)
	if err == nil && report != nil {
		// File already analyzed
		logger.LogInfo("File already analyzed by VirusTotal", map[string]interface{}{
			"file":   filepath.Base(filePath),
			"sha256": fileInfo.SHA256,
		})

		// If we've found a report, cache and return it
		if opts.EnableCache {
			cacheKey := fmt.Sprintf("file_scan:%s", fileInfo.SHA256)
			client.cacheResult(cacheKey, report)
		}

		return report, nil
	}

	// If file not found, upload and scan it
	logger.LogInfo("Uploading file for scanning", map[string]interface{}{
		"file": filepath.Base(filePath),
		"size": fileInfo.Size,
	})

	// Create a new file scanner
	scanner := client.vtClient.NewFileScanner()

	// Upload the file
	var scanObj *vt.Object
	var scanErr error

	// Execute the upload with retries
	uploadErr := client.executeWithRetry(fmt.Sprintf("file_upload:%s", filepath.Base(filePath)), func() error {
		// Use fsutil for thread-safe file operations
		fileMutex := fsutil.GetPathMutex(filePath)
		fileMutex.Lock()
		defer fileMutex.Unlock()

		// Open the file
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("%w: %s", errors.ErrFileReadError, err.Error())
		}
		defer file.Close()

		// Create a progress channel if callback provided
		var progressChan chan<- float32
		if opts.ProgressCallback != nil {
			ch := make(chan float32)
			progressChan = ch

			// Start a goroutine to handle progress updates
			go func() {
				for progress := range ch {
					opts.ProgressCallback(progress)
				}
			}()
		}

		// Scan the file with parameters
		customName := opts.CustomName
		if customName == "" {
			customName = fileInfo.Name
		}

		// Create parameters map
		params := make(map[string]string)
		for k, v := range opts.AdditionalParams {
			params[k] = v
		}

		// Add custom name if provided
		if customName != "" {
			params["filename"] = customName
		}

		scanObj, scanErr = scanner.ScanFileWithParameters(file, progressChan, params)
		return scanErr
	})

	// Handle upload errors
	if uploadErr != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrUploadError, uploadErr.Error())
	}

	// Extract scan ID
	scanID, err := scanObj.GetString("id")
	if err != nil {
		return nil, fmt.Errorf("failed to get scan ID: %w", err)
	}

	// Update result with scan ID
	result.ScanID = scanID
	result.Status = FileScanStatusInProgress

	// Get permalink
	permalink, _ := scanObj.GetString("url")
	result.Permalink = permalink

	logger.LogInfo("File uploaded successfully", map[string]interface{}{
		"file":    filepath.Base(filePath),
		"scan_id": scanID,
	})

	// Wait for completion if requested
	if opts.WaitForCompletion {
		pollResult, err := pollScanCompletion(client, scanID, opts.PollingInterval, opts.PollingTimeout)
		if err != nil {
			return nil, err
		}
		result = pollResult
	}

	// Cache the result if enabled
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("file_scan:%s", fileInfo.SHA256)
		client.cacheResult(cacheKey, result)
	}

	return result, nil
}

// LookupFileByHash gets a file analysis report using its hash
func LookupFileByHash(fileHash string) (*FileScanResult, error) {
	// Get client
	client, err := GetClient()
	if err != nil {
		return nil, err
	}

	// Check if hash is valid (we expect SHA256, but handle other formats)
	hashType := detectHashType(fileHash)
	if hashType == "" {
		return nil, fmt.Errorf("%w: invalid hash format", errors.ErrInvalidArgument)
	}

	// Check cache
	cacheKey := fmt.Sprintf("file_scan:%s", fileHash)
	if cachedResult, found := client.getCachedResult(cacheKey); found {
		logger.LogInfo("Retrieved file hash lookup from cache", map[string]interface{}{
			"hash": fileHash,
			"type": hashType,
		})
		return cachedResult.(*FileScanResult), nil
	}

	// Initialize the result
	result := &FileScanResult{
		Resource:      fileHash,
		Status:        FileScanStatusCompleted,
		EngineResults: make(map[string]EngineResult),
	}

	// Get file report from VirusTotal
	var fileObj *vt.Object
	lookupErr := client.executeWithRetry(fmt.Sprintf("file_lookup:%s", fileHash), func() error {
		var err error
		fileObj, err = client.vtClient.GetObject(vt.URL("files/%s", fileHash))
		return err
	})

	// Handle lookup errors
	if lookupErr != nil {
		// Check if this is a "not found" error
		if strings.Contains(lookupErr.Error(), "not found") {
			logger.LogInfo("File not found in VirusTotal database", map[string]interface{}{
				"hash": fileHash,
			})
			return nil, fmt.Errorf("%w: file not found in VirusTotal database", errors.ErrFileNotFound)
		}
		return nil, fmt.Errorf("%w: %s", errors.ErrNetworkError, lookupErr.Error())
	}

	// Parse the object
	return parseFileObject(fileObj, result)
}

// parseFileObject parses a VirusTotal file object into our FileScanResult structure
func parseFileObject(obj *vt.Object, result *FileScanResult) (*FileScanResult, error) {
	// Extract file info
	fileInfo := FileInfo{
		Size: 0, // Default values
	}

	// Get hashes
	sha256, _ := obj.GetString("sha256")
	sha1, _ := obj.GetString("sha1")
	md5, _ := obj.GetString("md5")
	fileInfo.SHA256 = sha256
	fileInfo.SHA1 = sha1
	fileInfo.MD5 = md5

	// Get name and type
	name, _ := obj.GetString("meaningful_name")
	if name == "" {
		name, _ = obj.GetString("name")
	}
	fileInfo.Name = name

	// Get file type
	fileType, _ := obj.GetString("type_description")
	if fileType == "" {
		fileType, _ = obj.GetString("type_tag")
	}
	fileInfo.Type = fileType

	// Get file size
	size, err := obj.GetInt64("size")
	if err == nil {
		fileInfo.Size = size
	}

	// Get last modified/analysis date
	scanDate, err := obj.GetTime("last_analysis_date")
	if err == nil {
		result.ScanDate = scanDate
		fileInfo.LastModified = scanDate
	}

	// Get scan results
	lastAnalysisStats, err := obj.Get("last_analysis_stats")
	if err == nil {
		if stats, ok := lastAnalysisStats.(map[string]interface{}); ok {
			if positives, found := stats["malicious"]; found {
				if positiveCount, ok := positives.(float64); ok {
					result.PositiveCount = int(positiveCount)
				}
			}

			total := 0
			for _, count := range stats {
				if countVal, ok := count.(float64); ok {
					total += int(countVal)
				}
			}
			result.TotalCount = total
		}
	}

	// Get scan results from engines
	lastAnalysisResults, err := obj.Get("last_analysis_results")
	if err == nil {
		if results, ok := lastAnalysisResults.(map[string]interface{}); ok {
			for engine, data := range results {
				if engineData, ok := data.(map[string]interface{}); ok {
					engineResult := EngineResult{}

					if category, found := engineData["category"].(string); found {
						engineResult.Category = category
					}

					if result, found := engineData["result"].(string); found {
						engineResult.Result = result
					}

					if method, found := engineData["method"].(string); found {
						engineResult.Method = method
					}

					if version, found := engineData["engine_version"].(string); found {
						engineResult.EngineVersion = version
					}

					if update, found := engineData["engine_update"].(string); found {
						engineResult.EngineUpdate = update
					}

					result.EngineResults[engine] = engineResult
				}
			}
		}
	}

	// Get tags
	tags, err := obj.GetStringSlice("tags")
	if err == nil {
		result.Tags = tags
	}

	// Get permalink
	permalink := fmt.Sprintf("https://www.virustotal.com/gui/file/%s/detection", sha256)
	result.Permalink = permalink

	// Update the FileInfo in the result
	result.FileInfo = fileInfo
	result.Resource = sha256
	result.Status = FileScanStatusCompleted

	return result, nil
}

// pollScanCompletion polls VirusTotal until the scan is completed or times out
func pollScanCompletion(client *Client, analysisID string, pollingInterval, timeout time.Duration) (*FileScanResult, error) {
	startTime := time.Now()

	logger.LogInfo("Polling for scan completion", map[string]interface{}{
		"analysis_id": analysisID,
		"timeout":     timeout.String(),
	})

	for {
		// Check if we've exceeded the timeout
		if time.Since(startTime) > timeout {
			return nil, fmt.Errorf("%w: scan polling timed out after %s", errors.ErrNetworkTimeout, timeout.String())
		}

		// Get analysis
		var analysisObj *vt.Object
		err := client.executeWithRetry(fmt.Sprintf("analysis_poll:%s", analysisID), func() error {
			var err error
			analysisObj, err = client.vtClient.GetObject(vt.URL("analyses/%s", analysisID))
			return err
		})

		if err != nil {
			logger.LogWarn("Failed to get analysis status", map[string]interface{}{
				"analysis_id": analysisID,
				"error":       err.Error(),
			})
			// Continue polling
			time.Sleep(pollingInterval)
			continue
		}

		// Check status
		status, err := analysisObj.GetString("status")
		if err != nil {
			// Continue polling if we can't get the status
			time.Sleep(pollingInterval)
			continue
		}

		// If completed, get the file result
		if status == "completed" {
			logger.LogInfo("Scan completed", map[string]interface{}{
				"analysis_id": analysisID,
			})

			// Get the file hash from the analysis using Get for the metadata
			metaData, err := analysisObj.Get("meta")
			if err != nil {
				return nil, fmt.Errorf("failed to get file metadata: %w", err)
			}

			// Convert to map to navigate the structure
			metaMap, ok := metaData.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("metadata is not in expected format")
			}

			// Get file_info
			fileInfo, ok := metaMap["file_info"].(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("file_info is not in expected format")
			}

			// Get sha256
			fileHash, ok := fileInfo["sha256"].(string)
			if !ok {
				return nil, fmt.Errorf("failed to get file hash")
			}

			// Get the full file report
			return LookupFileByHash(fileHash)
		} else if status == "failed" {
			return nil, fmt.Errorf("%w: scan failed", errors.ErrScanFailed)
		}

		// Still in progress, continue polling
		logger.LogInfo("Scan in progress, continuing to poll", map[string]interface{}{
			"analysis_id": analysisID,
			"status":      status,
		})

		time.Sleep(pollingInterval)
	}
}

// detectHashType tries to determine the hash type from its format
func detectHashType(hash string) string {
	hash = strings.TrimSpace(hash)

	switch len(hash) {
	case 32:
		// Could be MD5
		if isHexString(hash) {
			return HashTypeMD5
		}
	case 40:
		// Could be SHA1
		if isHexString(hash) {
			return HashTypeSHA1
		}
	case 64:
		// Could be SHA256
		if isHexString(hash) {
			return HashTypeSHA256
		}
	}

	return ""
}

// isHexString checks if a string is a valid hexadecimal string
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// WithFileCache enables or disables caching
func WithFileCache(enable bool) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		o.EnableCache = enable
	}
}

// WithEngineDetail enables or disables detailed engine results
func WithEngineDetail(includeDetail bool) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		o.SkipEngineDetail = !includeDetail
	}
}

// WithWaitForCompletion sets whether to wait for scan completion
func WithWaitForCompletion(wait bool) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		o.WaitForCompletion = wait
	}
}

// WithPollingSettings configures polling settings
func WithPollingSettings(interval, timeout time.Duration) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		if interval > 0 {
			o.PollingInterval = interval
		}
		if timeout > 0 {
			o.PollingTimeout = timeout
		}
	}
}

// WithCustomName sets a custom name for the file
func WithCustomName(name string) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		o.CustomName = name
	}
}

// WithCustomTags sets custom tags for the file
func WithCustomTags(tags []string) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		o.CustomTags = tags
	}
}

// WithProgressCallback sets a progress callback for upload
func WithProgressCallback(callback func(float32)) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		o.ProgressCallback = callback
	}
}

// WithAdditionalParams sets additional API parameters
func WithAdditionalParams(params map[string]string) func(*FileScanOptions) {
	return func(o *FileScanOptions) {
		for k, v := range params {
			o.AdditionalParams[k] = v
		}
	}
}
