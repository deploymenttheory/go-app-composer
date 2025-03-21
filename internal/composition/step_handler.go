package composition

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/logger"
	compression "github.com/deploymenttheory/go-app-composer/internal/utils/compressionutil"
	errors "github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"
	"github.com/deploymenttheory/go-app-composer/internal/utils/plistutil"
	"github.com/deploymenttheory/go-app-composer/internal/utils/urlutil"
	"github.com/deploymenttheory/go-app-composer/internal/utils/vtutil"
)

// StepHandler is a function that executes a workflow step
type StepHandler func(step Step, variables map[string]interface{}) (map[string]interface{}, error)

func createStepHandlerRegistry() map[string]StepHandler {
	return map[string]StepHandler{
		"download":   handleDownloadStep,
		"extract":    handleExtractStep,  // Update this to support multiple formats
		"compress":   handleCompressStep, // New step for compression
		"package":    handlePackageStep,
		"add_file":   handleAddFileStep,
		"scan":       handleScanStep,
		"sign":       handleSignStep,
		"notarize":   handleNotarizeStep,
		"upload":     handleUploadStep,
		"delete":     handleDeleteStep,
		"move":       handleMoveStep,
		"copy":       handleCopyStep,
		"exec":       handleExecStep,
		"script":     handleScriptStep,
		"edit_plist": handleEditPlistStep,
	}
}

// evaluateCondition evaluates a condition string using the provided variables
func evaluateCondition(condition string, variables map[string]interface{}) (bool, error) {
	// For now, just process the template and check if it's "true"
	// This could be enhanced with a proper expression evaluator
	result, err := processTemplate(condition, variables)
	if err != nil {
		return false, err
	}

	result = strings.TrimSpace(strings.ToLower(result))
	return result == "true" || result == "yes" || result == "1", nil
}

// ---- step handlers ---- //

// ---- download steps ---- //

// handleDownloadStep implements the download step handler
func handleDownloadStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// Validate required parameters
	url, ok := step.Parameters["url"].(string)
	if !ok {
		logger.LogError("download step requires a url parameter", nil, nil)
		return nil, fmt.Errorf("%w: missing url parameter", errors.ErrInvalidArgument)
	}

	// Validate the URL
	if err := urlutil.ValidateURL(url); err != nil {
		logger.LogError(fmt.Sprintf("Invalid URL: %s", url), err, nil)
		return nil, err
	}

	// Get output path (optional, will derive from URL if not provided)
	outputPath, _ := step.Parameters["output"].(string)

	// If output path is not absolute, make it relative to the current working directory
	if outputPath != "" && !filepath.IsAbs(outputPath) {
		cwd, err := os.Getwd()
		if err == nil {
			outputPath = filepath.Join(cwd, outputPath)
		}
	}

	// Create download options
	options := urlutil.DefaultDownloadOptions()

	// Set output path if provided
	options.OutputPath = outputPath

	// Get timeout (optional)
	if timeoutStr, ok := step.Parameters["timeout"].(string); ok {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			options.Timeout = timeout
		}
	}

	// Get checksum (optional)
	if checksum, ok := step.Parameters["checksum"].(string); ok {
		options.ExpectedChecksum = checksum
	}

	// Get checksum URL (optional) - alternative to direct checksum
	if checksumURL, ok := step.Parameters["checksum_url"].(string); ok && checksumURL != "" {
		// Only fetch checksum if we don't already have one specified directly
		if options.ExpectedChecksum == "" {
			// Validate the checksum URL
			if err := urlutil.ValidateURL(checksumURL); err != nil {
				logger.LogError(fmt.Sprintf("Invalid checksum URL: %s", checksumURL), err, nil)
				return nil, err
			}

			// Download the checksum file
			logger.LogInfo(fmt.Sprintf("Downloading checksum from: %s", checksumURL), nil)
			checksumOptions := urlutil.DefaultDownloadOptions()
			// Create a temporary file for the checksum
			tmpDir := os.TempDir()
			checksumOptions.OutputPath = filepath.Join(tmpDir, "checksum-"+strconv.FormatInt(time.Now().UnixNano(), 10))

			checksumPath, err := urlutil.DownloadFile(checksumURL, checksumOptions)
			if err != nil {
				logger.LogError("Failed to download checksum file", err, nil)
				// Continue without checksum verification, but log a warning
				logger.LogWarn("Proceeding without checksum verification", nil)
			} else {
				// Read the checksum file
				checksumData, err := os.ReadFile(checksumPath)
				if err != nil {
					logger.LogError("Failed to read checksum file", err, nil)
				} else {
					// Parse the checksum (typically checksums are the first word in the file)
					checksumStr := strings.TrimSpace(string(checksumData))
					fields := strings.Fields(checksumStr)
					if len(fields) > 0 {
						options.ExpectedChecksum = fields[0]
						logger.LogInfo(fmt.Sprintf("Using downloaded checksum: %s", options.ExpectedChecksum), nil)
					}
				}

				// Clean up the checksum file
				os.Remove(checksumPath)
			}
		}
	}

	// Get checksum verification flag (optional)
	verifyChecksum := true
	if verifyStr, ok := step.Parameters["verify_checksum"].(string); ok {
		verifyChecksum = strings.ToLower(verifyStr) != "false"
	}

	// If verification is disabled, clear the checksum
	if !verifyChecksum {
		options.ExpectedChecksum = ""
		logger.LogInfo("Checksum verification disabled", nil)
	} else if options.ExpectedChecksum == "" {
		logger.LogWarn("No checksum provided. Download will succeed without verification.", nil)
	}

	// Get checksum algorithm (optional)
	if checksumAlgo, ok := step.Parameters["checksum_algorithm"].(string); ok {
		options.ChecksumAlgorithm = checksumAlgo
	}

	// Get skip_tls_verify (optional)
	if skipTLSStr, ok := step.Parameters["skip_tls_verify"].(string); ok {
		options.SkipTLSVerify = strings.ToLower(skipTLSStr) == "true"
	}

	// Get retries (optional)
	if retriesStr, ok := step.Parameters["retries"].(string); ok {
		if retries, err := strconv.Atoi(retriesStr); err == nil && retries >= 0 {
			options.MaxRetries = retries
		}
	}

	// Get retry_delay (optional)
	if retryDelayStr, ok := step.Parameters["retry_delay"].(string); ok {
		if retryDelay, err := strconv.Atoi(retryDelayStr); err == nil && retryDelay > 0 {
			options.RetryDelay = retryDelay
		}
	}

	// Get headers (optional)
	if headersMap, ok := step.Parameters["headers"].(map[string]interface{}); ok {
		options.Headers = make(map[string]string)
		for key, val := range headersMap {
			if strVal, ok := val.(string); ok {
				options.Headers[key] = strVal
			}
		}
	}

	// Add progress tracking
	options.ProgressCallback = func(bytesDownloaded, totalBytes int64) {
		// Only log every 10% progress to avoid spamming
		if totalBytes > 0 {
			percent := float64(bytesDownloaded) / float64(totalBytes) * 100
			if percent > 0 && int64(percent)%10 == 0 {
				logger.LogInfo(fmt.Sprintf("Download progress: %.1f%% (%d/%d bytes)",
					percent, bytesDownloaded, totalBytes), nil)
			}
		}
	}

	// Execute the download
	logger.LogInfo(fmt.Sprintf("Downloading file from: %s", url), nil)
	downloadedFile, err := urlutil.DownloadFile(url, options)
	if err != nil {
		logger.LogError("Download failed", err, nil)
		return nil, err
	}

	// Verify the downloaded file exists and is readable
	if !fsutil.FileExists(downloadedFile) {
		return nil, fmt.Errorf("%w: file not found after download", errors.ErrDownloadFailed)
	}

	// Log success
	fileInfo, _ := os.Stat(downloadedFile)
	var fileSize int64
	if fileInfo != nil {
		fileSize = fileInfo.Size()
	}

	logger.LogInfo(fmt.Sprintf("Download successful: %s (%.2f MB)",
		downloadedFile, float64(fileSize)/(1024*1024)), nil)

	// Return the downloaded file path for use in subsequent steps
	results := map[string]interface{}{
		"downloaded_file": downloadedFile,
		"file_size_bytes": fileSize,
	}

	return results, nil
}

func handlePackageStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement packaging functionality
	return nil, fmt.Errorf("package step not yet implemented")
}

func handleAddFileStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement add file functionality
	return nil, fmt.Errorf("add_file step not yet implemented")
}

func handleSignStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement code signing functionality
	return nil, fmt.Errorf("sign step not yet implemented")
}

func handleNotarizeStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement notarization functionality
	return nil, fmt.Errorf("notarize step not yet implemented")
}

func handleUploadStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement upload functionality
	return nil, fmt.Errorf("upload step not yet implemented")
}

func handleDeleteStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement delete functionality
	return nil, fmt.Errorf("delete step not yet implemented")
}

func handleMoveStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement move functionality
	return nil, fmt.Errorf("move step not yet implemented")
}

func handleCopyStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement copy functionality
	return nil, fmt.Errorf("copy step not yet implemented")
}

func handleExecStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement exec functionality
	return nil, fmt.Errorf("exec step not yet implemented")
}

func handleScriptStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement script functionality
	return nil, fmt.Errorf("script step not yet implemented")
}

// ---- vt scan steps ---- //

// handleScanStep implements virus scanning functionality using VirusTotal
func handleScanStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// Validate required parameters
	input, ok := step.Parameters["input"].(string)
	if !ok {
		logger.LogError("scan step requires an input parameter", nil, nil)
		return nil, fmt.Errorf("%w: missing input parameter", errors.ErrInvalidArgument)
	}

	// Determine the scan type
	scanType, _ := step.Parameters["scan_type"].(string)
	if scanType == "" {
		// Auto-detect based on input format
		if fsutil.FileExists(input) {
			scanType = "file"
		} else if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
			scanType = "url"
		} else if net.ParseIP(input) != nil {
			scanType = "ip"
		} else {
			scanType = "domain"
		}
	}

	// Get API key (first from step parameters, then from workflow variables)
	apiKey, ok := step.Parameters["api_key"].(string)
	if !ok {
		// Try to get from variables
		if apiKeyVar, ok := variables["vt_api_key"].(string); ok {
			apiKey = apiKeyVar
		} else {
			logger.LogError("scan step requires an API key for VirusTotal", nil, nil)
			return nil, fmt.Errorf("%w: missing VirusTotal API key", errors.ErrInvalidArgument)
		}
	}

	// Initialize VirusTotal client if not already initialized
	if !vtutil.IsInitialized() {
		config := vtutil.DefaultConfig()
		config.APIKey = apiKey

		// Configure cache settings
		cacheMode := vtutil.CacheModeMemory
		if cacheStr, ok := step.Parameters["cache_mode"].(string); ok {
			switch strings.ToLower(cacheStr) {
			case "none":
				cacheMode = vtutil.CacheModeNone
			case "file":
				cacheMode = vtutil.CacheModeFile
			}
		}
		config.CacheMode = cacheMode

		// Set cache path if in file mode
		if config.CacheMode == vtutil.CacheModeFile {
			if cachePath, ok := step.Parameters["cache_path"].(string); ok {
				config.CachePath = cachePath
			} else {
				cacheDir, ok := variables["cache_dir"].(string)
				if !ok {
					cacheDir = "cache"
				}
				config.CachePath = filepath.Join(cacheDir, "vt-cache")
			}
		}

		// Initialize VT utilities
		if err := vtutil.Configure(config); err != nil {
			logger.LogError("Failed to initialize VirusTotal client", err, nil)
			return nil, fmt.Errorf("failed to initialize VirusTotal client: %w", err)
		}
	}

	// Generate results based on scan type
	var result vtutil.ScanResult

	logger.LogInfo(fmt.Sprintf("Starting VirusTotal scan of %s (%s)", input, scanType), nil)

	switch scanType {
	case "file":
		// Check if input exists
		if !fsutil.FileExists(input) {
			return nil, fmt.Errorf("%w: file not found: %s", errors.ErrFileNotFound, input)
		}

		// Configure scan options
		waitForCompletion := false
		if waitStr, ok := step.Parameters["wait_for_completion"].(string); ok {
			waitForCompletion = strings.ToLower(waitStr) == "true"
		}

		// Scan the file
		fileResult, err := vtutil.ScanFile(input,
			vtutil.WithWaitForCompletion(waitForCompletion),
		)
		if err != nil {
			logger.LogError(fmt.Sprintf("Failed to scan file: %s", input), err, nil)
			return nil, fmt.Errorf("failed to scan file: %w", err)
		}
		result = fileResult

	case "url":
		// Configure scan options
		waitForCompletion := false
		if waitStr, ok := step.Parameters["wait_for_completion"].(string); ok {
			waitForCompletion = strings.ToLower(waitStr) == "true"
		}

		// Scan the URL
		urlResult, err := vtutil.ScanURL(input,
			vtutil.WithURLWaitForCompletion(waitForCompletion),
		)
		if err != nil {
			logger.LogError(fmt.Sprintf("Failed to scan URL: %s", input), err, nil)
			return nil, fmt.Errorf("failed to scan URL: %w", err)
		}
		result = urlResult

	case "domain":
		// Check for options
		includeSubdomains := true
		if subStr, ok := step.Parameters["include_subdomains"].(string); ok {
			includeSubdomains = strings.ToLower(subStr) != "false"
		}

		includeWhois := true
		if whoisStr, ok := step.Parameters["include_whois"].(string); ok {
			includeWhois = strings.ToLower(whoisStr) != "false"
		}

		// Scan the domain
		domainResult, err := vtutil.LookupDomain(input,
			vtutil.WithDomainSubdomains(includeSubdomains),
			vtutil.WithDomainWhois(includeWhois),
		)
		if err != nil {
			logger.LogError(fmt.Sprintf("Failed to scan domain: %s", input), err, nil)
			return nil, fmt.Errorf("failed to scan domain: %w", err)
		}
		result = domainResult

	case "ip":
		// Check for options
		includeResolutions := true
		if resStr, ok := step.Parameters["include_resolutions"].(string); ok {
			includeResolutions = strings.ToLower(resStr) != "false"
		}

		// Scan the IP
		ipResult, err := vtutil.LookupIP(input,
			vtutil.WithIPResolutions(includeResolutions),
		)
		if err != nil {
			logger.LogError(fmt.Sprintf("Failed to scan IP: %s", input), err, nil)
			return nil, fmt.Errorf("failed to scan IP: %w", err)
		}
		result = ipResult

	default:
		return nil, fmt.Errorf("%w: unsupported scan type: %s", errors.ErrInvalidScanType, scanType)
	}

	// Create a standardized summary
	summary := vtutil.GetScanResultSummary(result)
	threatLevel := vtutil.ThreatLevelToString(summary.ThreatLevel)

	logger.LogInfo(fmt.Sprintf("VirusTotal scan completed: %s is %s (Threat Level: %s)",
		input, summary.ThreatName, threatLevel), nil)

	// Return results for use in subsequent steps
	return map[string]interface{}{
		"vt_scan_result":  result,
		"vt_threat_level": threatLevel,
		"vt_threat_name":  summary.ThreatName,
		"vt_permalink":    summary.Permalink,
		"vt_scan_date":    summary.ScanDate.Format(time.RFC3339),
		"vt_resource":     summary.Resource,
	}, nil
}

// ---- compress / decompress steps ---- //

func handleCompressStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	format, ok := step.Parameters["format"].(string)
	if !ok {
		logger.LogError("compress step requires a format parameter", nil, nil)
		return nil, fmt.Errorf("%w: invalid argument", errors.ErrInvalidArgument)
	}

	src, ok := step.Parameters["source"].(string)
	if !ok {
		logger.LogError("compress step requires a source parameter", nil, nil)
		return nil, fmt.Errorf("%w: invalid argument", errors.ErrInvalidArgument)
	}

	dst, ok := step.Parameters["destination"].(string)
	if !ok {
		logger.LogError("compress step requires a destination parameter", nil, nil)
		return nil, fmt.Errorf("%w: invalid argument", errors.ErrInvalidArgument)
	}

	// Ensure enough disk space before compression
	estimatedSize, err := compression.EstimateCompressionSize(src, format)
	if err != nil {
		logger.LogError("failed to estimate compression size", err, nil)
		return nil, fmt.Errorf("%w: compression failed", errors.ErrCompressionFailed)
	}

	sufficientSpace, err := fsutil.HasEnoughDiskSpace(dst, estimatedSize)
	if err != nil {
		logger.LogError("failed to check disk space", err, nil)
		return nil, fmt.Errorf("%w: disk space error", errors.ErrDiskSpaceError)
	}
	if !sufficientSpace {
		logger.LogError(fmt.Sprintf("not enough disk space to compress %s", src), nil, nil)
		return nil, fmt.Errorf("%w: insufficient disk space", errors.ErrInsufficientDiskSpace)
	}

	switch format {
	case "zip":
		return nil, compression.CompressZIP(src, dst)
	case "tar":
		return nil, compression.CompressTAR(src, dst)
	case "gzip":
		return nil, compression.CompressGZIP(src, dst)
	case "bzip2":
		return nil, compression.CompressBZIP2(src, dst)
	case "xz":
		return nil, compression.CompressXZ(src, dst)
	default:
		logger.LogError(fmt.Sprintf("unsupported compression format: %s", format), nil, nil)
		return nil, fmt.Errorf("%w: unsupported compression format", errors.ErrUnsupportedCompression)
	}
}

func handleExtractStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	format, ok := step.Parameters["format"].(string)
	if !ok {
		logger.LogError("extract step requires a format parameter", nil, nil)
		return nil, fmt.Errorf("%w: invalid argument", errors.ErrInvalidArgument)
	}

	src, ok := step.Parameters["source"].(string)
	if !ok {
		logger.LogError("extract step requires a source parameter", nil, nil)
		return nil, fmt.Errorf("%w: invalid argument", errors.ErrInvalidArgument)
	}

	dst, ok := step.Parameters["destination"].(string)
	if !ok {
		logger.LogError("extract step requires a destination parameter", nil, nil)
		return nil, fmt.Errorf("%w: invalid argument", errors.ErrInvalidArgument)
	}

	// Auto-detect archive format if not provided
	if format == "auto" {
		detectedFormat, err := compression.DetectArchiveFormat(src)
		if err != nil {
			logger.LogError("failed to detect archive format", err, nil)
			return nil, fmt.Errorf("%w: invalid archive format", errors.ErrInvalidArchive)
		}
		format = detectedFormat
	}

	// Ensure destination is writable
	if !fsutil.IsWritable(dst) {
		logger.LogError(fmt.Sprintf("destination %s is not writable", dst), nil, nil)
		return nil, fmt.Errorf("%w: insufficient permissions", errors.ErrInsufficientPermissions)
	}

	switch format {
	case "zip":
		return nil, compression.ExtractZIP(src, dst)
	case "tar":
		return nil, compression.ExtractTAR(src, dst)
	case "gzip":
		return nil, compression.ExtractGZIP(src, dst)
	case "bzip2":
		return nil, compression.ExtractBZIP2(src, dst)
	case "xz":
		return nil, compression.ExtractXZ(src, dst)
	default:
		logger.LogError(fmt.Sprintf("unsupported extraction format: %s", format), nil, nil)
		return nil, fmt.Errorf("%w: unsupported compression format", errors.ErrUnsupportedCompression)
	}
}

// handleEditPlistStep modifies a property list file
func handleEditPlistStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// Validate required parameters
	plistPath, ok := step.Parameters["path"].(string)
	if !ok {
		logger.LogError("edit_plist step requires a path parameter", nil, nil)
		return nil, fmt.Errorf("%w: missing path parameter", errors.ErrInvalidArgument)
	}

	// Check if the plist file exists
	if !fsutil.FileExists(plistPath) {
		logger.LogError(fmt.Sprintf("plist file not found: %s", plistPath), nil, nil)
		return nil, fmt.Errorf("%w: plist file not found", errors.ErrFileNotFound)
	}

	// Get the operation type (set, delete, merge)
	operation, ok := step.Parameters["operation"].(string)
	if !ok {
		operation = "set" // Default operation
	}

	// Get the format (if converting)
	formatStr, _ := step.Parameters["format"].(string)
	format := plistutil.StringToFormat(formatStr)

	// Perform the requested operation
	switch operation {
	case "set":
		return handleSetPlistValue(step, plistPath, variables)
	case "delete":
		return handleDeletePlistValue(step, plistPath)
	case "merge":
		return handleMergePlist(step, plistPath)
	case "convert":
		return handleConvertPlist(step, plistPath, format)
	default:
		logger.LogError(fmt.Sprintf("unsupported plist operation: %s", operation), nil, nil)
		return nil, fmt.Errorf("%w: unsupported plist operation", errors.ErrInvalidArgument)
	}
}

// handleSetPlistValue sets a value in a plist
func handleSetPlistValue(step Step, plistPath string, variables map[string]interface{}) (map[string]interface{}, error) {
	// Validate parameters
	key, ok := step.Parameters["key"].(string)
	if !ok {
		logger.LogError("set operation requires a key parameter", nil, nil)
		return nil, fmt.Errorf("%w: missing key parameter", errors.ErrInvalidArgument)
	}

	value, ok := step.Parameters["value"]
	if !ok {
		logger.LogError("set operation requires a value parameter", nil, nil)
		return nil, fmt.Errorf("%w: missing value parameter", errors.ErrInvalidArgument)
	}

	// Process template in value if it's a string
	if strValue, ok := value.(string); ok {
		processedValue, err := processTemplate(strValue, variables)
		if err != nil {
			logger.LogError("error processing template in value", err, nil)
			return nil, fmt.Errorf("%w: template processing failed", errors.ErrInvalidArgument)
		}
		value = processedValue
	}

	// Get the output format
	formatStr, _ := step.Parameters["format"].(string)
	format := plistutil.StringToFormat(formatStr)

	// If format is auto, detect the current format
	if format == plistutil.FormatAuto {
		detectedFormat, err := plistutil.DetectFormat(plistPath)
		if err != nil {
			logger.LogError("failed to detect plist format", err, nil)
			return nil, fmt.Errorf("%w: failed to detect plist format", errors.ErrUnsupportedFile)
		}
		format = detectedFormat
	}

	// Read the plist
	data, err := plistutil.ReadPlist(plistPath)
	if err != nil {
		logger.LogError("failed to read plist", err, nil)
		return nil, err
	}

	// Set the value
	err = plistutil.SetValue(data, key, value)
	if err != nil {
		logger.LogError(fmt.Sprintf("failed to set value for key: %s", key), err, nil)
		return nil, fmt.Errorf("%w: failed to set plist value", errors.ErrInvalidArgument)
	}

	// Write the plist back
	err = plistutil.WritePlist(plistPath, data, format)
	if err != nil {
		logger.LogError("failed to write plist", err, nil)
		return nil, err
	}

	logger.LogInfo(fmt.Sprintf("Successfully set value for key '%s' in plist: %s", key, plistPath), nil)
	return nil, nil
}

// handleDeletePlistValue deletes a value from a plist
func handleDeletePlistValue(step Step, plistPath string) (map[string]interface{}, error) {
	// Validate parameters
	key, ok := step.Parameters["key"].(string)
	if !ok {
		logger.LogError("delete operation requires a key parameter", nil, nil)
		return nil, fmt.Errorf("%w: missing key parameter", errors.ErrInvalidArgument)
	}

	// Get the output format
	formatStr, _ := step.Parameters["format"].(string)
	format := plistutil.StringToFormat(formatStr)

	// If format is auto, detect the current format
	if format == plistutil.FormatAuto {
		detectedFormat, err := plistutil.DetectFormat(plistPath)
		if err != nil {
			logger.LogError("failed to detect plist format", err, nil)
			return nil, fmt.Errorf("%w: failed to detect plist format", errors.ErrUnsupportedFile)
		}
		format = detectedFormat
	}

	// Read the plist
	data, err := plistutil.ReadPlist(plistPath)
	if err != nil {
		logger.LogError("failed to read plist", err, nil)
		return nil, err
	}

	// Delete the value
	deleted := plistutil.DeleteValue(data, key)
	if !deleted {
		logger.LogWarn(fmt.Sprintf("key not found in plist: %s", key), nil)
		// Not returning an error as the end state is what was desired (key not present)
	}

	// Write the plist back
	err = plistutil.WritePlist(plistPath, data, format)
	if err != nil {
		logger.LogError("failed to write plist", err, nil)
		return nil, err
	}

	logger.LogInfo(fmt.Sprintf("Successfully deleted key '%s' from plist: %s", key, plistPath), nil)
	return nil, nil
}

// handleMergePlist merges a plist with another plist
func handleMergePlist(step Step, plistPath string) (map[string]interface{}, error) {
	// Validate parameters
	sourcePath, ok := step.Parameters["source"].(string)
	if !ok {
		logger.LogError("merge operation requires a source parameter", nil, nil)
		return nil, fmt.Errorf("%w: missing source parameter", errors.ErrInvalidArgument)
	}

	// Check if the source plist exists
	if !fsutil.FileExists(sourcePath) {
		logger.LogError(fmt.Sprintf("source plist file not found: %s", sourcePath), nil, nil)
		return nil, fmt.Errorf("%w: source plist file not found", errors.ErrFileNotFound)
	}

	// Get the output format
	formatStr, _ := step.Parameters["format"].(string)
	format := plistutil.StringToFormat(formatStr)

	// If format is auto, detect the current format
	if format == plistutil.FormatAuto {
		detectedFormat, err := plistutil.DetectFormat(plistPath)
		if err != nil {
			logger.LogError("failed to detect plist format", err, nil)
			return nil, fmt.Errorf("%w: failed to detect plist format", errors.ErrUnsupportedFile)
		}
		format = detectedFormat
	}

	// Read the destination plist
	destData, err := plistutil.ReadPlist(plistPath)
	if err != nil {
		logger.LogError("failed to read destination plist", err, nil)
		return nil, err
	}

	// Read the source plist
	sourceData, err := plistutil.ReadPlist(sourcePath)
	if err != nil {
		logger.LogError("failed to read source plist", err, nil)
		return nil, err
	}

	// Merge the plists
	mergedData := plistutil.MergePlists(destData, sourceData)

	// Write the merged plist back
	err = plistutil.WritePlist(plistPath, mergedData, format)
	if err != nil {
		logger.LogError("failed to write merged plist", err, nil)
		return nil, err
	}

	logger.LogInfo(fmt.Sprintf("Successfully merged plist from %s into %s", sourcePath, plistPath), nil)
	return nil, nil
}

// handleConvertPlist converts a plist to a different format
func handleConvertPlist(step Step, plistPath string, format plistutil.Format) (map[string]interface{}, error) {
	// Validate parameters
	if format == plistutil.FormatAuto {
		logger.LogError("convert operation requires a specific format", nil, nil)
		return nil, fmt.Errorf("%w: invalid format for conversion", errors.ErrInvalidArgument)
	}

	// Get optional output path
	outputPath, ok := step.Parameters["output"].(string)
	if !ok {
		// If no output path is provided, convert in-place
		outputPath = plistPath
	}

	// Read the plist
	data, err := plistutil.ReadPlist(plistPath)
	if err != nil {
		logger.LogError("failed to read plist", err, nil)
		return nil, err
	}

	// Write the plist in the new format
	err = plistutil.WritePlist(outputPath, data, format)
	if err != nil {
		logger.LogError("failed to write plist in new format", err, nil)
		return nil, err
	}

	logger.LogInfo(fmt.Sprintf("Successfully converted plist to %s format: %s", plistutil.FormatToString(format), outputPath), nil)
	return nil, nil
}
