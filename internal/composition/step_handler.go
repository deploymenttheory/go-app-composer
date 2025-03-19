package composition

import (
	"fmt"
	"strings"

	compression "github.com/deploymenttheory/go-app-composer/internal/common/compressionutil"
	errors "github.com/deploymenttheory/go-app-composer/internal/common/errors"
	"github.com/deploymenttheory/go-app-composer/internal/common/fsutil"
	logger "github.com/deploymenttheory/go-app-composer/internal/common/zap_logger"
)

// StepHandler is a function that executes a workflow step
type StepHandler func(step Step, variables map[string]interface{}) (map[string]interface{}, error)

func createStepHandlerRegistry() map[string]StepHandler {
	return map[string]StepHandler{
		"download": handleDownloadStep,
		"extract":  handleExtractStep,  // Update this to support multiple formats
		"compress": handleCompressStep, // New step for compression
		"package":  handlePackageStep,
		"add_file": handleAddFileStep,
		"scan":     handleScanStep,
		"sign":     handleSignStep,
		"notarize": handleNotarizeStep,
		"upload":   handleUploadStep,
		"delete":   handleDeleteStep,
		"move":     handleMoveStep,
		"copy":     handleCopyStep,
		"exec":     handleExecStep,
		"script":   handleScriptStep,
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

// Step handler implementations would go here
// These are placeholders that would be implemented with actual functionality

func handleDownloadStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement download functionality
	return nil, fmt.Errorf("download step not yet implemented")
}

func handlePackageStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement packaging functionality
	return nil, fmt.Errorf("package step not yet implemented")
}

func handleAddFileStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement add file functionality
	return nil, fmt.Errorf("add_file step not yet implemented")
}

func handleScanStep(step Step, variables map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement virus scan functionality
	return nil, fmt.Errorf("scan step not yet implemented")
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

// ---- compress / decompress steps ----

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
