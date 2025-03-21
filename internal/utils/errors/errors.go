package errors

import (
	"errors"
)

var (
	// General Errors
	ErrInvalidArgument   = errors.New("invalid argument")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrUnsupportedFile   = errors.New("unsupported file format")
	ErrPathNotAccessible = errors.New("path is not accessible")
	ErrOSNotSupported    = errors.New("operating system not supported")

	// Compression Errors
	ErrCompressionFailed       = errors.New("compression failed")
	ErrUnsupportedCompression  = errors.New("unsupported compression format")
	ErrInsufficientDiskSpace   = errors.New("not enough disk space to complete compression/extraction")
	ErrInvalidArchive          = errors.New("archive file is corrupted or unsupported")
	ErrDiskSpaceError          = errors.New("disk space error")
	ErrInsufficientPermissions = errors.New("insufficient permissions to access or modify required files")

	// Extraction Errors
	ErrExtractionFailed    = errors.New("extraction failed")
	ErrDecompressionFailed = errors.New("decompression failed")

	// File & Directory Errors
	ErrFileNotFound        = errors.New("file not found")
	ErrFilePermissionError = errors.New("error setting file permissions")
	ErrFileReadError       = errors.New("error reading file")
	ErrFileWriteError      = errors.New("error writing to file")
	ErrFileDeleteError     = errors.New("error deleting file")
	ErrFileExistsError     = errors.New("file already exists")
	ErrDirNotFound         = errors.New("directory not found")
	ErrDirPermissionError  = errors.New("error setting directory permissions")
	ErrDirCopyError        = errors.New("error copying directory")
	ErrDirMoveError        = errors.New("error moving directory")

	// Download Errors
	ErrDownloadFailed   = errors.New("failed to download file")
	ErrChecksumFailed   = errors.New("checksum mismatch after download")
	ErrNetworkTimeout   = errors.New("network timeout or connection failure")
	ErrInvalidURL       = errors.New("invalid download URL")
	ErrHTTPStatusFailed = errors.New("unexpected HTTP status code during download")
	ErrFileCreateFailed = errors.New("failed to create destination file")
	ErrFileWriteFailed  = errors.New("failed to write to file during download")

	// Hash Errors
	ErrInvalidHasher = errors.New("invalid hasher")

	// Package Manager Errors
	ErrPackageNotFound      = errors.New("package not found") // Fixed typo from 'rrPackageNotFound'
	ErrPackageInstallFailed = errors.New("package installation failed")
	ErrPackageRemoveFailed  = errors.New("package removal failed")
	ErrPackageUpdateFailed  = errors.New("package update failed")
	ErrPackageBuildFailed   = errors.New("package build failed")
	ErrInvalidPackage       = errors.New("invalid package definition")
	ErrPackageManagerError  = errors.New("error from package manager")
	ErrUnsupportedPackage   = errors.New("unsupported package format")
	ErrDependencyResolution = errors.New("failed to resolve dependencies")
	ErrRepositoryNotFound   = errors.New("package repository not found")
	ErrRepositoryUpdate     = errors.New("failed to update package repository")

	// VirusTotal API Errors
	ErrAPIKeyMissing           = errors.New("API key is required")
	ErrAPIRateLimitExceeded    = errors.New("API rate limit exceeded")
	ErrAPICommunicationError   = errors.New("error communicating with VirusTotal API")
	ErrAPIAuthenticationFailed = errors.New("VirusTotal API authentication failed")
	ErrAPIQuotaExceeded        = errors.New("VirusTotal API quota exceeded")

	// Scanning Errors
	ErrScanFailed           = errors.New("scan failed to complete")
	ErrScanTimeout          = errors.New("scan timed out")
	ErrScanNotFound         = errors.New("scan result not found")
	ErrResourceNotFound     = errors.New("requested resource not found")
	ErrInvalidScanType      = errors.New("invalid scan type")
	ErrUploadError          = errors.New("error uploading file for scanning")
	ErrTooLargeForScan      = errors.New("file too large for scanning")
	ErrFileTypeNotSupported = errors.New("file type not supported for scanning")

	// Network Errors
	ErrNetworkError        = errors.New("network error")
	ErrHostNotFound        = errors.New("host not found")
	ErrConnectionRefused   = errors.New("connection refused")
	ErrSSLCertificateError = errors.New("SSL certificate error")

	// Cache Errors
	ErrCacheFailure        = errors.New("cache operation failed")
	ErrCacheCorrupted      = errors.New("cache data corrupted")
	ErrCacheNotInitialized = errors.New("cache not initialized")

	// Configuration Errors
	ErrConfigInvalid      = errors.New("invalid configuration")
	ErrConfigFileNotFound = errors.New("configuration file not found")
	ErrConfigParseError   = errors.New("error parsing configuration")
	ErrAlreadyInitialized = errors.New("component already initialized")
	ErrNotInitialized     = errors.New("component not initialized")
)
