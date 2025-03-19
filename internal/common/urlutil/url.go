// Package urlutil provides URL handling utilities for network operations
package urlutil

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/common/cryptoutil"
	"github.com/deploymenttheory/go-app-composer/internal/common/errors"
	"github.com/deploymenttheory/go-app-composer/internal/common/fsutil"
	logger "github.com/deploymenttheory/go-app-composer/internal/common/zap_logger"
)

// DownloadOptions represents options for downloading files
type DownloadOptions struct {
	// Output file path (if empty, will use the filename from URL)
	OutputPath string

	// HTTP timeout in seconds (default: 30s)
	Timeout int

	// Expected file checksum for verification
	ExpectedChecksum string

	// Checksum algorithm (md5, sha1, sha256)
	ChecksumAlgorithm string

	// Skip TLS verification
	SkipTLSVerify bool

	// HTTP headers to send with the request
	Headers map[string]string

	// Auto-retry settings
	MaxRetries int
	RetryDelay int // in seconds

	// Progress callback (receives bytes downloaded and total size)
	ProgressCallback func(bytesDownloaded, totalBytes int64)
}

// Default values for download options
const (
	DefaultTimeout    = 30 // 30 seconds
	DefaultMaxRetries = 3  // 3 retry attempts
	DefaultRetryDelay = 2  // 2 seconds between retries
)

// DefaultDownloadOptions returns a DownloadOptions with sensible defaults
func DefaultDownloadOptions() DownloadOptions {
	return DownloadOptions{
		Timeout:           DefaultTimeout,
		MaxRetries:        DefaultMaxRetries,
		RetryDelay:        DefaultRetryDelay,
		ChecksumAlgorithm: "sha256",
	}
}

// DownloadFile downloads a file from a URL with the specified options
func DownloadFile(sourceURL string, options DownloadOptions) (string, error) {
	// Parse the URL
	parsedURL, err := url.Parse(sourceURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	// Determine output path if not specified
	outputPath := options.OutputPath
	if outputPath == "" {
		// Extract filename from URL
		filename := filepath.Base(parsedURL.Path)
		if filename == "" || filename == "." || filename == "/" {
			// If URL doesn't have a useful filename, use the host + a timestamp
			timestamp := time.Now().Unix()
			filename = fmt.Sprintf("%s-%d", parsedURL.Hostname(), timestamp)
		}

		// Use current directory if no path specified
		outputPath = filename
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := fsutil.CreateDirIfNotExists(outputDir); err != nil {
		return "", fmt.Errorf("%w: failed to create output directory: %s", errors.ErrFileWriteError, err.Error())
	}

	// Create a custom HTTP client with the specified options
	client := createHTTPClient(options)

	// Prepare the request
	req, err := http.NewRequest("GET", sourceURL, nil)
	if err != nil {
		return "", fmt.Errorf("%w: failed to create request: %s", errors.ErrInvalidURL, err.Error())
	}

	// Add custom headers
	for key, value := range options.Headers {
		req.Header.Add(key, value)
	}

	// Set default headers if not overridden
	if _, ok := options.Headers["User-Agent"]; !ok {
		req.Header.Add("User-Agent", "go-app-composer/1.0")
	}

	// Download with retries
	var resp *http.Response
	var downloadErr error

	for attempt := 0; attempt <= options.MaxRetries; attempt++ {
		if attempt > 0 {
			logger.LogInfo(fmt.Sprintf("Retrying download (attempt %d/%d)...", attempt, options.MaxRetries), nil)
			time.Sleep(time.Duration(options.RetryDelay) * time.Second)
		}

		resp, downloadErr = client.Do(req)
		if downloadErr == nil && resp.StatusCode < 500 {
			break // Success or client error (don't retry 4xx errors)
		}

		if resp != nil {
			resp.Body.Close()
		}
	}

	// Handle download errors
	if downloadErr != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrDownloadFailed, downloadErr.Error())
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: HTTP status %d", errors.ErrHTTPStatusFailed, resp.StatusCode)
	}

	// Get file size for progress reporting
	fileSize := resp.ContentLength

	// Create the output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrFileCreateFailed, err.Error())
	}
	defer outputFile.Close()

	// Create a checksummer based on the algorithm
	checksummer, err := createChecksummer(options.ChecksumAlgorithm)
	if err != nil {
		return "", err
	}

	// Create a multi-writer to write to file and calculate checksum simultaneously
	var writer io.Writer
	if checksummer != nil {
		writer = io.MultiWriter(outputFile, checksummer)
	} else {
		writer = outputFile
	}

	// Create progress wrapper if callback is provided
	if options.ProgressCallback != nil && fileSize > 0 {
		writer = &progressWriter{
			Writer:   writer,
			FileSize: fileSize,
			Callback: options.ProgressCallback,
		}
	}

	// Copy data from response to file
	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		// Remove partial download on error
		outputFile.Close()
		os.Remove(outputPath)
		return "", fmt.Errorf("%w: %s", errors.ErrFileWriteFailed, err.Error())
	}

	// Verify checksum if expected checksum was provided
	if options.ExpectedChecksum != "" && checksummer != nil {
		hashWriter, ok := checksummer.(*cryptoutil.HashWriter)
		if !ok {
			return "", fmt.Errorf("invalid checksummer type")
		}

		actualChecksum := hashWriter.SumHex()
		if !strings.EqualFold(actualChecksum, options.ExpectedChecksum) {
			// Remove file if checksum doesn't match
			outputFile.Close()
			os.Remove(outputPath)
			return "", fmt.Errorf("%w: expected %s, got %s",
				errors.ErrChecksumFailed, options.ExpectedChecksum, actualChecksum)
		}
	}

	return outputPath, nil
}

// createHTTPClient creates an HTTP client with the specified options
func createHTTPClient(options DownloadOptions) *http.Client {
	// Set timeout
	timeout := time.Duration(options.Timeout) * time.Second
	if timeout <= 0 {
		timeout = DefaultTimeout * time.Second
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.SkipTLSVerify,
	}

	// Create transport with better defaults
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// createChecksummer creates a hash writer based on the specified algorithm
func createChecksummer(algorithm string) (io.Writer, error) {
	if algorithm == "" {
		return nil, nil
	}

	// Convert string to HashAlgorithm type
	hashAlgo := cryptoutil.HashAlgorithm(strings.ToLower(algorithm))

	// Create a hasher
	hasher, err := cryptoutil.NewHasher(hashAlgo)
	if err != nil {
		return nil, err
	}

	// Get a hash writer
	return hasher.NewHashWriter()
}

// progressWriter wraps an io.Writer to provide progress updates
type progressWriter struct {
	Writer         io.Writer
	FileSize       int64
	BytesProcessed int64
	Callback       func(int64, int64)
}

// Write implements io.Writer and updates progress
func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.Writer.Write(p)
	if err != nil {
		return n, err
	}

	pw.BytesProcessed += int64(n)
	if pw.Callback != nil {
		pw.Callback(pw.BytesProcessed, pw.FileSize)
	}

	return n, nil
}

// ValidateURL checks if a URL is valid and reachable
func ValidateURL(rawURL string) error {
	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	// Check scheme
	if parsedURL.Scheme == "" {
		return fmt.Errorf("%w: missing scheme (http:// or https://)", errors.ErrInvalidURL)
	}

	// Only allow HTTP and HTTPS
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme '%s'", errors.ErrInvalidURL, parsedURL.Scheme)
	}

	// Check host
	if parsedURL.Host == "" {
		return fmt.Errorf("%w: missing host", errors.ErrInvalidURL)
	}

	return nil
}

// GetFilenameFromURL extracts the filename from a URL
func GetFilenameFromURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	// Extract filename from path
	filename := filepath.Base(parsedURL.Path)

	// If the URL ends with a slash, the filename will be empty or "."
	if filename == "" || filename == "." {
		return "", fmt.Errorf("%w: could not determine filename from URL", errors.ErrInvalidURL)
	}

	return filename, nil
}

// GetRedirectURL follows redirects and returns the final URL
func GetRedirectURL(rawURL string) (string, error) {
	// Create a client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Send a HEAD request
	resp, err := client.Head(rawURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrDownloadFailed, err.Error())
	}
	defer resp.Body.Close()

	// If we got a redirect, return the Location header
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location == "" {
			return "", fmt.Errorf("%w: redirect with no Location header", errors.ErrInvalidURL)
		}

		// If location is relative, resolve it against the original URL
		if !strings.HasPrefix(location, "http") {
			baseURL, err := url.Parse(rawURL)
			if err != nil {
				return "", fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
			}

			relativeURL, err := url.Parse(location)
			if err != nil {
				return "", fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
			}

			resolvedURL := baseURL.ResolveReference(relativeURL)
			location = resolvedURL.String()
		}

		return location, nil
	}

	// No redirect, return the original URL
	return rawURL, nil
}

// GetFileSize gets the size of a file from a URL without downloading it
func GetFileSize(rawURL string) (int64, error) {
	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	// Create a client with default settings
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Send a HEAD request
	req, err := http.NewRequest("HEAD", parsedURL.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	req.Header.Add("User-Agent", "go-app-composer/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", errors.ErrDownloadFailed, err.Error())
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%w: HTTP status %d", errors.ErrHTTPStatusFailed, resp.StatusCode)
	}

	// Get content length
	contentLength := resp.ContentLength
	if contentLength < 0 {
		return 0, fmt.Errorf("%w: content length not available", errors.ErrDownloadFailed)
	}

	return contentLength, nil
}

// JoinURL joins a base URL and path segments
func JoinURL(baseURL string, paths ...string) (string, error) {
	// Parse the base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	// Join the paths
	p := filepath.Join(paths...)
	p = filepath.ToSlash(p) // Ensure forward slashes

	// If the base URL has a path, join with it
	if u.Path != "" && u.Path != "/" {
		// Ensure the base path doesn't end with a slash
		basePath := strings.TrimSuffix(u.Path, "/")
		p = filepath.ToSlash(filepath.Join(basePath, p))
	}

	// Update the path in the URL
	u.Path = p

	return u.String(), nil
}
