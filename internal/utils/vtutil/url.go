package vtutil

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/logger"
	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"

	vt "github.com/VirusTotal/vt-go"
)

// URLScanStatus represents the status of a URL scan
type URLScanStatus string

// URL scan status constants
const (
	URLScanStatusQueued     URLScanStatus = "queued"
	URLScanStatusInProgress URLScanStatus = "in_progress"
	URLScanStatusCompleted  URLScanStatus = "completed"
	URLScanStatusError      URLScanStatus = "error"
)

// URLScanResult represents the result of a URL scan
type URLScanResult struct {
	URL              string                  `json:"url"`
	ScanID           string                  `json:"scan_id"`
	Status           URLScanStatus           `json:"status"`
	Resource         string                  `json:"resource"`
	Permalink        string                  `json:"permalink"`
	PositiveCount    int                     `json:"positive_count"`
	TotalCount       int                     `json:"total_count"`
	ScanDate         time.Time               `json:"scan_date"`
	Categories       []string                `json:"categories"`
	Tags             []string                `json:"tags"`
	FinalURL         string                  `json:"final_url,omitempty"`
	Title            string                  `json:"title,omitempty"`
	EngineResults    map[string]EngineResult `json:"engine_results"`
	Error            string                  `json:"error,omitempty"`
	HttpStatus       int                     `json:"http_status,omitempty"`
	RedirectionChain []string                `json:"redirection_chain,omitempty"`
}

// URLInfo contains normalized information about a URL
type URLInfo struct {
	Original    string            `json:"original"`
	Normalized  string            `json:"normalized"`
	Hostname    string            `json:"hostname"`
	Path        string            `json:"path"`
	Scheme      string            `json:"scheme"`
	QueryString string            `json:"query_string,omitempty"`
	Fragment    string            `json:"fragment,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

// URLScanOptions represents options for URL scanning
type URLScanOptions struct {
	EnableCache       bool              // Whether to use caching
	SkipEngineDetail  bool              // Skip detailed engine results to reduce response size
	WaitForCompletion bool              // Wait for scan completion (may take time)
	PollingInterval   time.Duration     // Interval for polling scan results
	PollingTimeout    time.Duration     // Maximum time to wait for scan completion
	CustomTags        []string          // Custom tags for the scan
	AdditionalParams  map[string]string // Additional API parameters
}

// DefaultURLScanOptions returns default options for URL scanning
func DefaultURLScanOptions() URLScanOptions {
	return URLScanOptions{
		EnableCache:       true,
		SkipEngineDetail:  false,
		WaitForCompletion: false,
		PollingInterval:   time.Second * 15,
		PollingTimeout:    time.Minute * 5,
		AdditionalParams:  make(map[string]string),
	}
}

// normalizeURL normalizes a URL for consistent lookup
func normalizeURL(inputURL string) (string, error) {
	// Add scheme if missing
	if !strings.HasPrefix(inputURL, "http://") && !strings.HasPrefix(inputURL, "https://") {
		inputURL = "http://" + inputURL
	}

	// Parse the URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	// Normalize hostname (remove www. prefix if present)
	hostname := parsedURL.Hostname()
	if strings.HasPrefix(hostname, "www.") {
		hostname = hostname[4:]
		parsedURL.Host = hostname
		if parsedURL.Port() != "" {
			parsedURL.Host = hostname + ":" + parsedURL.Port()
		}
	}

	// Make sure path ends with / if it's just the domain
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	}

	// Return normalized URL
	normalizedURL := parsedURL.String()
	return normalizedURL, nil
}

// getURLInfo extracts detailed information from a URL
func getURLInfo(inputURL string) (*URLInfo, error) {
	// Add scheme if missing
	if !strings.HasPrefix(inputURL, "http://") && !strings.HasPrefix(inputURL, "https://") {
		inputURL = "http://" + inputURL
	}

	// Parse the URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrInvalidURL, err.Error())
	}

	// Create URL info
	urlInfo := &URLInfo{
		Original:    inputURL,
		Normalized:  parsedURL.String(),
		Hostname:    parsedURL.Hostname(),
		Path:        parsedURL.Path,
		Scheme:      parsedURL.Scheme,
		QueryString: parsedURL.RawQuery,
		Fragment:    parsedURL.Fragment,
		Parameters:  make(map[string]string),
	}

	// Parse query parameters
	if parsedURL.RawQuery != "" {
		query, err := url.ParseQuery(parsedURL.RawQuery)
		if err == nil {
			for key, values := range query {
				if len(values) > 0 {
					urlInfo.Parameters[key] = values[0]
				}
			}
		}
	}

	return urlInfo, nil
}

// encodeURLForVT encodes a URL for VirusTotal API requests
func encodeURLForVT(inputURL string) string {
	// Normalize first
	normalizedURL, err := normalizeURL(inputURL)
	if err != nil {
		// If normalization fails, use the original
		normalizedURL = inputURL
	}

	// Create ID based on base64 encoding
	return base64.URLEncoding.EncodeToString([]byte(normalizedURL))
}

// ScanURL submits a URL for scanning by VirusTotal
func ScanURL(targetURL string, options ...func(*URLScanOptions)) (*URLScanResult, error) {
	// Create options with defaults and apply provided options
	opts := DefaultURLScanOptions()
	for _, option := range options {
		option(&opts)
	}

	// Get client
	client, err := GetClient()
	if err != nil {
		return nil, err
	}

	// Normalize URL
	normalizedURL, err := normalizeURL(targetURL)
	if err != nil {
		return nil, err
	}

	// Check cache if enabled
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("url_scan:%s", normalizedURL)
		if cachedResult, found := client.getCachedResult(cacheKey); found {
			logger.LogInfo("Retrieved URL scan result from cache", map[string]interface{}{
				"url": normalizedURL,
			})
			return cachedResult.(*URLScanResult), nil
		}
	}

	// Initialize scan result
	result := &URLScanResult{
		URL:           normalizedURL,
		Status:        URLScanStatusQueued,
		Resource:      normalizedURL,
		EngineResults: make(map[string]EngineResult),
	}

	// Try to get report first (URL might have been previously scanned)
	report, err := LookupURL(normalizedURL)
	if err == nil && report != nil && report.Status == URLScanStatusCompleted {
		// URL already analyzed recently
		logger.LogInfo("URL already analyzed by VirusTotal", map[string]interface{}{
			"url": normalizedURL,
		})

		// If we've found a report, cache and return it
		if opts.EnableCache {
			cacheKey := fmt.Sprintf("url_scan:%s", normalizedURL)
			client.cacheResult(cacheKey, report)
		}

		return report, nil
	}

	// If URL not found or not recently scanned, submit it for scanning
	logger.LogInfo("Submitting URL for scanning", map[string]interface{}{
		"url": normalizedURL,
	})

	// Create a new URL scanner
	scanner := client.vtClient.NewURLScanner()

	// Submit the URL
	var scanObj *vt.Object
	var scanErr error

	// Execute the submission with retries
	submitErr := client.executeWithRetry(fmt.Sprintf("url_submit:%s", normalizedURL), func() error {
		scanObj, scanErr = scanner.Scan(normalizedURL)
		return scanErr
	})

	// Handle submission errors
	if submitErr != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrNetworkError, submitErr.Error())
	}

	// Extract scan ID
	analysisID, err := scanObj.GetString("id")
	if err != nil {
		return nil, fmt.Errorf("failed to get scan ID: %w", err)
	}

	// Update result with scan ID
	result.ScanID = analysisID
	result.Status = URLScanStatusInProgress

	// Get permalink
	urlID := encodeURLForVT(normalizedURL)
	result.Permalink = fmt.Sprintf("https://www.virustotal.com/gui/url/%s/detection", urlID)

	logger.LogInfo("URL submitted successfully", map[string]interface{}{
		"url":     normalizedURL,
		"scan_id": analysisID,
	})

	// Wait for completion if requested
	if opts.WaitForCompletion {
		pollResult, err := pollURLScanCompletion(client, analysisID, normalizedURL, opts.PollingInterval, opts.PollingTimeout)
		if err != nil {
			return nil, err
		}
		result = pollResult
	}

	// Cache the result if enabled
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("url_scan:%s", normalizedURL)
		client.cacheResult(cacheKey, result)
	}

	return result, nil
}

// LookupURL gets the latest analysis of a URL
func LookupURL(targetURL string) (*URLScanResult, error) {
	// Get client
	client, err := GetClient()
	if err != nil {
		return nil, err
	}

	// Normalize URL
	normalizedURL, err := normalizeURL(targetURL)
	if err != nil {
		return nil, err
	}

	// Check cache
	cacheKey := fmt.Sprintf("url_scan:%s", normalizedURL)
	if cachedResult, found := client.getCachedResult(cacheKey); found {
		logger.LogInfo("Retrieved URL lookup from cache", map[string]interface{}{
			"url": normalizedURL,
		})
		return cachedResult.(*URLScanResult), nil
	}

	// Initialize the result
	result := &URLScanResult{
		URL:           normalizedURL,
		Status:        URLScanStatusCompleted,
		Resource:      normalizedURL,
		EngineResults: make(map[string]EngineResult),
	}

	// Encode the URL for VirusTotal
	urlID := encodeURLForVT(normalizedURL)

	// Get URL report from VirusTotal
	var urlObj *vt.Object
	lookupErr := client.executeWithRetry(fmt.Sprintf("url_lookup:%s", normalizedURL), func() error {
		var err error
		urlObj, err = client.vtClient.GetObject(vt.URL("urls/%s", urlID))
		return err
	})

	// Handle lookup errors
	if lookupErr != nil {
		// Check if this is a "not found" error
		if strings.Contains(lookupErr.Error(), "not found") {
			logger.LogInfo("URL not found in VirusTotal database", map[string]interface{}{
				"url": normalizedURL,
			})
			return nil, fmt.Errorf("%w: URL not found in VirusTotal database", errors.ErrFileNotFound)
		}
		return nil, fmt.Errorf("%w: %s", errors.ErrNetworkError, lookupErr.Error())
	}

	// Parse the object
	return parseURLObject(urlObj, result)
}

// parseURLObject parses a VirusTotal URL object into our URLScanResult structure
func parseURLObject(obj *vt.Object, result *URLScanResult) (*URLScanResult, error) {
	// Get URL
	url, _ := obj.GetString("url")
	if url != "" {
		result.URL = url
	}

	// Get scan date
	scanDate, err := obj.GetTime("last_analysis_date")
	if err == nil {
		result.ScanDate = scanDate
	}

	// Get last HTTP response code
	httpCode, err := obj.GetInt64("last_http_response_code")
	if err == nil {
		result.HttpStatus = int(httpCode)
	}

	// Get title
	title, _ := obj.GetString("title")
	result.Title = title

	// Get final URL (after redirects)
	finalURL, _ := obj.GetString("final_url")
	result.FinalURL = finalURL

	// Get redirection chain
	redirects, err := obj.GetStringSlice("redirection_chain")
	if err == nil {
		result.RedirectionChain = redirects
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

	// Get categories
	categories, err := obj.Get("categories")
	if err == nil {
		if cats, ok := categories.(map[string]interface{}); ok {
			for _, category := range cats {
				if cat, ok := category.(string); ok {
					result.Categories = append(result.Categories, cat)
				}
			}
		}
	}

	// Get tags
	tags, err := obj.GetStringSlice("tags")
	if err == nil {
		result.Tags = tags
	}

	// Get ID for permalink
	urlID := obj.ID()
	result.Permalink = fmt.Sprintf("https://www.virustotal.com/gui/url/%s/detection", urlID)

	// Set status to completed
	result.Status = URLScanStatusCompleted

	return result, nil
}

// pollURLScanCompletion polls VirusTotal until the URL scan is completed or times out
func pollURLScanCompletion(client *Client, analysisID, targetURL string, pollingInterval, timeout time.Duration) (*URLScanResult, error) {
	startTime := time.Now()

	logger.LogInfo("Polling for URL scan completion", map[string]interface{}{
		"analysis_id": analysisID,
		"url":         targetURL,
		"timeout":     timeout.String(),
	})

	// Create a mutex for this URL
	urlMutex := fsutil.GetPathMutex(fmt.Sprintf("vturl:%s", targetURL))

	for {
		// Check if we've exceeded the timeout
		if time.Since(startTime) > timeout {
			return nil, fmt.Errorf("%w: scan polling timed out after %s", errors.ErrNetworkTimeout, timeout.String())
		}

		// Lock the URL mutex for this polling operation
		urlMutex.Lock()

		// Get analysis
		var analysisObj *vt.Object
		err := client.executeWithRetry(fmt.Sprintf("url_analysis_poll:%s", analysisID), func() error {
			var err error
			analysisObj, err = client.vtClient.GetObject(vt.URL("analyses/%s", analysisID))
			return err
		})

		if err != nil {
			urlMutex.Unlock()
			logger.LogWarn("Failed to get URL analysis status", map[string]interface{}{
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
			urlMutex.Unlock()
			// Continue polling if we can't get the status
			time.Sleep(pollingInterval)
			continue
		}

		// If completed, get the URL result
		if status == "completed" {
			urlMutex.Unlock()
			logger.LogInfo("URL scan completed", map[string]interface{}{
				"analysis_id": analysisID,
				"url":         targetURL,
			})

			// Lookup the URL
			return LookupURL(targetURL)
		} else if status == "failed" {
			urlMutex.Unlock()
			return nil, fmt.Errorf("%w: scan failed", errors.ErrScanFailed)
		}

		// Still in progress, continue polling
		urlMutex.Unlock()
		logger.LogInfo("URL scan in progress, continuing to poll", map[string]interface{}{
			"analysis_id": analysisID,
			"status":      status,
		})

		time.Sleep(pollingInterval)
	}
}

// WithURLCache enables or disables caching
func WithURLCache(enable bool) func(*URLScanOptions) {
	return func(o *URLScanOptions) {
		o.EnableCache = enable
	}
}

// WithURLEngineDetail enables or disables detailed engine results
func WithURLEngineDetail(includeDetail bool) func(*URLScanOptions) {
	return func(o *URLScanOptions) {
		o.SkipEngineDetail = !includeDetail
	}
}

// WithURLWaitForCompletion sets whether to wait for scan completion
func WithURLWaitForCompletion(wait bool) func(*URLScanOptions) {
	return func(o *URLScanOptions) {
		o.WaitForCompletion = wait
	}
}

// WithURLPollingSettings configures polling settings
func WithURLPollingSettings(interval, timeout time.Duration) func(*URLScanOptions) {
	return func(o *URLScanOptions) {
		if interval > 0 {
			o.PollingInterval = interval
		}
		if timeout > 0 {
			o.PollingTimeout = timeout
		}
	}
}

// WithURLCustomTags sets custom tags for the URL scan
func WithURLCustomTags(tags []string) func(*URLScanOptions) {
	return func(o *URLScanOptions) {
		o.CustomTags = tags
	}
}

// WithURLAdditionalParams sets additional API parameters
func WithURLAdditionalParams(params map[string]string) func(*URLScanOptions) {
	return func(o *URLScanOptions) {
		for k, v := range params {
			o.AdditionalParams[k] = v
		}
	}
}
