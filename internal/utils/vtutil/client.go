// Package vtutil provides utilities for interacting with the VirusTotal API
// to scan files, URLs, domains, and IP addresses for security threats.
package vtutil

import (
	"fmt"
	"sync"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/logger"
	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"

	vt "github.com/VirusTotal/vt-go"
)

// Default settings
const (
	DefaultRateLimitPerMinute = 4    // Default API request limit per minute (free tier)
	DefaultRetryCount         = 3    // Default number of retries for failed requests
	DefaultRetryDelay         = 5    // Default delay between retries in seconds
	DefaultResultCacheTTL     = 3600 // Default cache TTL in seconds (1 hour)
)

// ClientConfig holds configuration for the VirusTotal client
type ClientConfig struct {
	APIKey           string        // VirusTotal API key
	RateLimitPerMin  int           // Rate limit for API requests per minute
	RetryCount       int           // Number of retries for failed requests
	RetryDelay       time.Duration // Delay between retries
	ResultCacheTTL   int           // Time-to-live for cached results in seconds
	CustomHost       string        // Optional custom VirusTotal API host
	DisableRateLimit bool          // Option to disable rate limiting (use with caution)
}

// Client is a thread-safe wrapper for the VirusTotal client
type Client struct {
	vtClient     *vt.Client         // Underlying VT client
	config       ClientConfig       // Client configuration
	lastRequest  time.Time          // Timestamp of the last API request
	requestCount int                // Number of requests made in the current minute
	mutex        sync.Mutex         // Mutex for thread safety
	cacheMutex   sync.RWMutex       // Mutex for cache operations
	cache        map[string]*Result // Simple in-memory cache
}

// Result represents a cached scan result
type Result struct {
	Data      interface{} // The result data
	Timestamp time.Time   // When the result was obtained
}

// Global client instance
var (
	globalClient *Client
	clientMutex  sync.Mutex
)

// DefaultClientConfig returns a default configuration for the client
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		RateLimitPerMin: DefaultRateLimitPerMinute,
		RetryCount:      DefaultRetryCount,
		RetryDelay:      time.Duration(DefaultRetryDelay) * time.Second,
		ResultCacheTTL:  DefaultResultCacheTTL,
	}
}

// Initialize creates or returns the global client instance
func Initialize(apiKey string, options ...func(*ClientConfig)) (*Client, error) {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	if globalClient != nil {
		return globalClient, nil
	}

	if apiKey == "" {
		logger.LogError("VirusTotal API key is required", fmt.Errorf("missing API key"), nil)
		return nil, fmt.Errorf("%w: VirusTotal API key is required", errors.ErrInvalidArgument)
	}

	// Create default config
	config := DefaultClientConfig()
	config.APIKey = apiKey

	// Apply options
	for _, option := range options {
		option(&config)
	}

	// Initialize the VirusTotal client
	vtClient := vt.NewClient(apiKey)

	// Set custom host if provided
	if config.CustomHost != "" {
		vt.SetHost(config.CustomHost)
	}

	globalClient = &Client{
		vtClient:    vtClient,
		config:      config,
		lastRequest: time.Now().Add(-time.Minute), // Initialize to allow immediate requests
		cache:       make(map[string]*Result),
	}

	logger.LogInfo("VirusTotal client initialized", map[string]interface{}{
		"rateLimit": config.RateLimitPerMin,
		"retries":   config.RetryCount,
	})

	return globalClient, nil
}

// GetClient returns the initialized global client instance or an error if not initialized
func GetClient() (*Client, error) {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	if globalClient == nil {
		logger.LogError("VirusTotal client not initialized", nil, nil)
		return nil, fmt.Errorf("%w: VirusTotal client not initialized", errors.ErrInvalidArgument)
	}

	return globalClient, nil
}

// WithRateLimit sets the rate limit for API requests
func WithRateLimit(requestsPerMinute int) func(*ClientConfig) {
	return func(c *ClientConfig) {
		if requestsPerMinute > 0 {
			c.RateLimitPerMin = requestsPerMinute
		}
	}
}

// WithRetrySettings configures retry behavior
func WithRetrySettings(count int, delay time.Duration) func(*ClientConfig) {
	return func(c *ClientConfig) {
		if count >= 0 {
			c.RetryCount = count
		}
		if delay > 0 {
			c.RetryDelay = delay
		}
	}
}

// WithCacheTTL sets the cache time-to-live
func WithCacheTTL(ttlSeconds int) func(*ClientConfig) {
	return func(c *ClientConfig) {
		if ttlSeconds >= 0 {
			c.ResultCacheTTL = ttlSeconds
		}
	}
}

// WithCustomHost sets a custom API host
func WithCustomHost(host string) func(*ClientConfig) {
	return func(c *ClientConfig) {
		c.CustomHost = host
	}
}

// WithDisableRateLimit disables rate limiting
func WithDisableRateLimit(disable bool) func(*ClientConfig) {
	return func(c *ClientConfig) {
		c.DisableRateLimit = disable
	}
}

// getRawClient returns the underlying vt.Client for direct operations
// This is primarily for internal use when you need direct access
func (c *Client) getRawClient() *vt.Client {
	return c.vtClient
}

// checkRateLimit ensures we don't exceed the API rate limit
// Returns the time to wait before making the next request
func (c *Client) checkRateLimit() time.Duration {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Skip rate limiting if disabled
	if c.config.DisableRateLimit {
		return 0
	}

	now := time.Now()
	elapsed := now.Sub(c.lastRequest)

	// Reset counter after a minute
	if elapsed >= time.Minute {
		c.requestCount = 0
		c.lastRequest = now
		return 0
	}

	// Check if we've hit the rate limit
	if c.requestCount >= c.config.RateLimitPerMin {
		// Calculate time to wait until next minute starts
		waitTime := time.Minute - elapsed
		logger.LogInfo("Rate limit reached, throttling requests", map[string]interface{}{
			"waitTime": waitTime.String(),
		})
		return waitTime
	}

	// Update counters and allow request
	c.requestCount++
	c.lastRequest = now
	return 0
}

// executeWithRetry executes a function with retry logic
func (c *Client) executeWithRetry(operation string, fn func() error) error {
	// Thread-safe paths for operation
	operationMutex := fsutil.GetPathMutex(operation)
	operationMutex.Lock()
	defer operationMutex.Unlock()

	var lastErr error

	for attempt := 0; attempt <= c.config.RetryCount; attempt++ {
		// Check rate limit and wait if necessary
		if waitTime := c.checkRateLimit(); waitTime > 0 {
			logger.LogInfo(fmt.Sprintf("Waiting %v before next VirusTotal API request", waitTime), nil)
			time.Sleep(waitTime)
		}

		// Execute the function
		err := fn()
		if err == nil {
			return nil // Success
		}

		lastErr = err
		logger.LogWarn(fmt.Sprintf("VirusTotal API request failed (attempt %d/%d): %s",
			attempt+1, c.config.RetryCount+1, operation), map[string]interface{}{
			"error": err.Error(),
		})

		// Don't sleep after the last attempt
		if attempt < c.config.RetryCount {
			time.Sleep(c.config.RetryDelay)
		}
	}

	// All retries failed
	logger.LogError(fmt.Sprintf("VirusTotal API request failed after %d attempts: %s",
		c.config.RetryCount+1, operation), lastErr, nil)
	return lastErr
}

// getCachedResult retrieves a cached result if available and not expired
func (c *Client) getCachedResult(cacheKey string) (interface{}, bool) {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	cachedResult, exists := c.cache[cacheKey]
	if !exists {
		return nil, false
	}

	// Check if result has expired
	if time.Since(cachedResult.Timestamp).Seconds() > float64(c.config.ResultCacheTTL) {
		return nil, false
	}

	return cachedResult.Data, true
}

// cacheResult stores a result in the cache
func (c *Client) cacheResult(cacheKey string, data interface{}) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	c.cache[cacheKey] = &Result{
		Data:      data,
		Timestamp: time.Now(),
	}
}

// clearCache clears all cached results
func (c *Client) clearCache() {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	c.cache = make(map[string]*Result)
}

// invalidateCache removes a specific entry from the cache
func (c *Client) invalidateCache(cacheKey string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	delete(c.cache, cacheKey)
}
