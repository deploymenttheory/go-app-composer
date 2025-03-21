package vtutil

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/logger"
	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"
)

// ConfigMode determines how the package handles configuration
type ConfigMode string

const (
	// ConfigModeManual requires explicit configuration through code
	ConfigModeManual ConfigMode = "manual"

	// ConfigModeFile loads configuration from a file
	ConfigModeFile ConfigMode = "file"

	// ConfigModeEnv loads configuration from environment variables
	ConfigModeEnv ConfigMode = "env"
)

// CacheMode determines how cache is stored
type CacheMode string

const (
	// CacheModeNone disables caching
	CacheModeNone CacheMode = "none"

	// CacheModeMemory stores cache in memory
	CacheModeMemory CacheMode = "memory"

	// CacheModeFile stores cache in files
	CacheModeFile CacheMode = "file"
)

// Config contains all configuration for the vtutil package
type Config struct {
	// API configuration
	APIKey           string        `json:"api_key"`
	CustomHost       string        `json:"custom_host,omitempty"`
	RateLimitPerMin  int           `json:"rate_limit_per_min"`
	RetryCount       int           `json:"retry_count"`
	RetryDelay       time.Duration `json:"retry_delay"`
	DisableRateLimit bool          `json:"disable_rate_limit"`

	// Cache configuration
	CacheMode CacheMode     `json:"cache_mode"`
	CacheTTL  time.Duration `json:"cache_ttl"`
	CachePath string        `json:"cache_path,omitempty"`

	// File scan defaults
	FileDefaultWaitForCompletion bool          `json:"file_default_wait_for_completion"`
	FilePollingInterval          time.Duration `json:"file_polling_interval"`
	FilePollingTimeout           time.Duration `json:"file_polling_timeout"`

	// URL scan defaults
	URLDefaultWaitForCompletion bool          `json:"url_default_wait_for_completion"`
	URLPollingInterval          time.Duration `json:"url_polling_interval"`
	URLPollingTimeout           time.Duration `json:"url_polling_timeout"`

	// Domain scan defaults
	DomainDefaultIncludeSubdomains   bool `json:"domain_default_include_subdomains"`
	DomainDefaultIncludeResolutions  bool `json:"domain_default_include_resolutions"`
	DomainDefaultIncludeWhois        bool `json:"domain_default_include_whois"`
	DomainDefaultIncludeCertificates bool `json:"domain_default_include_certificates"`

	// IP scan defaults
	IPDefaultIncludeResolutions bool `json:"ip_default_include_resolutions"`
	IPDefaultIncludeWhois       bool `json:"ip_default_include_whois"`

	// Logging configuration
	LogSuccessfulScans bool `json:"log_successful_scans"`
	LogDetailLevel     int  `json:"log_detail_level"` // 0=minimal, 1=normal, 2=verbose
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		// API configuration
		RateLimitPerMin:  4,
		RetryCount:       3,
		RetryDelay:       5 * time.Second,
		DisableRateLimit: false,

		// Cache configuration
		CacheMode: CacheModeMemory,
		CacheTTL:  1 * time.Hour,
		CachePath: "vt-cache",

		// File scan defaults
		FileDefaultWaitForCompletion: false,
		FilePollingInterval:          15 * time.Second,
		FilePollingTimeout:           10 * time.Minute,

		// URL scan defaults
		URLDefaultWaitForCompletion: false,
		URLPollingInterval:          15 * time.Second,
		URLPollingTimeout:           5 * time.Minute,

		// Domain scan defaults
		DomainDefaultIncludeSubdomains:   true,
		DomainDefaultIncludeResolutions:  true,
		DomainDefaultIncludeWhois:        true,
		DomainDefaultIncludeCertificates: true,

		// IP scan defaults
		IPDefaultIncludeResolutions: true,
		IPDefaultIncludeWhois:       true,

		// Logging configuration
		LogSuccessfulScans: true,
		LogDetailLevel:     1,
	}
}

// Global configuration instance
var (
	globalConfig *Config
	configMutex  sync.RWMutex
	initialized  bool
)

// configure sets up the package using the provided configuration
func configure(config Config) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	// API key is required
	if config.APIKey == "" {
		return fmt.Errorf("%w: API key is required", errors.ErrInvalidArgument)
	}

	// Save the configuration
	globalConfig = &config
	initialized = true

	// Initialize cache
	err := initializeCache(config)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Initialize client with translated options
	_, err = Initialize(config.APIKey,
		WithRateLimit(config.RateLimitPerMin),
		WithRetrySettings(config.RetryCount, config.RetryDelay),
		WithCacheTTL(int(config.CacheTTL.Seconds())),
		func(c *ClientConfig) {
			if config.CustomHost != "" {
				c.CustomHost = config.CustomHost
			}
			c.DisableRateLimit = config.DisableRateLimit
		},
	)

	if err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}

	logger.LogInfo("VirusTotal utilities initialized", map[string]interface{}{
		"cacheMode": string(config.CacheMode),
		"rateLimit": config.RateLimitPerMin,
	})

	return nil
}

// initializeCache sets up the caching system
func initializeCache(config Config) error {
	switch config.CacheMode {
	case CacheModeNone:
		// No need to initialize cache
		return nil

	case CacheModeMemory:
		return InitMemoryCache(config.CacheTTL)

	case CacheModeFile:
		// Ensure cache path is set
		if config.CachePath == "" {
			config.CachePath = "vt-cache"
		}

		// Resolve relative path
		if !filepath.IsAbs(config.CachePath) {
			cwd, err := os.Getwd()
			if err == nil {
				config.CachePath = filepath.Join(cwd, config.CachePath)
			}
		}

		return InitFileCache(config.CachePath, config.CacheTTL)

	default:
		return fmt.Errorf("%w: unsupported cache mode: %s", errors.ErrInvalidArgument, config.CacheMode)
	}
}

// IsInitialized returns whether the package has been initialized
func IsInitialized() bool {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return initialized
}

// GetConfig returns the current configuration
func GetConfig() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()

	if globalConfig == nil {
		return nil
	}

	// Return a copy to prevent modification
	configCopy := *globalConfig
	return &configCopy
}

// Initialize sets up the vtutil package with the provided configuration
func Configure(config Config) error {
	if IsInitialized() {
		return fmt.Errorf("%w: vtutil package already initialized", errors.ErrInvalidArgument)
	}

	return configure(config)
}

// ConfigureFromFile loads configuration from a JSON file
func ConfigureFromFile(filePath string) error {
	if IsInitialized() {
		return fmt.Errorf("%w: vtutil package already initialized", errors.ErrInvalidArgument)
	}

	// Check if file exists
	if !fsutil.FileExists(filePath) {
		return fmt.Errorf("%w: configuration file not found: %s", errors.ErrFileNotFound, filePath)
	}

	// Read the file
	data, err := fsutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Parse the configuration
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse configuration file: %w", err)
	}

	// Configure the package
	return configure(config)
}

// ConfigureFromEnv loads configuration from environment variables
func ConfigureFromEnv() error {
	if IsInitialized() {
		return fmt.Errorf("%w: vtutil package already initialized", errors.ErrInvalidArgument)
	}

	// Create default configuration
	config := DefaultConfig()

	// Load API key (required)
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("%w: VT_API_KEY environment variable is required", errors.ErrInvalidArgument)
	}
	config.APIKey = apiKey

	// Load optional configuration
	if host := os.Getenv("VT_CUSTOM_HOST"); host != "" {
		config.CustomHost = host
	}

	// Configure the package
	return configure(config)
}

// SaveConfig saves the current configuration to a file
func SaveConfig(filePath string) error {
	configMutex.RLock()
	defer configMutex.RUnlock()

	if globalConfig == nil {
		return fmt.Errorf("%w: configuration not initialized", errors.ErrInvalidArgument)
	}

	// Marshal the configuration
	data, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Write the file
	if err := fsutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	return nil
}
