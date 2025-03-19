package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-app-composer/internal/common/fsutil"
	"github.com/deploymenttheory/go-app-composer/internal/common/osutil"
	"github.com/spf13/viper"
)

const (
	// AppName is the application name used for config files and directories
	AppName = "go-app-composer"

	// EnvPrefix is the prefix for environment variables
	EnvPrefix = "APP_COMPOSER"
)

// AppConfig holds the application configuration
type AppConfig struct {
	// Core settings
	Debug     bool   `mapstructure:"debug"`
	LogFormat string `mapstructure:"log_format"`
	LogFile   string `mapstructure:"log_file"`

	// MDM settings
	MDM struct {
		Provider string `mapstructure:"provider"` // jamf, intune, mosyle, etc.

		// Jamf settings
		Jamf struct {
			URL      string `mapstructure:"url"`
			Username string `mapstructure:"username"`
			Password string `mapstructure:"password"`
		} `mapstructure:"jamf"`

		// Intune settings
		Intune struct {
			TenantID     string `mapstructure:"tenant_id"`
			ClientID     string `mapstructure:"client_id"`
			ClientSecret string `mapstructure:"client_secret"`
		} `mapstructure:"intune"`

		// Mosyle settings
		Mosyle struct {
			APIKey string `mapstructure:"api_key"`
			Domain string `mapstructure:"domain"`
		} `mapstructure:"mosyle"`
	} `mapstructure:"mdm"`

	// Storage settings
	Storage struct {
		Provider string `mapstructure:"provider"` // s3, gcp, etc.

		// AWS S3 settings
		S3 struct {
			Bucket     string `mapstructure:"bucket"`
			Region     string `mapstructure:"region"`
			AccessKey  string `mapstructure:"access_key"`
			SecretKey  string `mapstructure:"secret_key"`
			Endpoint   string `mapstructure:"endpoint"`    // For custom S3-compatible storage
			DisableSSL bool   `mapstructure:"disable_ssl"` // For development/testing
		} `mapstructure:"s3"`

		// GCP settings
		GCP struct {
			Bucket          string `mapstructure:"bucket"`
			CredentialsFile string `mapstructure:"credentials_file"`
			ProjectID       string `mapstructure:"project_id"`
		} `mapstructure:"gcp"`
	} `mapstructure:"storage"`

	// Packaging settings
	Packaging struct {
		TempDir        string `mapstructure:"temp_dir"`
		CacheDir       string `mapstructure:"cache_dir"`
		SigningID      string `mapstructure:"signing_id"`      // For code signing
		NotarizationID string `mapstructure:"notarization_id"` // For macOS notarization
	} `mapstructure:"packaging"`
}

// Global variables
var (
	// Global configuration instance
	Instance AppConfig

	// Status indicators
	ConfigLoaded bool
	ConfigFile   string

	// Viper instance
	v *viper.Viper

	// Ensure thread safety
	initOnce sync.Once
)

// Initialize sets up the configuration system
func Initialize(cfgFile string) error {
	var err error

	initOnce.Do(func() {
		// Create a new viper instance
		v = viper.New()

		// Set default values
		setDefaults(v)

		// Load configuration from file if specified
		if cfgFile != "" {
			v.SetConfigFile(cfgFile)
		} else {
			// Set config name and type
			v.SetConfigName(AppName)
			v.SetConfigType("yaml")

			// Add default search paths
			addSearchPaths(v)
		}

		// Set up environment variables
		v.SetEnvPrefix(EnvPrefix)
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
		v.AutomaticEnv()

		// Read configuration file
		if readErr := v.ReadInConfig(); readErr != nil {
			if _, ok := readErr.(viper.ConfigFileNotFoundError); !ok {
				// Only capture error if the config file was found but couldn't be read
				err = fmt.Errorf("error reading config file: %w", readErr)
			}
			// Config file not found, using defaults and environment variables
			ConfigLoaded = false
			ConfigFile = ""
		} else {
			ConfigLoaded = true
			ConfigFile = v.ConfigFileUsed()
		}

		// Unmarshal config into struct
		if unmarshalErr := v.Unmarshal(&Instance); unmarshalErr != nil {
			err = fmt.Errorf("error parsing config: %w", unmarshalErr)
			return
		}

		// Ensure required directories exist
		ensureDirectories()
	})

	return err
}

// setDefaults sets default values for configuration
func setDefaults(v *viper.Viper) {
	// Core settings
	v.SetDefault("debug", false)
	v.SetDefault("log_format", "human")

	// Set default log file based on OS
	logDir, err := fsutil.GetLogDir(AppName)
	if err == nil {
		v.SetDefault("log_file", filepath.Join(logDir, "tooling.log"))
	} else {
		v.SetDefault("log_file", "logs/tooling.log")
	}

	// MDM defaults
	v.SetDefault("mdm.provider", "")

	// Storage defaults
	v.SetDefault("storage.provider", "")

	// Packaging defaults
	tempDir, err := fsutil.GetTempDir(AppName)
	if err == nil {
		v.SetDefault("packaging.temp_dir", tempDir)
	} else {
		v.SetDefault("packaging.temp_dir", "temp")
	}

	cacheDir, err := fsutil.GetCacheDir(AppName)
	if err == nil {
		v.SetDefault("packaging.cache_dir", cacheDir)
	} else {
		v.SetDefault("packaging.cache_dir", "cache")
	}
}

// addSearchPaths adds config search paths
func addSearchPaths(v *viper.Viper) {
	// Always check current directory first
	v.AddConfigPath(".")

	// Check for development environment
	isDev := osutil.IsDevEnvironment()
	if isDev {
		// In dev mode, only use current directory and user home
		configDir, err := fsutil.GetConfigDir(AppName)
		if err == nil {
			v.AddConfigPath(configDir)
		}
		return
	}

	// Check for CI/Pipeline environment
	isCI := isRunningInPipeline()
	if isCI {
		// In CI/Pipeline, only use current directory and explicit CI directories
		v.AddConfigPath("/etc/" + AppName)
		return
	}

	// Standard operation - add user config directory
	configDir, err := fsutil.GetConfigDir(AppName)
	if err == nil {
		v.AddConfigPath(configDir)
	}

	// Add system-wide config directory
	systemConfigDir, err := fsutil.GetSystemConfigDir(AppName)
	if err == nil {
		v.AddConfigPath(systemConfigDir)
	}
}

// ensureDirectories creates necessary directories based on configuration
func ensureDirectories() {
	// Don't create directories in a pipeline environment unless explicitly requested
	if isRunningInPipeline() && os.Getenv("CREATE_DIRS") != "true" {
		return
	}

	// Create log directory
	if Instance.LogFile != "" {
		logDir := filepath.Dir(Instance.LogFile)
		_ = fsutil.CreateDirIfNotExists(logDir)
	}

	// Create temp directory
	if Instance.Packaging.TempDir != "" {
		_ = fsutil.CreateDirIfNotExists(Instance.Packaging.TempDir)
	}

	// Create cache directory
	if Instance.Packaging.CacheDir != "" {
		_ = fsutil.CreateDirIfNotExists(Instance.Packaging.CacheDir)
	}
}

// GetMDMConfig returns the configuration for the specified MDM provider
func GetMDMConfig() (interface{}, error) {
	switch Instance.MDM.Provider {
	case "jamf":
		return Instance.MDM.Jamf, nil
	case "intune":
		return Instance.MDM.Intune, nil
	case "mosyle":
		return Instance.MDM.Mosyle, nil
	case "":
		return nil, fmt.Errorf("no MDM provider specified")
	default:
		return nil, fmt.Errorf("unsupported MDM provider: %s", Instance.MDM.Provider)
	}
}

// GetStorageConfig returns the configuration for the specified storage provider
func GetStorageConfig() (interface{}, error) {
	switch Instance.Storage.Provider {
	case "s3":
		return Instance.Storage.S3, nil
	case "gcp":
		return Instance.Storage.GCP, nil
	case "":
		return nil, fmt.Errorf("no storage provider specified")
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", Instance.Storage.Provider)
	}
}

// SaveConfig saves the current configuration to a file
func SaveConfig(filePath string) error {
	// Create a new viper instance for saving
	saveV := viper.New()

	// Set the configuration to match our current Instance
	saveV.SetConfigFile(filePath)

	// Convert the struct to a map
	configMap := structToMap(Instance)

	// Set the values in viper
	for k, v := range configMap {
		saveV.Set(k, v)
	}

	// Ensure the directory exists
	configDir := filepath.Dir(filePath)
	if err := fsutil.CreateDirIfNotExists(configDir); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write the configuration to file
	return saveV.WriteConfig()
}

// structToMap converts a struct to a map using viper
func structToMap(config interface{}) map[string]interface{} {
	tempV := viper.New()
	tempV.SetConfigType("yaml")

	// Use a temporary key to store the struct
	tempV.Set("temp", config)

	// Extract the map
	if allSettings := tempV.AllSettings(); allSettings != nil {
		if tempMap, ok := allSettings["temp"].(map[string]interface{}); ok {
			return tempMap
		}
	}

	// Fallback to empty map
	return make(map[string]interface{})
}

// isRunningInPipeline returns true if running in a CI/CD pipeline environment
func isRunningInPipeline() bool {
	return os.Getenv("CI") == "true" ||
		os.Getenv("PIPELINE") == "true" ||
		os.Getenv("GITHUB_ACTIONS") == "true" ||
		os.Getenv("JENKINS_URL") != ""
}
