// fsutil/locations.go
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/deploymenttheory/go-app-composer/internal/utils/osutil"
)

// GetHomeDir returns the user's home directory
func GetHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine home directory: %w", err)
	}
	return home, nil
}

// GetConfigDir returns the appropriate configuration directory for the application
func GetConfigDir(appName string) (string, error) {
	// In development mode, use a local config directory
	if osutil.IsDevEnvironment() {
		return "config", nil
	}

	home, err := GetHomeDir()
	if err != nil {
		return "", err
	}

	// Determine OS-specific config directory
	switch runtime.GOOS {
	case "windows":
		// Windows: %APPDATA%\appName
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, appName), nil

	case "darwin":
		// macOS: ~/Library/Application Support/appName
		return filepath.Join(home, "Library", "Application Support", appName), nil

	default:
		// Linux/Unix: ~/.config/appName (XDG Base Directory specification)
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return filepath.Join(configHome, appName), nil
	}
}

// GetSystemConfigDir returns the system-wide configuration directory
func GetSystemConfigDir(appName string) (string, error) {
	// In development mode, use a local config directory
	if osutil.IsDevEnvironment() {
		return "config", nil
	}

	switch runtime.GOOS {
	case "windows":
		// Windows: C:\ProgramData\appName
		programData := os.Getenv("ProgramData")
		if programData == "" {
			// Fallback if environment variable is not available
			systemDrive := os.Getenv("SystemDrive")
			if systemDrive == "" {
				systemDrive = "C:"
			}
			programData = filepath.Join(systemDrive, "ProgramData")
		}
		return filepath.Join(programData, appName), nil

	case "darwin":
		// macOS: /Library/Application Support/appName
		return filepath.Join("/Library", "Application Support", appName), nil

	default:
		// Linux/Unix: /etc/appName
		etcPaths := []string{
			filepath.Join("/etc", appName),
			filepath.Join("/usr/local/etc", appName),
		}

		// Return the first path that exists or the default
		for _, path := range etcPaths {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}

		return filepath.Join("/etc", appName), nil
	}
}

// GetDataDir returns the appropriate data directory for the application
func GetDataDir(appName string) (string, error) {
	// In development mode, use a local data directory
	if osutil.IsDevEnvironment() {
		return "data", nil
	}

	home, err := GetHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "windows":
		// Windows: %LOCALAPPDATA%\appName\Data
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(localAppData, appName, "Data"), nil

	case "darwin":
		// macOS: ~/Library/Application Support/appName
		return filepath.Join(home, "Library", "Application Support", appName), nil

	default:
		// Linux/Unix: ~/.local/share/appName (XDG Base Directory specification)
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			dataHome = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(dataHome, appName), nil
	}
}

// GetSystemDataDir returns the system-wide data directory
func GetSystemDataDir(appName string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			systemDrive := os.Getenv("SystemDrive")
			if systemDrive == "" {
				systemDrive = "C:"
			}
			programData = filepath.Join(systemDrive, "ProgramData")
		}
		return filepath.Join(programData, appName, "Data"), nil

	case "darwin":
		return filepath.Join("/Library", "Application Support", appName), nil

	default:
		// Linux/Unix: /usr/share/appName
		dataDirs := []string{
			filepath.Join("/usr/local/share", appName),
			filepath.Join("/usr/share", appName),
		}

		// Return the first path that exists or the default
		for _, path := range dataDirs {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}

		return filepath.Join("/usr/share", appName), nil
	}
}

// GetCacheDir returns the appropriate cache directory for the application
func GetCacheDir(appName string) (string, error) {
	// In development mode, use a local cache directory
	if osutil.IsDevEnvironment() {
		return "cache", nil
	}

	home, err := GetHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "windows":
		// Windows: %LOCALAPPDATA%\appName\Cache
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(localAppData, appName, "Cache"), nil

	case "darwin":
		// macOS: ~/Library/Caches/appName
		return filepath.Join(home, "Library", "Caches", appName), nil

	default:
		// Linux/Unix: ~/.cache/appName (XDG Base Directory specification)
		cacheHome := os.Getenv("XDG_CACHE_HOME")
		if cacheHome == "" {
			cacheHome = filepath.Join(home, ".cache")
		}
		return filepath.Join(cacheHome, appName), nil
	}
}

// GetLogDir returns the appropriate log directory for the application
func GetLogDir(appName string) (string, error) {
	// In development mode, use a local logs directory
	if osutil.IsDevEnvironment() {
		return "logs", nil
	}

	home, err := GetHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "windows":
		// Windows: %LOCALAPPDATA%\appName\Logs
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(localAppData, appName, "Logs"), nil

	case "darwin":
		// macOS: ~/Library/Logs/appName
		return filepath.Join(home, "Library", "Logs", appName), nil

	default:
		// Linux/Unix: ~/.local/state/appName/logs or ~/.local/share/appName/logs
		// Check if XDG_STATE_HOME is available (newer standard)
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome != "" {
			return filepath.Join(stateHome, appName, "logs"), nil
		}

		// Fallback to data directory
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			dataHome = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(dataHome, appName, "logs"), nil
	}
}

// GetSystemLogDir returns the system-wide log directory
func GetSystemLogDir(appName string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			systemDrive := os.Getenv("SystemDrive")
			if systemDrive == "" {
				systemDrive = "C:"
			}
			programData = filepath.Join(systemDrive, "ProgramData")
		}
		return filepath.Join(programData, appName, "Logs"), nil

	case "darwin":
		return filepath.Join("/Library", "Logs", appName), nil

	default:
		// Linux/Unix: /var/log/appName
		return filepath.Join("/var", "log", appName), nil
	}
}

// GetTempDir returns a temporary directory for the application
func GetTempDir(appName string) (string, error) {
	tempDir := os.TempDir()
	return filepath.Join(tempDir, appName), nil
}

// GetExecutableDir returns the directory of the current executable
func GetExecutableDir() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return filepath.Dir(execPath), nil
}

// GetRuntimeDir returns a directory for runtime files (sockets, PIDs, etc.)
func GetRuntimeDir(appName string) (string, error) {
	// In development mode, use a local run directory
	if osutil.IsDevEnvironment() {
		return "run", nil
	}

	switch runtime.GOOS {
	case "windows":
		// Windows doesn't have a standard runtime dir, use temp
		tempDir := os.TempDir()
		return filepath.Join(tempDir, appName), nil

	case "darwin":
		// macOS doesn't have a standard runtime dir, use temp
		tempDir := os.TempDir()
		return filepath.Join(tempDir, appName), nil

	default:
		// Linux/Unix: Use XDG_RUNTIME_DIR if available
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir != "" {
			return filepath.Join(runtimeDir, appName), nil
		}

		// Fallback to /tmp
		return filepath.Join("/tmp", appName), nil
	}
}

// GetTempCompressionDir returns a temporary directory for compression/extraction operations
func GetTempCompressionDir() (string, error) {
	tempDir := os.TempDir()
	compressionDir := filepath.Join(tempDir, "app_composer_compression")

	// Use mutex to protect directory creation
	mu := GetPathMutex(compressionDir)
	mu.Lock()
	defer mu.Unlock()

	if err := os.MkdirAll(compressionDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp compression directory: %w", err)
	}
	return compressionDir, nil
}
