package osutil

import (
	"os"
	"runtime"
)

// OS type constants
const (
	Windows = "windows"
	MacOS   = "darwin"
	Linux   = "linux"
)

// GetOSType returns the current operating system type
func GetOSType() string {
	return runtime.GOOS
}

// IsWindows returns true if running on Windows
func IsWindows() bool {
	return GetOSType() == Windows
}

// IsMacOS returns true if running on macOS (Darwin)
func IsMacOS() bool {
	return GetOSType() == MacOS
}

// IsLinux returns true if running on Linux
func IsLinux() bool {
	return GetOSType() == Linux
}

// IsUnix returns true if running on a Unix-like system (macOS, Linux, BSD, etc.)
func IsUnix() bool {
	return IsMacOS() || IsLinux() || GetOSType() == "freebsd" ||
		GetOSType() == "openbsd" || GetOSType() == "netbsd"
}

// IsDevEnvironment checks if the application is running in a development environment
// based on environment variables
func IsDevEnvironment() bool {
	// Check for typical development environment indicators
	return os.Getenv("APP_COMPOSER_ENV") == "development" ||
		os.Getenv("APP_COMPOSER_DEV") == "true" ||
		os.Getenv("APP_COMPOSER_DEBUG") == "true" ||
		os.Getenv("DEV") == "true" ||
		os.Getenv("DEBUG") == "true"
}

// GetArchitecture returns the system architecture (amd64, arm64, etc.)
func GetArchitecture() string {
	return runtime.GOARCH
}

// GetNumCPU returns the number of logical CPUs on the system
func GetNumCPU() int {
	return runtime.NumCPU()
}

// IsContainerized attempts to detect if running in a container environment
func IsContainerized() bool {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check for Kubernetes
	if _, err := os.Stat("/var/run/secrets/kubernetes.io"); err == nil {
		return true
	}

	return false
}
