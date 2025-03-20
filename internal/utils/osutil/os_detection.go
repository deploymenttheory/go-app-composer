package osutil

import (
	"os"
	"runtime"
	"strings"
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

// IsRunningInWSL checks if the current Linux environment
// is specifically running under Windows WSL
func IsRunningInWSL() bool {
	return IsWSL() && IsLinux()
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

// IsWSL checks if the current environment is Windows Subsystem for Linux (WSL)
func IsWSL() bool {
	// WSL-specific checks
	if !IsLinux() {
		return false
	}

	// First, check the WSL-specific environment variable
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}

	// Check for WSL-specific files
	// WSL 1 and WSL 2 have different methods of identification
	if _, err := os.Stat("/proc/sys/fs/binfmt_misc/WSLInterop"); err == nil {
		return true
	}

	// Check for WSL version specific files
	// Read the release information
	releaseContent, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err == nil {
		releaseString := string(releaseContent)
		if strings.Contains(strings.ToLower(releaseString), "microsoft") {
			return true
		}
	}

	// Additional check by reading OS release file
	osReleaseContent, err := os.ReadFile("/etc/os-release")
	if err == nil {
		releaseString := string(osReleaseContent)
		return strings.Contains(strings.ToLower(releaseString), "microsoft") ||
			strings.Contains(strings.ToLower(releaseString), "wsl")
	}

	return false
}

// GetWSLVersion attempts to determine the specific WSL version
func GetWSLVersion() string {
	if !IsWSL() {
		return ""
	}

	// Check for WSL 2 specific characteristics
	if _, err := os.Stat("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		return "WSL2"
	}

	// Default fallback to WSL 1 if specific WSL 2 checks fail
	return "WSL1"
}
