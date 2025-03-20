package cryptoutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/osutil"
)

// SignatureVerifier provides an interface for verifying digital signatures
type SignatureVerifier interface {
	// VerifyFile checks if a file's signature is valid
	VerifyFile(filePath, signaturePath string) (bool, error)

	// VerifyDetachedSignature verifies a detached signature for a file
	VerifyDetachedSignature(filePath, signaturePath string) (bool, error)
}

// MacOSSignatureVerifier verifies signatures using macOS codesign
type MacOSSignatureVerifier struct{}

// NewMacOSSignatureVerifier creates a new macOS signature verifier
func NewMacOSSignatureVerifier() *MacOSSignatureVerifier {
	return &MacOSSignatureVerifier{}
}

// VerifyFile verifies a file's signature using codesign
func (v *MacOSSignatureVerifier) VerifyFile(filePath, _ string) (bool, error) {
	if !osutil.IsMacOS() {
		return false, fmt.Errorf("%w: macOS signature verification only available on macOS", errors.ErrOSNotSupported)
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, fmt.Errorf("%w: %s", errors.ErrFileNotFound, filePath)
	}

	// Use codesign to verify
	cmd := exec.Command("codesign", "-v", filePath)
	err := cmd.Run()

	// codesign returns 0 if signature is valid, non-zero otherwise
	return err == nil, nil
}

// VerifyDetachedSignature verifies a detached signature (not applicable for codesign)
func (v *MacOSSignatureVerifier) VerifyDetachedSignature(filePath, signaturePath string) (bool, error) {
	return false, fmt.Errorf("%w: detached signatures not supported by macOS codesign", errors.ErrUnsupportedFile)
}

// WindowsSignatureVerifier verifies signatures using Windows signtool
type WindowsSignatureVerifier struct{}

// NewWindowsSignatureVerifier creates a new Windows signature verifier
func NewWindowsSignatureVerifier() *WindowsSignatureVerifier {
	return &WindowsSignatureVerifier{}
}

// VerifyFile verifies a file's signature using signtool
func (v *WindowsSignatureVerifier) VerifyFile(filePath, _ string) (bool, error) {
	if !osutil.IsWindows() {
		return false, fmt.Errorf("%w: Windows signature verification only available on Windows", errors.ErrOSNotSupported)
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, fmt.Errorf("%w: %s", errors.ErrFileNotFound, filePath)
	}

	// Use signtool to verify
	cmd := exec.Command("signtool", "verify", "/pa", filePath)
	err := cmd.Run()

	// signtool returns 0 if signature is valid, non-zero otherwise
	return err == nil, nil
}

// VerifyDetachedSignature verifies a detached signature (not applicable for signtool)
func (v *WindowsSignatureVerifier) VerifyDetachedSignature(filePath, signaturePath string) (bool, error) {
	return false, fmt.Errorf("%w: detached signatures not supported by Windows signtool", errors.ErrUnsupportedFile)
}

// GPGSignatureVerifier verifies signatures using GnuPG
type GPGSignatureVerifier struct{}

// NewGPGSignatureVerifier creates a new GPG signature verifier
func NewGPGSignatureVerifier() *GPGSignatureVerifier {
	return &GPGSignatureVerifier{}
}

// VerifyFile verifies a file's signature using gpg
func (v *GPGSignatureVerifier) VerifyFile(filePath, _ string) (bool, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, fmt.Errorf("%w: %s", errors.ErrFileNotFound, filePath)
	}

	// For GPG, we assume the signature is embedded if no signature path is provided
	cmd := exec.Command("gpg", "--verify", filePath)
	err := cmd.Run()

	// gpg returns 0 if signature is valid, non-zero otherwise
	return err == nil, nil
}

// VerifyDetachedSignature verifies a detached signature using gpg
func (v *GPGSignatureVerifier) VerifyDetachedSignature(filePath, signaturePath string) (bool, error) {
	// Check if files exist
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, fmt.Errorf("%w: %s", errors.ErrFileNotFound, filePath)
	}

	if _, err := os.Stat(signaturePath); os.IsNotExist(err) {
		return false, fmt.Errorf("%w: %s", errors.ErrFileNotFound, signaturePath)
	}

	// Verify detached signature
	cmd := exec.Command("gpg", "--verify", signaturePath, filePath)
	err := cmd.Run()

	// gpg returns 0 if signature is valid, non-zero otherwise
	return err == nil, nil
}

// GetSignatureVerifier returns an appropriate signature verifier based on the current OS
func GetSignatureVerifier() SignatureVerifier {
	if osutil.IsMacOS() {
		return NewMacOSSignatureVerifier()
	} else if osutil.IsWindows() {
		return NewWindowsSignatureVerifier()
	} else {
		// Default to GPG for Linux and other platforms
		return NewGPGSignatureVerifier()
	}
}

// VerifySignature is a convenience function that verifies a file's signature
// using the appropriate verifier for the current OS
func VerifySignature(filePath, signaturePath string) (bool, error) {
	verifier := GetSignatureVerifier()

	// If signaturePath is empty, verify the file itself
	if signaturePath == "" {
		return verifier.VerifyFile(filePath, "")
	}

	// Otherwise, verify the detached signature
	return verifier.VerifyDetachedSignature(filePath, signaturePath)
}

// IsSignatureFile checks if a file is likely a signature file based on its extension
func IsSignatureFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".sig" || ext == ".asc" || ext == ".sign" || ext == ".signature"
}

// FindSignatureFile attempts to find a signature file for the given file
func FindSignatureFile(filePath string) (string, error) {
	// Common signature extensions
	signatureExtensions := []string{".sig", ".asc", ".sign", ".signature"}

	// Base path without extension
	basePathWithoutExt := strings.TrimSuffix(filePath, filepath.Ext(filePath))

	// Try common signature filename patterns
	for _, ext := range signatureExtensions {
		// Pattern 1: file.ext.sig
		sigPath := filePath + ext
		if _, err := os.Stat(sigPath); err == nil {
			return sigPath, nil
		}

		// Pattern 2: file.sig
		sigPath = basePathWithoutExt + ext
		if _, err := os.Stat(sigPath); err == nil {
			return sigPath, nil
		}
	}

	return "", fmt.Errorf("%w: no signature file found for %s", errors.ErrFileNotFound, filePath)
}
