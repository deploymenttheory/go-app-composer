package download

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/common/errors"
	logger "github.com/deploymenttheory/go-app-composer/internal/common/zap_logger"
)

// DownloadFile downloads a file from a URL and saves it to a local path.
func DownloadFile(url, dest string, expectedChecksum string) error {
	logger.LogInfo(fmt.Sprintf("Downloading file: %s", url), nil)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		logger.LogError("Failed to initiate download", err, nil)
		return fmt.Errorf("%w: failed to start download", errors.ErrDownloadFailed)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.LogError(fmt.Sprintf("Download failed with HTTP status: %d", resp.StatusCode), nil, nil)
		return fmt.Errorf("%w: HTTP status %d", errors.ErrDownloadFailed, resp.StatusCode)
	}

	// Create the destination file
	out, err := os.Create(dest)
	if err != nil {
		logger.LogError("Failed to create destination file", err, nil)
		return fmt.Errorf("%w: failed to create file", errors.ErrFileWriteError)
	}
	defer out.Close()

	// Copy response body to file
	hasher := sha256.New()
	multiWriter := io.MultiWriter(out, hasher)
	_, err = io.Copy(multiWriter, resp.Body)
	if err != nil {
		logger.LogError("Failed to write downloaded file", err, nil)
		return fmt.Errorf("%w: failed to write file", errors.ErrFileWriteError)
	}

	// Verify checksum if provided
	if expectedChecksum != "" {
		actualChecksum := fmt.Sprintf("%x", hasher.Sum(nil))
		if actualChecksum != expectedChecksum {
			logger.LogError(fmt.Sprintf("Checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum), nil, nil)
			return fmt.Errorf("%w: checksum mismatch", errors.ErrChecksumFailed)
		}
	}

	logger.LogInfo("Download completed successfully", nil)
	return nil
}
