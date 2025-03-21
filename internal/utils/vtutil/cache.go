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

// CacheStorage defines the interface for cache storage backends
type CacheStorage interface {
	// Get retrieves a value from the cache
	Get(key string) ([]byte, bool, error)

	// Set stores a value in the cache
	Set(key string, value []byte, ttl time.Duration) error

	// Delete removes a value from the cache
	Delete(key string) error

	// Clear removes all values from the cache
	Clear() error
}

// MemoryCache implements an in-memory cache storage
type MemoryCache struct {
	data  map[string]*cacheEntry
	mutex sync.RWMutex
}

// cacheEntry represents a single cached item
type cacheEntry struct {
	Value      []byte
	Expiration time.Time
}

// FileCache implements a file-based cache storage
type FileCache struct {
	basePath string
	mutex    sync.RWMutex
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		data: make(map[string]*cacheEntry),
	}
}

// NewFileCache creates a new file-based cache
func NewFileCache(basePath string) (*FileCache, error) {
	// Create cache directory if it doesn't exist
	if err := fsutil.CreateDirIfNotExists(basePath); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &FileCache{
		basePath: basePath,
	}, nil
}

// Get retrieves a value from the memory cache
func (c *MemoryCache) Get(key string) ([]byte, bool, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false, nil
	}

	// Check if the entry has expired
	if time.Now().After(entry.Expiration) {
		// Clean up expired entry (defer to avoid deadlock)
		go func(key string) {
			c.Delete(key)
		}(key)
		return nil, false, nil
	}

	return entry.Value, true, nil
}

// Set stores a value in the memory cache
func (c *MemoryCache) Set(key string, value []byte, ttl time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data[key] = &cacheEntry{
		Value:      value,
		Expiration: time.Now().Add(ttl),
	}

	return nil
}

// Delete removes a value from the memory cache
func (c *MemoryCache) Delete(key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.data, key)
	return nil
}

// Clear removes all values from the memory cache
func (c *MemoryCache) Clear() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data = make(map[string]*cacheEntry)
	return nil
}

// generateCacheFilePath generates a filesystem-safe cache file path
func (c *FileCache) generateCacheFilePath(key string) string {
	// Replace potentially problematic characters
	safeKey := sanitizeKey(key)
	return filepath.Join(c.basePath, safeKey+".cache")
}

// sanitizeKey makes a cache key safe for use as a filename
func sanitizeKey(key string) string {
	// For now, we'll use a simple hex encoding to ensure safety
	return fmt.Sprintf("%x", []byte(key))
}

// Get retrieves a value from the file cache
func (c *FileCache) Get(key string) ([]byte, bool, error) {
	filePath := c.generateCacheFilePath(key)

	// Use fsutil for thread-safe file operations
	fileMutex := fsutil.GetPathMutex(filePath)
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// Check if file exists
	if !fsutil.FileExists(filePath) {
		return nil, false, nil
	}

	// Read file content
	fileData, err := fsutil.ReadFile(filePath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read cache file: %w", err)
	}

	// Unmarshal the file content
	var entry cacheEntry
	if err := json.Unmarshal(fileData, &entry); err != nil {
		// If we can't unmarshal, delete the corrupt file
		os.Remove(filePath)
		return nil, false, fmt.Errorf("corrupt cache file: %w", err)
	}

	// Check if the entry has expired
	if time.Now().After(entry.Expiration) {
		// Clean up expired entry
		os.Remove(filePath)
		return nil, false, nil
	}

	return entry.Value, true, nil
}

// Set stores a value in the file cache
func (c *FileCache) Set(key string, value []byte, ttl time.Duration) error {
	filePath := c.generateCacheFilePath(key)

	// Use fsutil for thread-safe file operations
	fileMutex := fsutil.GetPathMutex(filePath)
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// Create cache entry
	entry := cacheEntry{
		Value:      value,
		Expiration: time.Now().Add(ttl),
	}

	// Marshal the entry
	fileData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	// Write to file
	if err := fsutil.WriteFile(filePath, fileData, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// Delete removes a value from the file cache
func (c *FileCache) Delete(key string) error {
	filePath := c.generateCacheFilePath(key)

	// Use fsutil for thread-safe file operations
	fileMutex := fsutil.GetPathMutex(filePath)
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// Remove file if it exists
	if fsutil.FileExists(filePath) {
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to delete cache file: %w", err)
		}
	}

	return nil
}

// Clear removes all values from the file cache
func (c *FileCache) Clear() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Get all cache files
	files, err := filepath.Glob(filepath.Join(c.basePath, "*.cache"))
	if err != nil {
		return fmt.Errorf("failed to list cache files: %w", err)
	}

	// Remove each file
	for _, file := range files {
		fileMutex := fsutil.GetPathMutex(file)
		fileMutex.Lock()

		if err := os.Remove(file); err != nil {
			fileMutex.Unlock()
			logger.LogWarn(fmt.Sprintf("Failed to delete cache file %s", file), map[string]interface{}{
				"error": err.Error(),
			})
			continue
		}

		fileMutex.Unlock()
	}

	return nil
}

// CleanExpiredEntries removes expired entries from the cache
func (c *FileCache) CleanExpiredEntries() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Get all cache files
	files, err := filepath.Glob(filepath.Join(c.basePath, "*.cache"))
	if err != nil {
		return fmt.Errorf("failed to list cache files: %w", err)
	}

	// Check each file
	for _, file := range files {
		fileMutex := fsutil.GetPathMutex(file)
		fileMutex.Lock()

		// Read file content
		fileData, err := fsutil.ReadFile(file)
		if err != nil {
			fileMutex.Unlock()
			logger.LogWarn(fmt.Sprintf("Failed to read cache file %s", file), map[string]interface{}{
				"error": err.Error(),
			})
			continue
		}

		// Unmarshal the file content
		var entry cacheEntry
		if err := json.Unmarshal(fileData, &entry); err != nil {
			// If we can't unmarshal, delete the corrupt file
			os.Remove(file)
			fileMutex.Unlock()
			continue
		}

		// Check if the entry has expired
		if time.Now().After(entry.Expiration) {
			os.Remove(file)
		}

		fileMutex.Unlock()
	}

	return nil
}

// Cache represents the caching system for VirusTotal API results
type Cache struct {
	storage     CacheStorage
	defaultTTL  time.Duration
	enabled     bool
	initialized bool
}

// GlobalCache is the global instance of the cache
var (
	GlobalCache *Cache
	cacheOnce   sync.Once
)

// InitCache initializes the cache with the specified storage
func InitCache(storage CacheStorage, defaultTTL time.Duration) {
	cacheOnce.Do(func() {
		GlobalCache = &Cache{
			storage:     storage,
			defaultTTL:  defaultTTL,
			enabled:     true,
			initialized: true,
		}

		logger.LogInfo("VirusTotal cache initialized", map[string]interface{}{
			"type": fmt.Sprintf("%T", storage),
			"ttl":  defaultTTL.String(),
		})
	})
}

// GetCache returns the global cache instance
func GetCache() (*Cache, error) {
	if GlobalCache == nil || !GlobalCache.initialized {
		return nil, fmt.Errorf("%w: cache not initialized", errors.ErrInvalidArgument)
	}
	return GlobalCache, nil
}

// Get retrieves an item from the cache
func (c *Cache) Get(key string, target interface{}) (bool, error) {
	if !c.enabled {
		return false, nil
	}

	data, found, err := c.storage.Get(key)
	if err != nil {
		return false, err
	}

	if !found {
		return false, nil
	}

	// Unmarshal the data into the target
	if err := json.Unmarshal(data, target); err != nil {
		return false, fmt.Errorf("failed to unmarshal cached data: %w", err)
	}

	return true, nil
}

// Set stores an item in the cache
func (c *Cache) Set(key string, value interface{}) error {
	return c.SetWithTTL(key, value, c.defaultTTL)
}

// SetWithTTL stores an item in the cache with a custom TTL
func (c *Cache) SetWithTTL(key string, value interface{}, ttl time.Duration) error {
	if !c.enabled {
		return nil
	}

	// Marshal the value
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}

	return c.storage.Set(key, data, ttl)
}

// Delete removes an item from the cache
func (c *Cache) Delete(key string) error {
	if !c.enabled {
		return nil
	}

	return c.storage.Delete(key)
}

// Clear removes all items from the cache
func (c *Cache) Clear() error {
	if !c.enabled {
		return nil
	}

	return c.storage.Clear()
}

// Enable enables the cache
func (c *Cache) Enable() {
	c.enabled = true
	logger.LogInfo("VirusTotal cache enabled", nil)
}

// Disable disables the cache
func (c *Cache) Disable() {
	c.enabled = false
	logger.LogInfo("VirusTotal cache disabled", nil)
}

// IsEnabled returns whether the cache is enabled
func (c *Cache) IsEnabled() bool {
	return c.enabled
}

// InitMemoryCache initializes a memory-based cache
func InitMemoryCache(ttl time.Duration) error {
	if GlobalCache != nil && GlobalCache.initialized {
		return fmt.Errorf("%w: cache already initialized", errors.ErrInvalidArgument)
	}

	InitCache(NewMemoryCache(), ttl)
	return nil
}

// InitFileCache initializes a file-based cache
func InitFileCache(cachePath string, ttl time.Duration) error {
	if GlobalCache != nil && GlobalCache.initialized {
		return fmt.Errorf("%w: cache already initialized", errors.ErrInvalidArgument)
	}

	fileCache, err := NewFileCache(cachePath)
	if err != nil {
		return err
	}

	// Clean expired entries on startup
	if err := fileCache.CleanExpiredEntries(); err != nil {
		logger.LogWarn("Failed to clean expired cache entries", map[string]interface{}{
			"error": err.Error(),
		})
	}

	InitCache(fileCache, ttl)
	return nil
}
