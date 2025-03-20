package fsutil

import (
	"path/filepath"
	"sort"
	"sync"
)

// Path mutex registry to protect operations on the same paths
var (
	pathMutexes sync.Map // Maps paths to mutexes
)

// GetPathMutex returns a mutex for the given path
func GetPathMutex(path string) *sync.Mutex {
	// Normalize the path to prevent different path representations causing issues
	normalizedPath := filepath.Clean(path)

	actual, _ := pathMutexes.LoadOrStore(normalizedPath, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// acquireMutexes acquires multiple mutexes in a consistent order to prevent deadlocks
func acquireMutexes(paths ...string) func() {
	// Sort paths to ensure consistent locking order (prevents deadlocks)
	sortedPaths := make([]string, len(paths))
	copy(sortedPaths, paths)
	sort.Strings(sortedPaths)

	// Deduplicate paths
	var uniquePaths []string
	for i, path := range sortedPaths {
		if i == 0 || path != sortedPaths[i-1] {
			uniquePaths = append(uniquePaths, path)
		}
	}

	// Acquire all mutexes
	var mutexes []*sync.Mutex
	for _, path := range uniquePaths {
		mu := GetPathMutex(path)
		mu.Lock()
		mutexes = append(mutexes, mu)
	}

	// Return a function that releases all mutexes in reverse order
	return func() {
		for i := len(mutexes) - 1; i >= 0; i-- {
			mutexes[i].Unlock()
		}
	}
}
