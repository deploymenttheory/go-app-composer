package vtutil

import (
	"time"
)

// ScanStatus represents the status of any kind of scan
type ScanStatus string

// Common scan status constants
const (
	ScanStatusQueued     ScanStatus = "queued"
	ScanStatusInProgress ScanStatus = "in_progress"
	ScanStatusCompleted  ScanStatus = "completed"
	ScanStatusError      ScanStatus = "error"
)

// ScanResult is an interface implemented by all scan result types
type ScanResult interface {
	// GetStatus returns the status of the scan
	GetStatus() ScanStatus

	// GetPermalink returns a permanent link to the analysis on VirusTotal
	GetPermalink() string

	// GetResource returns the resource identifier (hash, URL, domain, IP)
	GetResource() string

	// GetThreatLevel returns a standardized threat level assessment
	GetThreatLevel() ThreatLevel

	// GetScanDate returns the date of the analysis
	GetScanDate() time.Time

	// GetError returns any error that occurred during analysis
	GetError() string
}

// ThreatLevel represents a standardized threat severity
type ThreatLevel int

// Threat level constants
const (
	ThreatLevelClean    ThreatLevel = 0
	ThreatLevelLow      ThreatLevel = 1
	ThreatLevelMedium   ThreatLevel = 2
	ThreatLevelHigh     ThreatLevel = 3
	ThreatLevelCritical ThreatLevel = 4
	ThreatLevelUnknown  ThreatLevel = -1
)

// Implement ScanResult interface for FileScanResult
func (r *FileScanResult) GetStatus() ScanStatus {
	switch r.Status {
	case FileScanStatusQueued:
		return ScanStatusQueued
	case FileScanStatusInProgress:
		return ScanStatusInProgress
	case FileScanStatusCompleted:
		return ScanStatusCompleted
	case FileScanStatusError:
		return ScanStatusError
	default:
		return ScanStatusError
	}
}

func (r *FileScanResult) GetPermalink() string {
	return r.Permalink
}

func (r *FileScanResult) GetResource() string {
	return r.Resource
}

func (r *FileScanResult) GetThreatLevel() ThreatLevel {
	// Calculate threat level based on ratio of positive detections
	if r.TotalCount == 0 {
		return ThreatLevelUnknown
	}

	ratio := float64(r.PositiveCount) / float64(r.TotalCount)

	switch {
	case ratio == 0:
		return ThreatLevelClean
	case ratio < 0.05:
		return ThreatLevelLow
	case ratio < 0.15:
		return ThreatLevelMedium
	case ratio < 0.30:
		return ThreatLevelHigh
	default:
		return ThreatLevelCritical
	}
}

func (r *FileScanResult) GetScanDate() time.Time {
	return r.ScanDate
}

func (r *FileScanResult) GetError() string {
	return r.Error
}

// Implement ScanResult interface for URLScanResult
func (r *URLScanResult) GetStatus() ScanStatus {
	switch r.Status {
	case URLScanStatusQueued:
		return ScanStatusQueued
	case URLScanStatusInProgress:
		return ScanStatusInProgress
	case URLScanStatusCompleted:
		return ScanStatusCompleted
	case URLScanStatusError:
		return ScanStatusError
	default:
		return ScanStatusError
	}
}

func (r *URLScanResult) GetPermalink() string {
	return r.Permalink
}

func (r *URLScanResult) GetResource() string {
	return r.URL
}

func (r *URLScanResult) GetThreatLevel() ThreatLevel {
	// Calculate threat level based on ratio of positive detections
	if r.TotalCount == 0 {
		return ThreatLevelUnknown
	}

	ratio := float64(r.PositiveCount) / float64(r.TotalCount)

	switch {
	case ratio == 0:
		return ThreatLevelClean
	case ratio < 0.05:
		return ThreatLevelLow
	case ratio < 0.15:
		return ThreatLevelMedium
	case ratio < 0.30:
		return ThreatLevelHigh
	default:
		return ThreatLevelCritical
	}
}

func (r *URLScanResult) GetScanDate() time.Time {
	return r.ScanDate
}

func (r *URLScanResult) GetError() string {
	return r.Error
}

// Implement ScanResult interface for DomainResult
func (r *DomainResult) GetStatus() ScanStatus {
	switch r.Status {
	case DomainScanStatusCompleted:
		return ScanStatusCompleted
	case DomainScanStatusError:
		return ScanStatusError
	default:
		return ScanStatusError
	}
}

func (r *DomainResult) GetPermalink() string {
	return r.Permalink
}

func (r *DomainResult) GetResource() string {
	return r.Domain
}

func (r *DomainResult) GetThreatLevel() ThreatLevel {
	// Calculate threat level based on reputation
	switch r.ReputationLevel {
	case DomainReputationClean:
		return ThreatLevelClean
	case DomainReputationLow:
		return ThreatLevelLow
	case DomainReputationMedium:
		return ThreatLevelMedium
	case DomainReputationHigh:
		return ThreatLevelHigh
	case DomainReputationMalicious:
		return ThreatLevelCritical
	default:
		return ThreatLevelUnknown
	}
}

func (r *DomainResult) GetScanDate() time.Time {
	return r.LastAnalysisDate
}

func (r *DomainResult) GetError() string {
	return r.Error
}

// Implement ScanResult interface for IPResult
func (r *IPResult) GetStatus() ScanStatus {
	switch r.Status {
	case IPScanStatusCompleted:
		return ScanStatusCompleted
	case IPScanStatusError:
		return ScanStatusError
	default:
		return ScanStatusError
	}
}

func (r *IPResult) GetPermalink() string {
	return r.Permalink
}

func (r *IPResult) GetResource() string {
	return r.IP
}

func (r *IPResult) GetThreatLevel() ThreatLevel {
	// Calculate threat level based on reputation
	switch r.ReputationLevel {
	case IPReputationClean:
		return ThreatLevelClean
	case IPReputationLow:
		return ThreatLevelLow
	case IPReputationMedium:
		return ThreatLevelMedium
	case IPReputationHigh:
		return ThreatLevelHigh
	case IPReputationMalicious:
		return ThreatLevelCritical
	default:
		return ThreatLevelUnknown
	}
}

func (r *IPResult) GetScanDate() time.Time {
	return r.LastAnalysisDate
}

func (r *IPResult) GetError() string {
	return r.Error
}

// ThreatLevelToString converts a threat level to its string representation
func ThreatLevelToString(level ThreatLevel) string {
	switch level {
	case ThreatLevelClean:
		return "Clean"
	case ThreatLevelLow:
		return "Low"
	case ThreatLevelMedium:
		return "Medium"
	case ThreatLevelHigh:
		return "High"
	case ThreatLevelCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// ThreatLevelFromString converts a string to its threat level
func ThreatLevelFromString(level string) ThreatLevel {
	switch level {
	case "Clean":
		return ThreatLevelClean
	case "Low":
		return ThreatLevelLow
	case "Medium":
		return ThreatLevelMedium
	case "High":
		return ThreatLevelHigh
	case "Critical":
		return ThreatLevelCritical
	default:
		return ThreatLevelUnknown
	}
}

// ScanResultSummary provides a common structure for summarizing scan results
type ScanResultSummary struct {
	Resource    string      `json:"resource"`
	Type        string      `json:"type"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	ThreatName  string      `json:"threat_name"`
	ScanDate    time.Time   `json:"scan_date"`
	Permalink   string      `json:"permalink"`
}

// GetScanResultSummary returns a standardized summary from any scan result
func GetScanResultSummary(result ScanResult) ScanResultSummary {
	var resultType string
	var threatName string

	switch r := result.(type) {
	case *FileScanResult:
		resultType = "file"
		threatName = getMostCommonDetection(r.EngineResults)
	case *URLScanResult:
		resultType = "url"
		threatName = getMostCommonDetection(r.EngineResults)
	case *DomainResult:
		resultType = "domain"
		// Get most common category
		for _, category := range r.Categories {
			threatName = category
			break
		}
	case *IPResult:
		resultType = "ip"
		// Get most common category
		for _, category := range r.Categories {
			threatName = category
			break
		}
	}

	return ScanResultSummary{
		Resource:    result.GetResource(),
		Type:        resultType,
		ThreatLevel: result.GetThreatLevel(),
		ThreatName:  threatName,
		ScanDate:    result.GetScanDate(),
		Permalink:   result.GetPermalink(),
	}
}

// getMostCommonDetection finds the most common detection name from engine results
func getMostCommonDetection(results map[string]EngineResult) string {
	// Count occurrences of each result
	counts := make(map[string]int)
	for _, result := range results {
		if result.Result != "" && result.Category != "undetected" {
			counts[result.Result]++
		}
	}

	// Find the most common
	maxCount := 0
	mostCommon := ""

	for detection, count := range counts {
		if count > maxCount {
			maxCount = count
			mostCommon = detection
		}
	}

	return mostCommon
}
