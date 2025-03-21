package vtutil

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/deploymenttheory/go-app-composer/internal/logger"
	"github.com/deploymenttheory/go-app-composer/internal/utils/errors"
	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"

	vt "github.com/VirusTotal/vt-go"
)

// IPScanStatus represents the status of an IP scan
type IPScanStatus string

// IP scan status constants
const (
	IPScanStatusCompleted IPScanStatus = "completed"
	IPScanStatusError     IPScanStatus = "error"
)

// IPReputationLevel represents an IP's reputation level
type IPReputationLevel string

// IP reputation levels
const (
	IPReputationClean     IPReputationLevel = "clean"
	IPReputationLow       IPReputationLevel = "low_risk"
	IPReputationMedium    IPReputationLevel = "medium_risk"
	IPReputationHigh      IPReputationLevel = "high_risk"
	IPReputationMalicious IPReputationLevel = "malicious"
	IPReputationUnknown   IPReputationLevel = "unknown"
)

// IPResult represents the result of an IP address analysis
type IPResult struct {
	IP               string            `json:"ip"`
	Status           IPScanStatus      `json:"status"`
	Resource         string            `json:"resource"`
	Permalink        string            `json:"permalink"`
	ASN              int               `json:"asn"`
	ASOwner          string            `json:"as_owner"`
	Country          string            `json:"country"`
	Continent        string            `json:"continent"`
	Network          string            `json:"network"`
	Categories       map[string]string `json:"categories"`
	Reputation       int               `json:"reputation"`
	ReputationLevel  IPReputationLevel `json:"reputation_level"`
	LastAnalysisDate time.Time         `json:"last_analysis_date"`
	TotalVotes       struct {
		Harmless  int `json:"harmless"`
		Malicious int `json:"malicious"`
	} `json:"total_votes"`
	ResolutionRecords []ResolutionRecord      `json:"resolution_records,omitempty"`
	WhoisInfo         map[string]string       `json:"whois_info,omitempty"`
	EngineResults     map[string]EngineResult `json:"engine_results"`
	Tags              []string                `json:"tags"`
	Error             string                  `json:"error,omitempty"`
}

// IPOptions represents options for IP address analysis
type IPOptions struct {
	EnableCache        bool              // Whether to use caching
	IncludeResolutions bool              // Include DNS resolution history
	IncludeWhois       bool              // Include WHOIS data
	SkipEngineDetail   bool              // Skip detailed engine results
	AdditionalParams   map[string]string // Additional API parameters
}

// DefaultIPOptions returns default options for IP analysis
func DefaultIPOptions() IPOptions {
	return IPOptions{
		EnableCache:        true,
		IncludeResolutions: true,
		IncludeWhois:       true,
		SkipEngineDetail:   false,
		AdditionalParams:   make(map[string]string),
	}
}

// validateIP checks if a string is a valid IP address
func validateIP(ip string) (string, error) {
	// Parse and validate IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("%w: invalid IP address format", errors.ErrInvalidArgument)
	}

	// Return the string representation
	return parsedIP.String(), nil
}

// LookupIP retrieves information about an IP address from VirusTotal
func LookupIP(ip string, options ...func(*IPOptions)) (*IPResult, error) {
	// Create options with defaults and apply provided options
	opts := DefaultIPOptions()
	for _, option := range options {
		option(&opts)
	}

	// Get client
	client, err := GetClient()
	if err != nil {
		return nil, err
	}

	// Validate IP
	validatedIP, err := validateIP(ip)
	if err != nil {
		return nil, err
	}

	// Check cache
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("ip:%s", validatedIP)
		if cachedResult, found := client.getCachedResult(cacheKey); found {
			logger.LogInfo("Retrieved IP analysis from cache", map[string]interface{}{
				"ip": validatedIP,
			})
			return cachedResult.(*IPResult), nil
		}
	}

	// Create thread-safe path for this IP
	ipMutex := fsutil.GetPathMutex(fmt.Sprintf("vtip:%s", validatedIP))
	ipMutex.Lock()
	defer ipMutex.Unlock()

	// Initialize the result
	result := &IPResult{
		IP:            validatedIP,
		Status:        IPScanStatusCompleted,
		Resource:      validatedIP,
		Categories:    make(map[string]string),
		EngineResults: make(map[string]EngineResult),
		WhoisInfo:     make(map[string]string),
	}

	// Prepare the URL with relationships if needed
	urlRelationships := make([]string, 0)

	if opts.IncludeResolutions {
		urlRelationships = append(urlRelationships, "resolutions")
	}

	if opts.IncludeWhois {
		urlRelationships = append(urlRelationships, "whois")
	}

	// Build URL with relationships
	var path string
	if len(urlRelationships) > 0 {
		path = fmt.Sprintf("ip_addresses/%s?relationships=%s", validatedIP, strings.Join(urlRelationships, ","))
	} else {
		path = fmt.Sprintf("ip_addresses/%s", validatedIP)
	}

	// Get IP data from VirusTotal
	var ipObj *vt.Object
	lookupErr := client.executeWithRetry(fmt.Sprintf("ip_lookup:%s", validatedIP), func() error {
		var err error
		ipObj, err = client.vtClient.GetObject(vt.URL(path))
		return err
	})

	// Handle lookup errors
	if lookupErr != nil {
		// Check if this is a "not found" error
		if strings.Contains(lookupErr.Error(), "not found") {
			logger.LogInfo("IP not found in VirusTotal database", map[string]interface{}{
				"ip": validatedIP,
			})
			return nil, fmt.Errorf("%w: IP not found in VirusTotal database", errors.ErrFileNotFound)
		}
		return nil, fmt.Errorf("%w: %s", errors.ErrNetworkError, lookupErr.Error())
	}

	// Parse the IP object
	err = parseIPObject(ipObj, result, opts)
	if err != nil {
		return nil, err
	}

	// Process relationships if included in the response
	if opts.IncludeResolutions {
		processIPResolutions(ipObj, result)
	}

	if opts.IncludeWhois {
		processIPWhois(ipObj, result)
	}

	// Set permalink
	result.Permalink = fmt.Sprintf("https://www.virustotal.com/gui/ip-address/%s/detection", validatedIP)

	// Cache the result if enabled
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("ip:%s", validatedIP)
		client.cacheResult(cacheKey, result)
	}

	return result, nil
}

// parseIPObject extracts the main IP information from a VirusTotal IP object
func parseIPObject(obj *vt.Object, result *IPResult, opts IPOptions) error {
	// Get ASN information
	asn, err := obj.GetInt64("asn")
	if err == nil {
		result.ASN = int(asn)
	}

	// Get AS owner
	asOwner, _ := obj.GetString("as_owner")
	result.ASOwner = asOwner

	// Get country
	country, _ := obj.GetString("country")
	result.Country = country

	// Get continent
	continent, _ := obj.GetString("continent")
	result.Continent = continent

	// Get network
	network, _ := obj.GetString("network")
	result.Network = network

	// Get last analysis date
	lastAnalysisDate, err := obj.GetTime("last_analysis_date")
	if err == nil {
		result.LastAnalysisDate = lastAnalysisDate
	}

	// Get reputation
	reputation, err := obj.GetInt64("reputation")
	if err == nil {
		result.Reputation = int(reputation)
		result.ReputationLevel = calculateIPReputationLevel(int(reputation))
	}

	// Get categories
	categories, err := obj.Get("categories")
	if err == nil {
		if cats, ok := categories.(map[string]interface{}); ok {
			for source, category := range cats {
				if cat, ok := category.(string); ok {
					result.Categories[source] = cat
				}
			}
		}
	}

	// Get total votes
	harmlessVotes, _ := obj.GetInt64("total_votes.harmless")
	maliciousVotes, _ := obj.GetInt64("total_votes.malicious")
	result.TotalVotes.Harmless = int(harmlessVotes)
	result.TotalVotes.Malicious = int(maliciousVotes)

	// Get tags
	tags, err := obj.GetStringSlice("tags")
	if err == nil {
		result.Tags = tags
	}

	// Only get engine results if detailed results are requested
	if !opts.SkipEngineDetail {
		// Get scan results from engines
		lastAnalysisResults, err := obj.Get("last_analysis_results")
		if err == nil {
			if results, ok := lastAnalysisResults.(map[string]interface{}); ok {
				for engine, data := range results {
					if engineData, ok := data.(map[string]interface{}); ok {
						engineResult := EngineResult{}

						if category, found := engineData["category"].(string); found {
							engineResult.Category = category
						}

						if result, found := engineData["result"].(string); found {
							engineResult.Result = result
						}

						if method, found := engineData["method"].(string); found {
							engineResult.Method = method
						}

						if version, found := engineData["engine_version"].(string); found {
							engineResult.EngineVersion = version
						}

						if update, found := engineData["engine_update"].(string); found {
							engineResult.EngineUpdate = update
						}

						result.EngineResults[engine] = engineResult
					}
				}
			}
		}
	}

	return nil
}

// processIPResolutions extracts resolution records from the IP object
func processIPResolutions(obj *vt.Object, result *IPResult) {
	// Get resolutions relationship
	resolutionsRel, err := obj.GetRelationship("resolutions")
	if err != nil {
		return
	}

	// Process resolutions
	for _, resolution := range resolutionsRel.Objects() {
		record := ResolutionRecord{}

		// Get resolution hostname
		hostname, _ := resolution.GetString("host_name")
		if hostname != "" {
			record.Type = "PTR"
			record.Value = hostname
		}

		// Get date
		date, err := resolution.GetTime("date")
		if err == nil {
			record.Date = date
		}

		// Only add if we have a value
		if record.Value != "" {
			result.ResolutionRecords = append(result.ResolutionRecords, record)
		}
	}
}

// processIPWhois extracts WHOIS information from the IP object
func processIPWhois(obj *vt.Object, result *IPResult) {
	// Get WHOIS relationship
	whoisRel, err := obj.GetRelationship("whois")
	if err != nil {
		return
	}

	// Process WHOIS data
	if len(whoisRel.Objects()) > 0 {
		whoisObj := whoisRel.Objects()[0]

		// Get raw WHOIS data
		rawWhois, _ := whoisObj.GetString("raw")
		if rawWhois != "" {
			// Parse key-value pairs from WHOIS
			parseWhoisData(rawWhois, result.WhoisInfo)
		}
	}
}

// calculateIPReputationLevel converts a numerical reputation score to a level
func calculateIPReputationLevel(reputation int) IPReputationLevel {
	switch {
	case reputation >= 70:
		return IPReputationClean
	case reputation >= 40:
		return IPReputationLow
	case reputation >= 0:
		return IPReputationMedium
	case reputation >= -50:
		return IPReputationHigh
	case reputation < -50:
		return IPReputationMalicious
	default:
		return IPReputationUnknown
	}
}

// CheckIPReputation checks if an IP has known malicious activities
func CheckIPReputation(ip string) (*IPResult, error) {
	// Do a lightweight IP lookup
	result, err := LookupIP(ip,
		WithIPResolutions(false),
		WithIPWhois(false),
	)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetIPLocationInfo retrieves geolocation information for an IP
func GetIPLocationInfo(ip string) (*IPResult, error) {
	// Do a lightweight IP lookup focused on location data
	result, err := LookupIP(ip,
		WithIPResolutions(false),
		WithIPWhois(false),
		WithIPEngineDetail(false),
	)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// WithIPCache enables or disables caching
func WithIPCache(enable bool) func(*IPOptions) {
	return func(o *IPOptions) {
		o.EnableCache = enable
	}
}

// WithIPResolutions enables or disables resolution records in the result
func WithIPResolutions(include bool) func(*IPOptions) {
	return func(o *IPOptions) {
		o.IncludeResolutions = include
	}
}

// WithIPWhois enables or disables WHOIS data in the result
func WithIPWhois(include bool) func(*IPOptions) {
	return func(o *IPOptions) {
		o.IncludeWhois = include
	}
}

// WithIPEngineDetail enables or disables detailed engine results
func WithIPEngineDetail(includeDetail bool) func(*IPOptions) {
	return func(o *IPOptions) {
		o.SkipEngineDetail = !includeDetail
	}
}

// WithIPAdditionalParams sets additional API parameters
func WithIPAdditionalParams(params map[string]string) func(*IPOptions) {
	return func(o *IPOptions) {
		for k, v := range params {
			o.AdditionalParams[k] = v
		}
	}
}
