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

// DomainScanStatus represents the status of a domain scan
type DomainScanStatus string

// Domain scan status constants
const (
	DomainScanStatusCompleted DomainScanStatus = "completed"
	DomainScanStatusError     DomainScanStatus = "error"
)

// DomainReputationLevel represents a domain's reputation level
type DomainReputationLevel string

// Domain reputation levels
const (
	DomainReputationClean     DomainReputationLevel = "clean"
	DomainReputationLow       DomainReputationLevel = "low_risk"
	DomainReputationMedium    DomainReputationLevel = "medium_risk"
	DomainReputationHigh      DomainReputationLevel = "high_risk"
	DomainReputationMalicious DomainReputationLevel = "malicious"
	DomainReputationUnknown   DomainReputationLevel = "unknown"
)

// DomainResult represents the result of a domain analysis
type DomainResult struct {
	Domain           string                `json:"domain"`
	Status           DomainScanStatus      `json:"status"`
	Resource         string                `json:"resource"`
	Permalink        string                `json:"permalink"`
	Categories       map[string]string     `json:"categories"`
	Reputation       int                   `json:"reputation"`
	ReputationLevel  DomainReputationLevel `json:"reputation_level"`
	LastAnalysisDate time.Time             `json:"last_analysis_date"`
	TotalVotes       struct {
		Harmless  int `json:"harmless"`
		Malicious int `json:"malicious"`
	} `json:"total_votes"`
	RegisteredDate       *time.Time              `json:"registered_date,omitempty"`
	ExpirationDate       *time.Time              `json:"expiration_date,omitempty"`
	Registrar            string                  `json:"registrar,omitempty"`
	Subdomains           []string                `json:"subdomains,omitempty"`
	ResolutionRecords    []ResolutionRecord      `json:"resolution_records,omitempty"`
	WhoisInfo            map[string]string       `json:"whois_info,omitempty"`
	LastHTTPSCertificate *CertificateInfo        `json:"last_https_certificate,omitempty"`
	EngineResults        map[string]EngineResult `json:"engine_results"`
	Tags                 []string                `json:"tags"`
	Error                string                  `json:"error,omitempty"`
}

// ResolutionRecord represents a domain resolution record
type ResolutionRecord struct {
	Type  string    `json:"type"`
	Value string    `json:"value"`
	Date  time.Time `json:"date"`
	TTL   int       `json:"ttl,omitempty"`
}

// CertificateInfo contains information about a domain's HTTPS certificate
type CertificateInfo struct {
	Issuer         string    `json:"issuer"`
	Subject        string    `json:"subject"`
	ValidFrom      time.Time `json:"valid_from"`
	ValidTo        time.Time `json:"valid_to"`
	SerialNumber   string    `json:"serial_number"`
	Thumbprint     string    `json:"thumbprint"`
	Version        int       `json:"version"`
	SubjectAltName []string  `json:"subject_alt_name"`
}

// DomainOptions represents options for domain analysis
type DomainOptions struct {
	EnableCache         bool              // Whether to use caching
	IncludeSubdomains   bool              // Include subdomains list
	IncludeResolutions  bool              // Include DNS resolution history
	IncludeWhois        bool              // Include WHOIS data
	IncludeCertificates bool              // Include HTTPS certificate data
	SkipEngineDetail    bool              // Skip detailed engine results
	AdditionalParams    map[string]string // Additional API parameters
}

// DefaultDomainOptions returns default options for domain analysis
func DefaultDomainOptions() DomainOptions {
	return DomainOptions{
		EnableCache:         true,
		IncludeSubdomains:   true,
		IncludeResolutions:  true,
		IncludeWhois:        true,
		IncludeCertificates: true,
		SkipEngineDetail:    false,
		AdditionalParams:    make(map[string]string),
	}
}

// normalizeDomain normalizes a domain name for consistent lookup
func normalizeDomain(domain string) (string, error) {
	// Remove protocol prefixes if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Remove path, query string and fragment
	if slashIndex := strings.Index(domain, "/"); slashIndex != -1 {
		domain = domain[:slashIndex]
	}

	// Remove port number if present
	if colonIndex := strings.LastIndex(domain, ":"); colonIndex != -1 {
		// Make sure this is actually a port and not an IPv6 address
		if !strings.Contains(domain, "[") && !strings.Contains(domain, "]") {
			domain = domain[:colonIndex]
		}
	}

	// Check if the domain is valid
	if domain == "" || strings.Contains(domain, " ") {
		return "", fmt.Errorf("%w: invalid domain format", errors.ErrInvalidArgument)
	}

	// Validate domain format
	if net.ParseIP(domain) != nil {
		return "", fmt.Errorf("%w: input appears to be an IP address, not a domain", errors.ErrInvalidArgument)
	}

	// Convert to lowercase
	domain = strings.ToLower(domain)

	return domain, nil
}

// LookupDomain retrieves information about a domain from VirusTotal
func LookupDomain(domain string, options ...func(*DomainOptions)) (*DomainResult, error) {
	// Create options with defaults and apply provided options
	opts := DefaultDomainOptions()
	for _, option := range options {
		option(&opts)
	}

	// Get client
	client, err := GetClient()
	if err != nil {
		return nil, err
	}

	// Normalize domain
	normalizedDomain, err := normalizeDomain(domain)
	if err != nil {
		return nil, err
	}

	// Check cache
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("domain:%s", normalizedDomain)
		if cachedResult, found := client.getCachedResult(cacheKey); found {
			logger.LogInfo("Retrieved domain analysis from cache", map[string]interface{}{
				"domain": normalizedDomain,
			})
			return cachedResult.(*DomainResult), nil
		}
	}

	// Create thread-safe path for this domain
	domainMutex := fsutil.GetPathMutex(fmt.Sprintf("vtdomain:%s", normalizedDomain))
	domainMutex.Lock()
	defer domainMutex.Unlock()

	// Initialize the result
	result := &DomainResult{
		Domain:        normalizedDomain,
		Status:        DomainScanStatusCompleted,
		Resource:      normalizedDomain,
		Categories:    make(map[string]string),
		EngineResults: make(map[string]EngineResult),
		WhoisInfo:     make(map[string]string),
	}

	// Prepare the URL with relationships if needed
	urlRelationships := make([]string, 0)

	if opts.IncludeSubdomains {
		urlRelationships = append(urlRelationships, "subdomains")
	}

	if opts.IncludeResolutions {
		urlRelationships = append(urlRelationships, "resolutions")
	}

	if opts.IncludeWhois {
		urlRelationships = append(urlRelationships, "whois")
	}

	if opts.IncludeCertificates {
		urlRelationships = append(urlRelationships, "last_https_certificate")
	}

	// Build path with relationships
	var path string
	if len(urlRelationships) > 0 {
		path = fmt.Sprintf("domains/%s?relationships=%s", normalizedDomain, strings.Join(urlRelationships, ","))
	} else {
		path = fmt.Sprintf("domains/%s", normalizedDomain)
	}

	// Get domain data from VirusTotal
	var domainObj *vt.Object
	lookupErr := client.executeWithRetry(fmt.Sprintf("domain_lookup:%s", normalizedDomain), func() error {
		var err error
		domainObj, err = client.vtClient.GetObject(vt.URL(path))
		return err
	})

	// Handle lookup errors
	if lookupErr != nil {
		// Check if this is a "not found" error
		if strings.Contains(lookupErr.Error(), "not found") {
			logger.LogInfo("Domain not found in VirusTotal database", map[string]interface{}{
				"domain": normalizedDomain,
			})
			return nil, fmt.Errorf("%w: domain not found in VirusTotal database", errors.ErrFileNotFound)
		}
		return nil, fmt.Errorf("%w: %s", errors.ErrNetworkError, lookupErr.Error())
	}

	// Parse the domain object
	err = parseDomainObject(domainObj, result, opts)
	if err != nil {
		return nil, err
	}

	// Process relationships if included in the response
	if opts.IncludeSubdomains {
		processSubdomains(domainObj, result)
	}

	if opts.IncludeResolutions {
		processResolutions(domainObj, result)
	}

	if opts.IncludeWhois {
		processWhois(domainObj, result)
	}

	if opts.IncludeCertificates {
		processCertificates(domainObj, result)
	}

	// Set permalink
	result.Permalink = fmt.Sprintf("https://www.virustotal.com/gui/domain/%s/detection", normalizedDomain)

	// Cache the result if enabled
	if opts.EnableCache {
		cacheKey := fmt.Sprintf("domain:%s", normalizedDomain)
		client.cacheResult(cacheKey, result)
	}

	return result, nil
}

// parseDomainObject extracts the main domain information from a VirusTotal domain object
func parseDomainObject(obj *vt.Object, result *DomainResult, opts DomainOptions) error {
	// Get last analysis date
	lastAnalysisDate, err := obj.GetTime("last_analysis_date")
	if err == nil {
		result.LastAnalysisDate = lastAnalysisDate
	}

	// Get reputation
	reputation, err := obj.GetInt64("reputation")
	if err == nil {
		result.Reputation = int(reputation)
		result.ReputationLevel = calculateReputationLevel(int(reputation))
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

	// Get registrar
	registrar, _ := obj.GetString("registrar")
	result.Registrar = registrar

	// Get registration and expiration dates
	createDate, err := obj.GetTime("creation_date")
	if err == nil {
		result.RegisteredDate = &createDate
	}

	expirationDate, err := obj.GetTime("expiration_date")
	if err == nil {
		result.ExpirationDate = &expirationDate
	}

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

// processSubdomains extracts subdomains from the domain object
func processSubdomains(obj *vt.Object, result *DomainResult) {
	// Get subdomains relationship
	subdomainsRel, err := obj.GetRelationship("subdomains")
	if err != nil {
		return
	}

	// Process subdomains
	for _, subdomain := range subdomainsRel.Objects() {
		id := subdomain.ID()
		if id != "" {
			result.Subdomains = append(result.Subdomains, id)
		}
	}
}

// processResolutions extracts resolution records from the domain object
func processResolutions(obj *vt.Object, result *DomainResult) {
	// Get resolutions relationship
	resolutionsRel, err := obj.GetRelationship("resolutions")
	if err != nil {
		return
	}

	// Process resolutions
	for _, resolution := range resolutionsRel.Objects() {
		record := ResolutionRecord{}

		// Get resolution type and value
		ipAddress, _ := resolution.GetString("ip_address")
		if ipAddress != "" {
			record.Type = "A"
			record.Value = ipAddress
		}

		// Get date
		date, err := resolution.GetTime("date")
		if err == nil {
			record.Date = date
		}

		// Get TTL if available
		ttl, err := resolution.GetInt64("ttl")
		if err == nil {
			record.TTL = int(ttl)
		}

		// Only add if we have a value
		if record.Value != "" {
			result.ResolutionRecords = append(result.ResolutionRecords, record)
		}
	}
}

// processWhois extracts WHOIS information from the domain object
func processWhois(obj *vt.Object, result *DomainResult) {
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

// processCertificates extracts HTTPS certificate information from the domain object
func processCertificates(obj *vt.Object, result *DomainResult) {
	// Get certificate relationship
	certRel, err := obj.GetRelationship("last_https_certificate")
	if err != nil {
		return
	}

	// Process certificate data
	if len(certRel.Objects()) > 0 {
		certObj := certRel.Objects()[0]

		cert := &CertificateInfo{}

		// Get issuer
		issuer, _ := certObj.GetString("issuer.CN")
		if issuer == "" {
			issuer, _ = certObj.GetString("issuer.O")
		}
		cert.Issuer = issuer

		// Get subject
		subject, _ := certObj.GetString("subject.CN")
		cert.Subject = subject

		// Get validity dates
		validFrom, err := certObj.GetTime("validity.not_before")
		if err == nil {
			cert.ValidFrom = validFrom
		}

		validTo, err := certObj.GetTime("validity.not_after")
		if err == nil {
			cert.ValidTo = validTo
		}

		// Get serial number
		serialNumber, _ := certObj.GetString("serial_number")
		cert.SerialNumber = serialNumber

		// Get thumbprint
		thumbprint, _ := certObj.GetString("thumbprint")
		cert.Thumbprint = thumbprint

		// Get version
		version, err := certObj.GetInt64("version")
		if err == nil {
			cert.Version = int(version)
		}

		// Get subject alternative names
		sanData, err := certObj.Get("extensions.subject_alternative_name")
		if err == nil {
			if san, ok := sanData.([]interface{}); ok {
				for _, name := range san {
					if strName, ok := name.(string); ok {
						cert.SubjectAltName = append(cert.SubjectAltName, strName)
					}
				}
			}
		}

		result.LastHTTPSCertificate = cert
	}
}

// parseWhoisData parses raw WHOIS data into key-value pairs
func parseWhoisData(whoisData string, result map[string]string) {
	// Split the WHOIS data into lines
	lines := strings.Split(whoisData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for key-value pairs using a colon separator
		colonPos := strings.Index(line, ":")
		if colonPos > 0 {
			key := strings.TrimSpace(line[:colonPos])
			value := ""
			if colonPos < len(line)-1 {
				value = strings.TrimSpace(line[colonPos+1:])
			}

			// Don't add empty values
			if value != "" {
				result[key] = value
			}
		}
	}
}

// calculateReputationLevel converts a numerical reputation score to a level
func calculateReputationLevel(reputation int) DomainReputationLevel {
	switch {
	case reputation >= 70:
		return DomainReputationClean
	case reputation >= 40:
		return DomainReputationLow
	case reputation >= 0:
		return DomainReputationMedium
	case reputation >= -50:
		return DomainReputationHigh
	case reputation < -50:
		return DomainReputationMalicious
	default:
		return DomainReputationUnknown
	}
}

// GetSubdomains retrieves all known subdomains for a domain
func GetSubdomains(domain string) ([]string, error) {
	// Lookup the domain with subdomains included
	result, err := LookupDomain(domain, WithDomainSubdomains(true))
	if err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

// CheckDomainReputation checks if a domain has known malicious activities
func CheckDomainReputation(domain string) (*DomainResult, error) {
	// Do a lightweight domain lookup
	result, err := LookupDomain(domain,
		WithDomainSubdomains(false),
		WithDomainResolutions(false),
		WithDomainWhois(false),
		WithDomainCertificates(false),
	)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// WithDomainCache enables or disables caching
func WithDomainCache(enable bool) func(*DomainOptions) {
	return func(o *DomainOptions) {
		o.EnableCache = enable
	}
}

// WithDomainSubdomains enables or disables subdomains in the result
func WithDomainSubdomains(include bool) func(*DomainOptions) {
	return func(o *DomainOptions) {
		o.IncludeSubdomains = include
	}
}

// WithDomainResolutions enables or disables resolution records in the result
func WithDomainResolutions(include bool) func(*DomainOptions) {
	return func(o *DomainOptions) {
		o.IncludeResolutions = include
	}
}

// WithDomainWhois enables or disables WHOIS data in the result
func WithDomainWhois(include bool) func(*DomainOptions) {
	return func(o *DomainOptions) {
		o.IncludeWhois = include
	}
}

// WithDomainCertificates enables or disables certificate data in the result
func WithDomainCertificates(include bool) func(*DomainOptions) {
	return func(o *DomainOptions) {
		o.IncludeCertificates = include
	}
}

// WithDomainEngineDetail enables or disables detailed engine results
func WithDomainEngineDetail(includeDetail bool) func(*DomainOptions) {
	return func(o *DomainOptions) {
		o.SkipEngineDetail = !includeDetail
	}
}

// WithDomainAdditionalParams sets additional API parameters
func WithDomainAdditionalParams(params map[string]string) func(*DomainOptions) {
	return func(o *DomainOptions) {
		for k, v := range params {
			o.AdditionalParams[k] = v
		}
	}
}
