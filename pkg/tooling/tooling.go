package tooling

import (
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/composition"
	"github.com/deploymenttheory/go-app-composer/internal/config"
	"github.com/deploymenttheory/go-app-composer/internal/logger"
)

// InitOptions contains options for initializing the tooling API
type InitOptions struct {
	ConfigFile  string // Path to configuration file
	Debug       bool   // Enable debug logging
	LogFormat   string // Log format: "human" or "json"
	LogFile     string // Path to log file
	SuppressLog bool   // Suppress all logging
}

// WorkflowResult contains the results of a workflow execution
type WorkflowResult struct {
	Success      bool                   // Whether the workflow completed successfully
	ErrorMessage string                 // Error message if any
	Variables    map[string]interface{} // Final state of variables after workflow execution
}

var initialized bool

// Initialize initializes the tooling API with the given options
func Initialize(options InitOptions) error {
	if initialized {
		return nil // Already initialized
	}

	// Initialize configuration
	var configErr error
	if options.ConfigFile != "" {
		configErr = config.Initialize(options.ConfigFile)
	} else {
		configErr = config.Initialize("")
	}

	// Update config with provided options
	if options.Debug {
		config.Instance.Debug = true
	}

	if options.LogFormat != "" {
		config.Instance.LogFormat = options.LogFormat
	}

	if options.LogFile != "" {
		config.Instance.LogFile = options.LogFile
	}

	// Initialize logging
	if !options.SuppressLog {
		logConfig := logger.LoggerConfig{
			Debug:     config.Instance.Debug,
			LogFormat: config.Instance.LogFormat,
			LogFile:   config.Instance.LogFile,
		}

		if err := logger.InitLogger(logConfig); err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}
	}

	// Log initialization if logging is not suppressed
	if !options.SuppressLog {
		logger.LogInfo("Tooling API initialized", map[string]interface{}{
			"config_file": options.ConfigFile,
			"debug":       options.Debug,
			"log_format":  options.LogFormat,
		})

		// Log configuration error if any
		if configErr != nil {
			logger.LogWarn("Configuration initialization warning", map[string]interface{}{
				"error": configErr.Error(),
			})
		}
	}

	initialized = true
	return nil
}

// DefaultOptions returns the default initialization options
func DefaultOptions() InitOptions {
	return InitOptions{
		Debug:       false,
		LogFormat:   "human",
		LogFile:     "logs/tooling.log",
		SuppressLog: false,
	}
}

// ExecuteWorkflow executes a workflow defined in a file
func ExecuteWorkflow(workflowFile string) (*WorkflowResult, error) {
	// Ensure API is initialized
	if !initialized {
		if err := Initialize(DefaultOptions()); err != nil {
			return nil, fmt.Errorf("failed to initialize tooling API: %w", err)
		}
	}

	logger.LogInfo("Executing workflow", map[string]interface{}{
		"file": workflowFile,
	})

	// Load the workflow
	workflow, err := composition.LoadWorkflow(workflowFile)
	if err != nil {
		return &WorkflowResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to load workflow: %s", err.Error()),
		}, err
	}

	// Validate the workflow
	errors := composition.ValidateWorkflow(workflow)
	if len(errors) > 0 {
		// Concatenate all errors into a single message
		var errorMessages []string
		for _, err := range errors {
			errorMessages = append(errorMessages, err.Error())
		}

		errorMessage := fmt.Sprintf("Workflow validation failed with %d errors: %s",
			len(errors), strings.Join(errorMessages, "; "))

		return &WorkflowResult{
			Success:      false,
			ErrorMessage: errorMessage,
		}, fmt.Errorf("%s", errorMessage)
	}

	// Execute the workflow
	if err := composition.ExecuteWorkflow(workflow); err != nil {
		return &WorkflowResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Workflow execution failed: %s", err.Error()),
			Variables:    workflow.Variables,
		}, err
	}

	// Return successful result with final variables
	return &WorkflowResult{
		Success:   true,
		Variables: workflow.Variables,
	}, nil
}

// ExecuteWorkflowFromYAML executes a workflow defined in a YAML string
func ExecuteWorkflowFromYAML(workflowYAML string) (*WorkflowResult, error) {
	// Ensure API is initialized
	if !initialized {
		if err := Initialize(DefaultOptions()); err != nil {
			return nil, fmt.Errorf("failed to initialize tooling API: %w", err)
		}
	}

	// Create a temporary file for the workflow
	tempFile, err := os.CreateTemp("", "workflow-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	// Write the workflow YAML to the file
	if _, err := tempFile.WriteString(workflowYAML); err != nil {
		return nil, fmt.Errorf("failed to write workflow to temporary file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Execute the workflow from the temporary file
	return ExecuteWorkflow(tempFile.Name())
}

// SetMDMProvider sets the MDM provider in the configuration
func SetMDMProvider(provider string) {
	// Ensure API is initialized
	if !initialized {
		_ = Initialize(DefaultOptions())
	}

	config.Instance.MDM.Provider = provider
}

// SetStorageProvider sets the storage provider in the configuration
func SetStorageProvider(provider string) {
	// Ensure API is initialized
	if !initialized {
		_ = Initialize(DefaultOptions())
	}

	config.Instance.Storage.Provider = provider
}

// SetJamfCredentials sets the Jamf credentials in the configuration
func SetJamfCredentials(url, username, password string) {
	// Ensure API is initialized
	if !initialized {
		_ = Initialize(DefaultOptions())
	}

	config.Instance.MDM.Provider = "jamf"
	config.Instance.MDM.Jamf.URL = url
	config.Instance.MDM.Jamf.Username = username
	config.Instance.MDM.Jamf.Password = password
}

// SetIntuneCredentials sets the Intune credentials in the configuration
func SetIntuneCredentials(tenantID, clientID, clientSecret string) {
	// Ensure API is initialized
	if !initialized {
		_ = Initialize(DefaultOptions())
	}

	config.Instance.MDM.Provider = "intune"
	config.Instance.MDM.Intune.TenantID = tenantID
	config.Instance.MDM.Intune.ClientID = clientID
	config.Instance.MDM.Intune.ClientSecret = clientSecret
}

// SetS3Credentials sets the S3 credentials in the configuration
func SetS3Credentials(bucket, region, accessKey, secretKey string) {
	// Ensure API is initialized
	if !initialized {
		_ = Initialize(DefaultOptions())
	}

	config.Instance.Storage.Provider = "s3"
	config.Instance.Storage.S3.Bucket = bucket
	config.Instance.Storage.S3.Region = region
	config.Instance.Storage.S3.AccessKey = accessKey
	config.Instance.Storage.S3.SecretKey = secretKey
}

// GetVersion returns the current version of the tooling API
func GetVersion() string {
	return "0.1.0" // TODO: Implement proper versioning
}

// Shutdown performs any necessary cleanup before the application exits
func Shutdown() error {
	if initialized {
		logger.LogInfo("Tooling API shutting down", nil)
		logger.Sync()
	}
	return nil
}
