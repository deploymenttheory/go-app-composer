package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-app-composer/cmd"
	"github.com/deploymenttheory/go-app-composer/internal/bootstrap"
	logger "github.com/deploymenttheory/go-app-composer/internal/common/zap_logger"
	"github.com/deploymenttheory/go-app-composer/internal/composition"
	"github.com/deploymenttheory/go-app-composer/internal/config"
)

// Mode constants
const (
	ModeCLI      = "cli"
	ModeWorkflow = "workflow"
	ModeDirect   = "direct"
)

func main() {
	// Get app configuration file from environment if specified
	configFile := os.Getenv("APP_COMPOSER_CONFIG")

	// 1. Initialize application configuration
	if err := config.Initialize(configFile); err != nil {
		// For app configuration errors, we print to stderr and exit since we can't continue
		fmt.Fprintf(os.Stderr, "Error initializing configuration: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize logging based on application configuration
	if err := initLogging(); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	// Log startup information
	logger.LogInfo("Application started", map[string]interface{}{
		"version": "0.1.0", // TODO: Add versioning system
		"mode":    getModeString(),
	})

	// 3. Determine execution mode and handle workflow or direct execution
	if isWorkflowMode() {
		// Run in workflow mode using a composition file
		if err := runWorkflow(); err != nil {
			logger.LogError("Workflow execution failed", err, nil)
			os.Exit(1)
		}
	} else if isCLI() {
		// Run in CLI mode with Cobra
		cmd.Execute()
	} else {
		// Run in direct execution mode
		bootstrap.Boot()
	}

	// Ensure logs are flushed before exit
	logger.Sync()
}

// initLogging initializes the logger based on configuration settings
func initLogging() error {
	logConfig := logger.LoggerConfig{
		Debug:     config.Instance.Debug,
		LogFormat: config.Instance.LogFormat,
		LogFile:   config.Instance.LogFile,
	}

	return logger.InitLogger(logConfig)
}

// isCLI determines if the program was run with CLI arguments
func isCLI() bool {
	// Also check for RUN_MODE environment variable
	if runMode := os.Getenv("RUN_MODE"); runMode == ModeCLI {
		return true
	}

	// Check if this is a workflow mode call
	if isWorkflowMode() {
		return false
	}

	return len(os.Args) > 1 // If there are additional arguments, assume CLI mode
}

// isWorkflowMode determines if the program was run with a workflow file
func isWorkflowMode() bool {
	// Check for RUN_MODE environment variable
	if runMode := os.Getenv("RUN_MODE"); runMode == ModeWorkflow {
		return true
	}

	// Check for --workflow flag or -w flag
	for i, arg := range os.Args {
		if (arg == "--workflow" || arg == "-w") && i+1 < len(os.Args) {
			return true
		}

		// Check for --workflow=file syntax
		if strings.HasPrefix(arg, "--workflow=") || strings.HasPrefix(arg, "-w=") {
			return true
		}
	}

	// Check for WORKFLOW environment variable
	return os.Getenv("WORKFLOW") != ""
}

// getWorkflowFile gets the workflow file path from arguments or environment
func getWorkflowFile() string {
	// Check command line arguments
	for i, arg := range os.Args {
		if (arg == "--workflow" || arg == "-w") && i+1 < len(os.Args) {
			return os.Args[i+1]
		}

		// Check for --workflow=file syntax
		if strings.HasPrefix(arg, "--workflow=") {
			return arg[11:] // extract the part after "="
		}

		if strings.HasPrefix(arg, "-w=") {
			return arg[3:] // extract the part after "="
		}
	}

	// Fall back to environment variable
	return os.Getenv("WORKFLOW")
}

// runWorkflow loads and executes the workflow
func runWorkflow() error {
	workflowFile := getWorkflowFile()
	if workflowFile == "" {
		return fmt.Errorf("workflow mode specified but no workflow file provided")
	}

	// Load the workflow
	workflow, err := composition.LoadWorkflow(workflowFile)
	if err != nil {
		return fmt.Errorf("failed to load workflow: %w", err)
	}

	// Validate the workflow
	errors := composition.ValidateWorkflow(workflow)
	if len(errors) > 0 {
		// Log all validation errors
		for _, err := range errors {
			logger.LogError("Workflow validation error", err, nil)
		}
		return fmt.Errorf("workflow validation failed with %d errors", len(errors))
	}

	// Execute the workflow
	return composition.ExecuteWorkflow(workflow)
}

// getModeString returns a string representation of the current execution mode
func getModeString() string {
	if isWorkflowMode() {
		return ModeWorkflow
	} else if isCLI() {
		return ModeCLI
	} else {
		return ModeDirect
	}
}
