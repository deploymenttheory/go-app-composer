package composition

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	logger "github.com/deploymenttheory/go-app-composer/internal/common/zap_logger"
	"github.com/deploymenttheory/go-app-composer/internal/config"
	"github.com/spf13/viper"
)

// Step represents a single step in the composition workflow
type Step struct {
	Name        string                 `mapstructure:"name"`
	Type        string                 `mapstructure:"type"`
	Description string                 `mapstructure:"description"`
	Condition   string                 `mapstructure:"condition"`
	Parameters  map[string]interface{} `mapstructure:",remain"`
}

// Workflow represents the entire composition workflow
type Workflow struct {
	Name        string                 `mapstructure:"name"`
	Description string                 `mapstructure:"description"`
	Version     string                 `mapstructure:"version"`
	Author      string                 `mapstructure:"author"`
	Steps       []Step                 `mapstructure:"steps"`
	Variables   map[string]interface{} `mapstructure:"variables"`
}

// LoadWorkflow loads a composition workflow from a file
func LoadWorkflow(filePath string) (*Workflow, error) {
	// Create a new viper instance for the composition
	v := viper.New()

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workflow file not found: %s", filePath)
	}

	// Set the file to use
	v.SetConfigFile(filePath)

	// Determine the file extension for type
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != "" {
		v.SetConfigType(ext[1:]) // Remove the leading dot
	} else {
		// Default to YAML if no extension
		v.SetConfigType("yaml")
	}

	// Read the file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading workflow file: %w", err)
	}

	// Unmarshal into the Workflow struct
	workflow := &Workflow{}
	if err := v.Unmarshal(workflow); err != nil {
		return nil, fmt.Errorf("error parsing workflow: %w", err)
	}

	// Populate variables with defaults if not set
	if workflow.Variables == nil {
		workflow.Variables = make(map[string]interface{})
	}

	// Add system variables to the variables map
	addSystemVariables(workflow)

	// Process templates in step parameters
	if err := processTemplates(workflow); err != nil {
		return nil, fmt.Errorf("error processing templates: %w", err)
	}

	return workflow, nil
}

// addSystemVariables adds system and config variables to the workflow's variables
func addSystemVariables(workflow *Workflow) {
	// Add temp directory
	workflow.Variables["temp_dir"] = config.Instance.Packaging.TempDir

	// Add cache directory
	workflow.Variables["cache_dir"] = config.Instance.Packaging.CacheDir

	// Add current working directory
	if cwd, err := os.Getwd(); err == nil {
		workflow.Variables["current_dir"] = cwd
	}

	// Add timestamp
	workflow.Variables["timestamp"] = fmt.Sprintf("%d", time.Now().Unix())
}

// processTemplates processes template strings in step parameters
func processTemplates(workflow *Workflow) error {
	for i, step := range workflow.Steps {
		processedParams := make(map[string]interface{})
		for key, value := range step.Parameters {
			// Only process string values
			if strValue, ok := value.(string); ok {
				processed, err := processTemplate(strValue, workflow.Variables)
				if err != nil {
					return fmt.Errorf("error processing template in step %s, parameter %s: %w", step.Name, key, err)
				}
				processedParams[key] = processed
			} else {
				// Keep non-string values as is
				processedParams[key] = value
			}
		}
		workflow.Steps[i].Parameters = processedParams
	}
	return nil
}

// processTemplate processes a single template string
func processTemplate(templateString string, variables map[string]interface{}) (string, error) {
	// Only process if the string contains template markers
	if !strings.Contains(templateString, "{{") && !strings.Contains(templateString, "}}") {
		return templateString, nil
	}

	// Create a new template
	tmpl, err := template.New("inline").Parse(templateString)
	if err != nil {
		return "", err
	}

	// Execute the template
	var buffer bytes.Buffer
	if err := tmpl.Execute(&buffer, variables); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

// ValidateWorkflow validates the workflow structure and parameters
func ValidateWorkflow(workflow *Workflow) []error {
	var errors []error

	// Validate required fields
	if workflow.Name == "" {
		errors = append(errors, fmt.Errorf("workflow name is required"))
	}

	if len(workflow.Steps) == 0 {
		errors = append(errors, fmt.Errorf("workflow must contain at least one step"))
	}

	// Validate each step
	for i, step := range workflow.Steps {
		if step.Name == "" {
			errors = append(errors, fmt.Errorf("step %d: name is required", i+1))
		}

		if step.Type == "" {
			errors = append(errors, fmt.Errorf("step %d (%s): type is required", i+1, step.Name))
		}

		// Validate step type
		if !isValidStepType(step.Type) {
			errors = append(errors, fmt.Errorf("step %d (%s): invalid type '%s'", i+1, step.Name, step.Type))
		}

		// Validate step parameters based on type
		stepErrors := validateStepParameters(step)
		for _, err := range stepErrors {
			errors = append(errors, fmt.Errorf("step %d (%s): %w", i+1, step.Name, err))
		}
	}

	return errors
}

// isValidStepType checks if a step type is valid
func isValidStepType(stepType string) bool {
	validTypes := []string{
		"download", "extract", "package", "add_file", "scan", "sign",
		"notarize", "upload", "delete", "move", "copy", "exec", "script",
	}

	for _, validType := range validTypes {
		if stepType == validType {
			return true
		}
	}

	return false
}

// validateStepParameters validates parameters for a specific step type
func validateStepParameters(step Step) []error {
	var errors []error

	switch step.Type {
	case "download":
		if _, ok := step.Parameters["url"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'url'"))
		}
		if _, ok := step.Parameters["output"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'output'"))
		}

	case "extract":
		if _, ok := step.Parameters["input"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'input'"))
		}
		if _, ok := step.Parameters["output"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'output'"))
		}

	case "package":
		if _, ok := step.Parameters["input"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'input'"))
		}
		if _, ok := step.Parameters["output"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'output'"))
		}

	case "add_file":
		if _, ok := step.Parameters["source"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'source'"))
		}
		if _, ok := step.Parameters["destination"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'destination'"))
		}

	case "scan":
		if _, ok := step.Parameters["input"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'input'"))
		}

	case "upload":
		if _, ok := step.Parameters["input"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'input'"))
		}
		if _, ok := step.Parameters["destination"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'destination'"))
		}

	case "exec":
		if _, ok := step.Parameters["command"]; !ok {
			errors = append(errors, fmt.Errorf("missing required parameter 'command'"))
		}

	case "script":
		if _, ok := step.Parameters["script"]; !ok && step.Parameters["file"] == nil {
			errors = append(errors, fmt.Errorf("missing required parameter 'script' or 'file'"))
		}
	}

	return errors
}

// ExecuteWorkflow executes the workflow steps
func ExecuteWorkflow(workflow *Workflow) error {
	logger.LogInfo("Starting workflow execution", map[string]interface{}{
		"workflow": workflow.Name,
		"steps":    len(workflow.Steps),
	})

	// Create a registry for the step handlers
	registry := createStepHandlerRegistry()

	// Execute each step
	for i, step := range workflow.Steps {
		logger.LogInfo(fmt.Sprintf("Executing step %d/%d: %s", i+1, len(workflow.Steps), step.Name),
			map[string]interface{}{
				"type":        step.Type,
				"description": step.Description,
			})

		// Check if step should be skipped based on condition
		if step.Condition != "" {
			shouldRun, err := evaluateCondition(step.Condition, workflow.Variables)
			if err != nil {
				return fmt.Errorf("error evaluating condition for step '%s': %w", step.Name, err)
			}

			if !shouldRun {
				logger.LogInfo(fmt.Sprintf("Skipping step %d/%d: %s (condition not met)", i+1, len(workflow.Steps), step.Name), nil)
				continue
			}
		}

		// Look up the handler for this step type
		handler, found := registry[step.Type]
		if !found {
			return fmt.Errorf("no handler found for step type '%s'", step.Type)
		}

		// Execute the step
		result, err := handler(step, workflow.Variables)
		if err != nil {
			return fmt.Errorf("error executing step '%s': %w", step.Name, err)
		}

		// Update the workflow variables with the result
		if result != nil {
			for k, v := range result {
				workflow.Variables[k] = v
			}
		}

		logger.LogInfo(fmt.Sprintf("Completed step %d/%d: %s", i+1, len(workflow.Steps), step.Name), nil)
	}

	logger.LogInfo("Workflow execution completed successfully", map[string]interface{}{
		"workflow": workflow.Name,
	})

	return nil
}
