package composition

// Workflow represents the entire composition workflow
type Workflow struct {
	// Name of the workflow (required)
	Name string `mapstructure:"name"`

	// Optional description of the workflow
	Description string `mapstructure:"description,omitempty"`

	// Version of the workflow definition
	Version string `mapstructure:"version,omitempty"`

	// Author or creator of the workflow
	Author string `mapstructure:"author,omitempty"`

	// Ordered list of steps to execute
	Steps []Step `mapstructure:"steps"`

	// Variables that can be referenced in step parameters
	Variables map[string]interface{} `mapstructure:"variables,omitempty"`
}

// Step represents a single step in the composition workflow
type Step struct {
	// Unique name for the step (required)
	Name string `mapstructure:"name"`

	// Type of operation to perform (required)
	Type string `mapstructure:"type"`

	// Optional human-readable description of the step
	Description string `mapstructure:"description,omitempty"`

	// Optional conditional execution expression
	Condition string `mapstructure:"condition,omitempty"`

	// Flexible parameters for the step
	// Uses ",remain" to capture all additional parameters
	Parameters map[string]interface{} `mapstructure:",remain"`
}
