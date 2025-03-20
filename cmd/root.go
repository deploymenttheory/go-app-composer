package cmd

import (
	"fmt"

	"github.com/deploymenttheory/go-app-composer/internal/composition"
	"github.com/deploymenttheory/go-app-composer/internal/config"
	"github.com/deploymenttheory/go-app-composer/internal/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var workflowFile string

// rootCmd represents the base CLI command
var rootCmd = &cobra.Command{
	Use:   "go-app-composer",
	Short: "A CLI tool for handling app packages",
	Long: `go-app-composer is a command line tool designed to simplify the
packaging and distribution of applications across different platforms
and mobile device management (MDM) systems.

It supports various packaging formats and can integrate with MDM systems
like Jamf Pro, Microsoft Intune, Mosyle, and others.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// CLI flags can override config settings
		debug, _ := cmd.Flags().GetBool("debug")
		logFormat, _ := cmd.Flags().GetString("log-format")

		// If CLI flags were explicitly provided, update the global config
		if cmd.Flags().Changed("debug") {
			config.Instance.Debug = debug
		}

		if cmd.Flags().Changed("log-format") {
			config.Instance.LogFormat = logFormat
		}

		// If config file was explicitly specified via flag, reinitialize
		if cmd.Flags().Changed("config") && cfgFile != "" {
			// Only log an error, don't exit, as the config may still be usable
			if err := config.Initialize(cfgFile); err != nil {
				logger.LogError("Error loading config file", err, map[string]interface{}{
					"config_file": cfgFile,
				})
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		// If workflow is specified, execute it
		if workflowFile != "" {
			executeWorkflow(workflowFile)
			return
		}

		// Otherwise show help
		cmd.Help()
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger.LogError("Command execution failed", err, nil)
		// Let Cobra handle the exit
	}
}

func init() {
	// Config file flag
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is search in standard locations)")

	// Workflow file flag
	rootCmd.PersistentFlags().StringVarP(&workflowFile, "workflow", "w", "", "workflow file to execute")

	// Debug flag
	rootCmd.PersistentFlags().Bool("debug", config.Instance.Debug, "Enable debug logging")

	// Log format flag
	rootCmd.PersistentFlags().String("log-format", config.Instance.LogFormat, "Log format: json or human")

	// MDM provider flag
	rootCmd.PersistentFlags().String("mdm-provider", config.Instance.MDM.Provider, "MDM provider to use")

	// Storage provider flag
	rootCmd.PersistentFlags().String("storage-provider", config.Instance.Storage.Provider, "Storage provider to use")

	// Bind flags to viper settings
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("mdm.provider", rootCmd.PersistentFlags().Lookup("mdm-provider"))
	viper.BindPFlag("storage.provider", rootCmd.PersistentFlags().Lookup("storage-provider"))

	// Add version command
	rootCmd.AddCommand(versionCmd)
}

// executeWorkflow executes a workflow file
func executeWorkflow(file string) {
	logger.LogInfo("Executing workflow", map[string]interface{}{
		"file": file,
	})

	// Load the workflow
	workflow, err := composition.LoadWorkflow(file)
	if err != nil {
		logger.LogError("Failed to load workflow", err, map[string]interface{}{
			"file": file,
		})
		return
	}

	// Validate the workflow
	errors := composition.ValidateWorkflow(workflow)
	if len(errors) > 0 {
		// Log all validation errors
		for _, err := range errors {
			logger.LogError("Workflow validation error", err, nil)
		}
		logger.LogError("Workflow validation failed", fmt.Errorf("%d validation errors", len(errors)), nil)
		return
	}

	// Execute the workflow
	if err := composition.ExecuteWorkflow(workflow); err != nil {
		logger.LogError("Workflow execution failed", err, nil)
	}
}

// versionCmd shows the application version
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("go-app-composer v0.1.0") // Replace with actual version
	},
}
