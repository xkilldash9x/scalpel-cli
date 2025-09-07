// ./main.go
package main

import (
	"github.com/xkilldash9x/scalpel-cli/cmd"
)

// main is the entry point for the Scalpel CLI application.
func main() {
	// Execute the root command defined in the cmd package.
	// This handles all command-line parsing, configuration, and execution.
	cmd.Execute()
}
