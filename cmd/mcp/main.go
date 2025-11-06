// File: cmd/mcp/main.go
// This is the main entrypoint for the standalone MCP server application.
package main

import (
	// "flag" // Removed: Flags were not used by the server config
	// "fmt"  // Removed: 'addr' variable is no longer built
	"log"
	"os"

	"github.com/xkilldash9x/scalpel-cli/internal/mcp"
)

func main() {
	// Command-line flags (port, host) were removed as they were
	// not being used by mcp.NewServer(), which loads its own
	// configuration from environment variables or config files.
	//
	// The 'addr' variable previously here was removed as it was
	// unused and caused a compile error.

	// Initialize the server and its dependencies (Config, DB, Logger)
	// This will attempt to connect to the database using environment variables (e.g., SCALPEL_DATABASE_URL)
	// or configuration files, mirroring the behavior of the main CLI tool.
	// The server now also initializes the core persistent Agent instance.
	server, err := mcp.NewServer()
	if err != nil {
		// Use standard log for fatal errors during initialization, as the structured logger might not be ready.
		log.Printf("Failed to initialize MCP server: %v\n", err)
		log.Println("Ensure SCALPEL_DATABASE_URL is set (or config file is present) and the database is running.")
		// External scan orchestration via binary is no longer the primary method.
		os.Exit(1)
	}

	// Start the server. This function blocks until the server is shut down (e.g., Ctrl+C).
	// It uses the address defined in the server's internal configuration.
	if err := server.Start(); err != nil {
		// The server handles internal logging, but we exit with a non-zero status if it stops unexpectedly.
		os.Exit(1)
	}
}
