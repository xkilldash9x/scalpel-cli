// File: cmd/mcp/main.go
// This is the main entrypoint for the standalone MCP server application.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/xkilldash9x/scalpel-cli/internal/mcp"
)

func main() {
	// Define command-line flags
	port := flag.Int("port", 8080, "Port for the MCP server to listen on")
	// Default to localhost (127.0.0.1) for security, as this is intended as a local bridge.
	host := flag.String("host", "127.0.0.1", "Host address for the MCP server to listen on (use 0.0.0.0 for all interfaces)")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

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
	if err := server.Start(addr); err != nil {
		// The server handles internal logging, but we exit with a non-zero status if it stops unexpectedly.
		os.Exit(1)
	}
}
