// File: cmd/version.go
package cmd

// Version holds the current version of the Scalpel CLI application.
// This variable is typically set at build time using ldflags to inject
// version information dynamically. For example:
// go build -ldflags "-X github.com/xkilldash9x/scalpel-cli/cmd.Version=1.2.3"
var Version = "Alpha"