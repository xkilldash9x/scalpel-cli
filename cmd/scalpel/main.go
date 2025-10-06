// File: main.go

/*
Copyright © 2025 Kyle McAllister (xkilldash9x@proton.me)
*/

package main

import (
    "context"
    "os"
    "os/signal"
    "syscall"

    "github.com/xkilldash9x/scalpel-cli/cmd"
)

// main is the entry point of the application.
func main() {
    // Set up a context that listens for interrupt signals (SIGINT, SIGTERM) for graceful shutdown.
    // This context is passed down through the command execution chain.
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    // Execute the root command with the signal-aware context.
    if err := cmd.Execute(ctx); err != nil {
        // Error logging is handled within the cmd package.
        // Ensure a non-zero exit code on failure.
        os.Exit(1)
    }
}