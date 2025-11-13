// internal/reporting/reporter.go
package reporting

import (
	"fmt"
	"io"
	"os"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// Reporter defines the interface for writing scan results to an output.
// Implementations must be thread-safe.
type Reporter interface {
	// Write processes a single result envelope.
	Write(result *schemas.ResultEnvelope) error
	// Close finalizes the report and closes any underlying resources (e.g., file handles).
	Close() error
}

//  wraps an io.Writer like os.Stdout and provides a no-op Close method.
// This prevents closing standard streams when the reporter attempts to close its writer.
type nopWriteCloser struct {
	io.Writer
}

// Close is a no-op for standard streams.
func (nwc *nopWriteCloser) Close() error {
	return nil
}

// New creates a new reporter based on the specified format and output path.
// The signature is updated to accept the toolVersion for dependency injection.
func New(format, outputPath, toolVersion string) (Reporter, error) {
	logger := observability.GetLogger()

	var writer io.WriteCloser // Use interface type
	isStdOut := outputPath == "" || outputPath == "stdout"

	if isStdOut {
		// Wrap Stdout so Close() is a no-op.
		writer = &nopWriteCloser{os.Stdout}
		logger.Debug("Configured reporter to write to stdout")
	} else {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file %s: %w", outputPath, err)
		}
		writer = f
		logger.Debug("Configured reporter to write to file", zap.String("path", outputPath))
	}

	// Helper function to close the writer if it's a file and an error occurs during initialization.
	cleanup := func() {
		if !isStdOut {
			if err := writer.Close(); err != nil {
				logger.Warn("Failed to close output file during cleanup", zap.Error(err))
			}
		}
	}

	switch format {
	case "sarif":
		// Pass the toolVersion down to the SARIF reporter's constructor.
		return NewSARIFReporter(writer, toolVersion), nil
	case "json":
		cleanup() // Close the file handle
		return nil, fmt.Errorf("json reporter not yet implemented")
	case "text":
		cleanup() // Close the file handle
		return nil, fmt.Errorf("text reporter not yet implemented")
	default:
		cleanup() // Close the file handle
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}
