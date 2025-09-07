// -- pkg/reporting/reporter.go --
package reporting

import (
	"fmt"
	"io"
	"os"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Reporter defines the interface for writing scan results to an output.
type Reporter interface {
	// Write processes a single result envelope.
	Write(result *schemas.ResultEnvelope) error
	// Close finalizes the report and closes any underlying resources (e.g., file handles).
	Close() error
}

// nopWriteCloser wraps an io.Writer and provides a no-op Close method.
type nopWriteCloser struct {
	io.Writer
}

func (nwc *nopWriteCloser) Close() error {
	return nil
}

// New creates a new reporter based on the specified format and output path.
func New(format, outputPath string) (Reporter, error) {
	var writer io.WriteCloser // Use interface type
	isStdOut := outputPath == "" || outputPath == "stdout"

	if isStdOut {
		// Wrap Stdout so Close() is a no-op.
		writer = &nopWriteCloser{os.Stdout}
	} else {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file %s: %w", outputPath, err)
		}
		writer = f
	}

	// Helper function to close the writer if it's a file and an error occurs.
	cleanup := func() {
		if !isStdOut {
			writer.Close()
		}
	}

	switch format {
	case "sarif":
		// NewSARIFReporter takes ownership of the writer.
		return NewSARIFReporter(writer), nil
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