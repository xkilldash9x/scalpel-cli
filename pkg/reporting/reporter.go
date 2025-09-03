package reporting

import (
	"fmt"
	"os"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// Reporter defines the interface for writing scan results to an output.
type Reporter interface {
	// Write processes a single result envelope.
	Write(result *schemas.ResultEnvelope) error
	// Close finalizes the report and closes any underlying resources (e.g., file handles).
	Close() error
}

// New creates a new reporter based on the specified format and output path.
func New(format, outputPath string) (Reporter, error) {
	var writer *os.File
	if outputPath == "" |

| outputPath == "stdout" {
		writer = os.Stdout
	} else {
		f, err := os.Create(outputPath)
		if err!= nil {
			return nil, fmt.Errorf("failed to create output file %s: %w", outputPath, err)
		}
		writer = f
	}

	switch format {
	case "sarif":
		return NewSARIFReporter(writer), nil
	case "json":
		// Placeholder for a future JSON reporter
		return nil, fmt.Errorf("json reporter not yet implemented")
	case "text":
		// Placeholder for a future text reporter
		return nil, fmt.Errorf("text reporter not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}
