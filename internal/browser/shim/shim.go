// internal/browser/shim/shim.go
package shim

import (
	"fmt"
	"strings"
)

const (
	// ConfigPlaceholder is the string replaced in the JS template with the actual JSON configuration.
	ConfigPlaceholder = "/*{{SCALPEL_SINKS_CONFIG}}*/"
)

// BuildTaintShim injects the configuration into the template.
func BuildTaintShim(template, configJSON string) (string, error) {
	if template == "" {
		return "", fmt.Errorf("template is empty")
	}

	if !strings.Contains(template, ConfigPlaceholder) {
		return "", fmt.Errorf("template does not contain the required placeholder: %s", ConfigPlaceholder)
	}

	// Basic validation that configJSON is not empty.
	if configJSON == "" || configJSON == "[]" {
		// If configuration is empty, we still inject an empty array to ensure the JS runs safely.
		configJSON = "[]"
	}

	script := strings.Replace(template, ConfigPlaceholder, configJSON, 1)
	return script, nil
}
