// pkg/browser/shim/embed.go
package shim

import (
	_ "embed"
	"fmt"
)

//go:embed taint_shim.js
var taintShimTemplate string

// GetTaintShimTemplate returns the content of the embedded taint_shim.js file template.
// Renamed from GetTaintShim for clarity.
func GetTaintShimTemplate() (string, error) {
	if taintShimTemplate == "" {
		return "", fmt.Errorf("embedded taint_shim.js template is empty or failed to load")
	}
	return taintShimTemplate, nil
}
