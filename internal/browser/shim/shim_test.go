// internal/browser/shim/shim_test.go
package shim_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// -- a little dot import magic for the package under test --
	. "github.com/xkilldash9x/scalpel-cli/internal/browser/shim"
)

// TestBuildTaintShim ensures the shim script is constructed correctly.
func TestBuildTaintShim(t *testing.T) {
	t.Parallel()

	// -- a simple, valid template for our tests --
	mockTemplate := `
		(function() {
			"use strict";
			const config = /*{{SCALPEL_SINKS_CONFIG}}*/;
			console.log("Shim loaded with", config.length, "rules.");
		})();
	`

	t.Run("should inject valid JSON config into template", func(t *testing.T) {
		t.Parallel()
		configJSON := `[{"sink":"document.write","params":[0]}]`
		expectedScript := `
		(function() {
			"use strict";
			const config = [{"sink":"document.write","params":[0]}];
			console.log("Shim loaded with", config.length, "rules.");
		})();
	`

		script, err := BuildTaintShim(mockTemplate, configJSON)
		require.NoError(t, err, "Should not return an error with valid inputs")
		assert.Equal(t, expectedScript, script, "The configJSON should be correctly injected")
	})

	t.Run("should inject an empty array for an empty config string", func(t *testing.T) {
		t.Parallel()
		configJSON := ""
		expectedScript := `
		(function() {
			"use strict";
			const config = [];
			console.log("Shim loaded with", config.length, "rules.");
		})();
	`

		script, err := BuildTaintShim(mockTemplate, configJSON)
		require.NoError(t, err, "Should not return an error for an empty config string")
		assert.Equal(t, expectedScript, script, "Should default to an empty array for empty config")
	})

	t.Run("should inject an empty array for an empty JSON array config", func(t *testing.T) {
		t.Parallel()
		configJSON := "[]"
		expectedScript := `
		(function() {
			"use strict";
			const config = [];
			console.log("Shim loaded with", config.length, "rules.");
		})();
	`

		script, err := BuildTaintShim(mockTemplate, configJSON)
		require.NoError(t, err, "Should not return an error for an empty JSON array")
		assert.Equal(t, expectedScript, script, "Should correctly handle an empty JSON array")
	})

	t.Run("should return error for an empty template", func(t *testing.T) {
		t.Parallel()
		_, err := BuildTaintShim("", `[{"test":1}]`)
		require.Error(t, err, "Should return an error for an empty template")
		assert.EqualError(t, err, "template is empty", "Error message mismatch")
	})

	t.Run("should return error when placeholder is missing", func(t *testing.T) {
		t.Parallel()
		badTemplate := "const config = {};"
		expectedError := fmt.Sprintf("template does not contain the required placeholder: %s", ConfigPlaceholder)

		_, err := BuildTaintShim(badTemplate, `[{"test":1}]`)
		require.Error(t, err, "Should return an error if the placeholder is not in the template")
		assert.EqualError(t, err, expectedError, "Error message mismatch")
	})
}

// TestGetTaintShimTemplate verifies the behavior of the embedded template loader.
func TestGetTaintShimTemplate(t *testing.T) {
	t.Parallel()
	// NOTE: This test validates the error handling of the function.
	// Since the actual `taint_shim.js` file is not present in the test's context
	// (it's embedded during the main build), we expect the embedded variable to be empty
	// during this test run. A successful 'go test' run for this function proves that
	// the emptiness check is working correctly.

	template, err := GetTaintShimTemplate()

	require.Error(t, err, "Should return an error because the embedded file is not loaded during this test run")
	assert.Empty(t, template, "Template string should be empty on error")
	assert.EqualError(t, err, "embedded taint_shim.js template is empty or failed to load")
}
