// internal/analysis/active/timeslip/types_test.go
package timeslip

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfig_InitializeAndGetExcludedHeaders validates the logic for merging
// default header exclusions with user-provided ones, including canonicalization.
func TestConfig_InitializeAndGetExcludedHeaders(t *testing.T) {
	t.Run("Defaults Only", func(t *testing.T) {
		config := &Config{}
		// Trigger lazy initialization via GetExcludedHeaders
		excludeMap := config.GetExcludedHeaders()

		assert.NotNil(t, excludeMap)
		// Check specific defaults (keys must be canonical)
		assert.True(t, excludeMap["Date"])
		assert.True(t, excludeMap["Etag"])
		assert.True(t, excludeMap["Content-Length"])

		// Check a header that should NOT be excluded
		assert.False(t, excludeMap["Content-Type"])
	})

	t.Run("With Custom Exclusions and Canonicalization", func(t *testing.T) {
		config := &Config{
			// Provide custom headers with mixed casing
			ExcludeHeadersFromFingerprint: []string{"X-Custom-Header", "authorization", "another-one"},
		}
		excludeMap := config.GetExcludedHeaders()

		// Check defaults still exist
		assert.True(t, excludeMap["Date"])

		// Check custom headers (must be stored in Canonical format)
		assert.True(t, excludeMap["X-Custom-Header"])
		assert.True(t, excludeMap[http.CanonicalHeaderKey("authorization")])
		assert.True(t, excludeMap["Another-One"])
	})

	t.Run("Lazy Initialization Behavior", func(t *testing.T) {
		config := &Config{}
		// The internal map should be nil before the first call
		assert.Nil(t, config.excludeHeadersMap)

		config.GetExcludedHeaders()
		assert.NotNil(t, config.excludeHeadersMap, "Map should be initialized after GetExcludedHeaders")

		// Ensure subsequent calls don't re-initialize or change the map address
		firstMap := config.excludeHeadersMap
		config.GetExcludedHeaders()
		// Correctly assert that the map pointer itself is the same.
		assert.Equal(t, fmt.Sprintf("%p", firstMap), fmt.Sprintf("%p", config.excludeHeadersMap), "Map pointer should remain the same on subsequent calls.")
	})
}
