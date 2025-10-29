// internal/analysis/active/timeslip/types_test.go
package timeslip

import (
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
		assert.True(t, excludeMap["Date"], "Date should be excluded by default")
		assert.True(t, excludeMap["Etag"], "Etag should be excluded by default")
		assert.True(t, excludeMap["Content-Length"], "Content-Length should be excluded by default")

		// Check a header that should NOT be excluded
		assert.False(t, excludeMap["Content-Type"], "Content-Type should NOT be excluded by default")

		// Sanity check on the number of defaults
		assert.Greater(t, len(excludeMap), 10, "Should have many default exclusions")
	})

	t.Run("With Custom Exclusions and Canonicalization", func(t *testing.T) {
		config := &Config{
			// Provide custom headers with mixed casing
			ExcludeHeadersFromFingerprint: []string{"X-Custom-Header", "authorization", "another-one"},
		}
		excludeMap := config.GetExcludedHeaders()

		// Check defaults still exist
		assert.True(t, excludeMap["Date"], "Date should still be excluded")

		// Check custom headers (must be stored in Canonical format)
		assert.True(t, excludeMap["X-Custom-Header"], "X-Custom-Header should be excluded")
		assert.True(t, excludeMap[http.CanonicalHeaderKey("authorization")], "Authorization should be excluded")
		assert.True(t, excludeMap["Another-One"], "Another-One should be excluded (Canonicalized)")
	})

	t.Run("Lazy Initialization Behavior", func(t *testing.T) {
		config := &Config{}
		// The internal map should be nil before the first call
		assert.Nil(t, config.excludeHeadersMap)

		config.GetExcludedHeaders()
		assert.NotNil(t, config.excludeHeadersMap, "Map should be initialized after GetExcludedHeaders")

		// Ensure subsequent calls don't re-initialize or change the map address if config hasn't changed
		firstMap := config.excludeHeadersMap
		config.GetExcludedHeaders()
		assert.Same(t, firstMap, config.excludeHeadersMap, "Map pointer should remain the same on subsequent calls")
	})
}
