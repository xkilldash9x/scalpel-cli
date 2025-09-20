package stealth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestApplyStealthEvasions verifies that browser properties are correctly spoofed.
func TestApplyStealthEvasions(t *testing.T) {
	// Create a new sandboxed browser instance for this test.
	// We start with a parent context for the entire test's duration.
	testCtx, testCancel := context.WithCancel(context.Background())
	defer testCancel()

	// Create an allocator, which manages the browser process.
	allocatorCtx, allocatorCancel := chromedp.NewExecAllocator(testCtx, chromedp.DefaultExecAllocatorOptions[:]...)
	defer allocatorCancel()

	// Now create a browser context (a tab) from the allocator.
	ctx, cancel := chromedp.NewContext(allocatorCtx)
	defer cancel()

	// 1. Define a specific, non-default persona for the test.
	testPersona := schemas.Persona{
		UserAgent: "Mozilla/5.0 (Scalpel Test Environment) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36",
		Platform:  "TestOS",
		Languages: []string{"test-LA", "test"},
		Width:     800,
		Height:    600,
		Mobile:    false,
	}

	// 2. Setup a simple test server that serves a script to report browser properties.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `
			<html><body>
			<script>
				const properties = {
					userAgent: navigator.userAgent,
					platform: navigator.platform,
					webdriver: navigator.webdriver,
					languages: navigator.languages,
				};
				// Expose the results on the window object for easy access.
				window.fingerprint = properties;
			</script>
			</body></html>
		`)
	}))
	defer server.Close()

	// 3. Apply the stealth evasions (this is what we are testing).
	err := Apply(testPersona, zap.NewNop()).Do(ctx)
	require.NoError(t, err, "Applying stealth evasions should not fail")

	// 4. Navigate to the page and evaluate the results.
	var fingerprint map[string]interface{}
	err = chromedp.Run(ctx,
		chromedp.Navigate(server.URL),
		// Wait for the script to execute and set the window.fingerprint object.
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`window.fingerprint`, &fingerprint),
	)
	require.NoError(t, err, "Chromedp run failed")
	require.NotNil(t, fingerprint, "Fingerprint object should be populated by the page script")

	// 5. Assert that the properties were successfully spoofed.
	assert.Equal(t, testPersona.UserAgent, fingerprint["userAgent"], "UserAgent was not spoofed correctly")
	assert.Equal(t, testPersona.Platform, fingerprint["platform"], "Platform was not spoofed correctly")
	assert.False(t, fingerprint["webdriver"].(bool), "navigator.webdriver should be false")

	// The 'languages' property is returned as a slice of interfaces.
	langSlice, ok := fingerprint["languages"].([]interface{})
	require.True(t, ok, "Languages should be a slice")
	// Convert back to []string for comparison.
	actualLangs := make([]string, len(langSlice))
	for i, v := range langSlice {
		actualLangs[i] = v.(string)
	}
	assert.Equal(t, testPersona.Languages, actualLangs, "Languages were not spoofed correctly")
}