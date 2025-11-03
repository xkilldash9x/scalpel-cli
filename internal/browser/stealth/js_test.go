// internal/browser/stealth/js_test.go
package stealth

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

//go:embed evasions.test.js
var EvasionsTestJS string

// TestJavascriptEvasions runs the embedded JavaScript unit tests within a browser context.
func TestJavascriptEvasions(t *testing.T) {
	// 1. Setup Browser Context (using the helper defined in stealth_test.go)
	ctx, cancel := setupBrowserContext(t)
	defer cancel()

	// 2. Define the Persona specifically for the JS tests
	// We use distinct values to ensure the overrides are working.
	testPersona := schemas.Persona{
		UserAgent:     "Mozilla/5.0 (ScalpelJSTest/1.0)",
		Platform:      "JSTestOS",
		Languages:     []string{"js-TEST", "js"},
		Width:         1280,
		Height:        720,
		AvailWidth:    1280,
		AvailHeight:   700, // Slightly less than height
		ColorDepth:    32,  // Used for screen.colorDepth/pixelDepth in JS
		PixelDepth:    2,   // Used for Device Pixel Ratio (DPR) in CDP
		Mobile:        false,
		WebGLVendor:   "Test Vendor",
		WebGLRenderer: "Test Renderer",
	}

	// 3. Apply Evasions (This injects EvasionsJS and the Persona data via EvaluateOnNewDocument)
	// FIX: We must use chromedp.Run() instead of Tasks.Do(). Apply() returns low-level CDP actions
	// which require the context handled by the chromedp runner to access the browser executor.
	// Tasks.Do() bypasses this, causing "invalid context".
	err := chromedp.Run(ctx, Apply(testPersona, nil))
	require.NoError(t, err, "Applying stealth evasions failed")

	// 4. Setup Test Server
	// The server serves a blank page where we can run the tests.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><h1>Running JS Evasion Tests...</h1></body></html>`)
	}))
	defer server.Close()

	// 5. Navigate, Inject Test Runner, and Retrieve Results
	var rawResults interface{}
	err = chromedp.Run(ctx,
		chromedp.Navigate(server.URL),
		chromedp.WaitVisible("body"),
		// Inject the test runner script (evasions_test.js)
		chromedp.Evaluate(EvasionsTestJS, nil),
		// Wait for the tests to complete (they run asynchronously in the JS)
		// We use chromedp.Poll to wait robustly for the results variable to be set.
		chromedp.Poll(`window.SCALPEL_TEST_RESULTS`, &rawResults, chromedp.WithPollingTimeout(10*time.Second)),
	)
	require.NoError(t, err, "Chromedp run for JS tests failed or timed out waiting for results")
	require.NotNil(t, rawResults, "JS Test results should not be nil")

	// 6. Process Results
	// Convert the raw interface{} result into a structured format for analysis.
	resultsJSON, err := json.Marshal(rawResults)
	require.NoError(t, err, "Failed to marshal raw results")

	// Capture stack trace for better debugging
	type TestResult struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
		Stack  string `json:"stack,omitempty"`
	}
	var results []TestResult
	err = json.Unmarshal(resultsJSON, &results)
	require.NoError(t, err, "Failed to unmarshal test results")

	require.NotEmpty(t, results, "Should have received test results")

	// 7. Report Results
	failed := false
	t.Log("--- JavaScript Evasion Test Results (In-Browser) ---")
	for _, result := range results {
		if result.Status == "FAIL" {
			failed = true
			t.Errorf("FAIL: %s\n    Error: %s\n    Stack (JS):\n%s", result.Name, result.Error, result.Stack)
		} else {
			t.Logf("PASS: %s", result.Name)
		}
	}
	t.Log("----------------------------------------------------")

	assert.False(t, failed, "Some JavaScript evasion tests failed. Check logs above.")
}
