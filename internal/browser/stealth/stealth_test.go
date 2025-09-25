// internal/browser/stealth/stealth_test.go
package stealth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// Import the package under test.
	. "github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
)

const stealthTestTimeout = 60 * time.Second

// SetupPlaywrightTest initializes a Playwright instance and Browser for testing.
// This is a standalone setup utility specifically for the stealth package tests, ensuring isolation.
func SetupPlaywrightTest(t *testing.T) (*playwright.Playwright, playwright.Browser) {
	t.Helper()

	// Ensure installation (important for CI/CD).
	// Use a reasonable timeout for installation.
	installCtx, installCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer installCancel()

	installDone := make(chan error, 1)
	go func() {
		// Install specific browser for consistency.
		installDone <- playwright.Install(&playwright.RunOptions{Browsers: []string{"chromium"}})
	}()

	select {
	case err := <-installDone:
		require.NoError(t, err, "Failed to install Playwright browsers")
	case <-installCtx.Done():
		t.Fatal("Timeout waiting for Playwright installation")
	}

	pw, err := playwright.Run()
	require.NoError(t, err, "Failed to start Playwright driver")

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	require.NoError(t, err, "Failed to launch browser")

	t.Cleanup(func() {
		// Use a background context for cleanup.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		browser.Close(cleanupCtx)
		pw.Stop(cleanupCtx)
	})

	return pw, browser
}

// TestApplyEvasions verifies that browser properties are correctly spoofed using JS injection.
func TestApplyEvasions(t *testing.T) {
	pw, browser := SetupPlaywrightTest(t)
	_ = pw // pw is used during setup/cleanup.

	// 1. Define a specific persona for the test.
	testPersona := schemas.Persona{
		// Note: UserAgent, Platform, and Languages must also be set in ContextOptions for full stealth.
		UserAgent: "Mozilla/5.0 (Scalpel Stealth Test) Chrome/99.0.0.0",
		Platform:  "TestOS",
		Languages: []string{"test-LA", "test"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), stealthTestTimeout)
	defer cancel()

	// 2. Create a new context with the required base options.
	contextOptions := playwright.BrowserNewContextOptions{
		UserAgent: playwright.String(testPersona.UserAgent),
		Locale:    playwright.String(testPersona.Languages[0]),
	}
	pwContext, err := browser.NewContext(ctx, contextOptions)
	require.NoError(t, err, "Failed to create browser context")
	defer pwContext.Close(context.Background())

	// 3. Apply the stealth evasions (This is what we are testing).
	// We pass the context 'ctx' to ApplyEvasions.
	err = ApplyEvasions(ctx, pwContext, testPersona, zap.NewNop())
	require.NoError(t, err, "Applying stealth evasions should not fail")

	// 4. Setup a simple test server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a script that captures the fingerprint after the evasions have run.
		fmt.Fprint(w, `
            <html><body>
            <script>
                window.fingerprint = {
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    webdriver: navigator.webdriver,
                    languages: navigator.languages,
					hasChrome: window.chrome !== undefined,
                };
            </script>
            </body></html>
        `)
	}))
	defer server.Close()

	// 5. Navigate and evaluate the results.
	page, err := pwContext.NewPage(ctx)
	require.NoError(t, err, "Failed to create page")

	_, err = page.Goto(ctx, server.URL, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilLoad})
	require.NoError(t, err, "Navigation failed")

	// Evaluate the captured fingerprint.
	result, err := page.Evaluate(ctx, "window.fingerprint")
	require.NoError(t, err, "Evaluation failed")

	fingerprint, ok := result.(map[string]interface{})
	require.True(t, ok, "Fingerprint result should be a map")

	// 6. Assertions.

	// Crucial test: navigator.webdriver must be false.
	assert.False(t, fingerprint["webdriver"].(bool), "navigator.webdriver should be spoofed to false")

	// Verify persona properties are correctly reflected in the JS environment.
	assert.Equal(t, testPersona.UserAgent, fingerprint["userAgent"], "UserAgent mismatch")
	// Platform spoofing relies on the JS injection aligning with the persona data.
	assert.Equal(t, testPersona.Platform, fingerprint["platform"], "Platform mismatch")

	// Languages check.
	langSlice, ok := fingerprint["languages"].([]interface{})
	require.True(t, ok, "Languages should be a slice")
	actualLangs := make([]string, len(langSlice))
	for i, v := range langSlice {
		actualLangs[i] = v.(string)
	}
	assert.Equal(t, testPersona.Languages, actualLangs, "Languages mismatch")

	// Check for window.chrome presence.
	assert.True(t, fingerprint["hasChrome"].(bool), "window.chrome should be defined")
}