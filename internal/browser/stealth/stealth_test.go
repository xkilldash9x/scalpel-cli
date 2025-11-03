package stealth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// setupBrowserContext creates a reusable browser context for tests.
// It is used by both stealth_test.go and js_test.go.
func setupBrowserContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()

	// Set a timeout for the entire test duration
	testCtx, testCancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Create an allocator, which manages the browser process.
	allocatorCtx, allocatorCancel := chromedp.NewExecAllocator(testCtx, chromedp.DefaultExecAllocatorOptions[:]...)

	// Now create a browser context (a tab) from the allocator.
	ctx, cancel := chromedp.NewContext(allocatorCtx)

	// CRITICAL: Ensure the browser process is running and the connection is established
	// before returning the context. This initializes the context so it is ready for use.
	if err := chromedp.Run(ctx); err != nil {
		cancel()
		allocatorCancel()
		testCancel()
		t.Fatal("Failed to initialize browser context:", err)
	}

	// Combine all cleanup functions
	cleanup := func() {
		cancel()
		allocatorCancel()
		testCancel()
	}

	return ctx, cleanup
}

// setupTestServer creates a server that reports browser properties via window.fingerprint.
func setupTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `
			<html><body>
			<script>
				// Collect various properties spoofed by the evasions
				window.fingerprint = {
					userAgent: navigator.userAgent,
                    appVersion: navigator.appVersion,
					platform: navigator.platform,
					webdriver: navigator.webdriver,
					languages: navigator.languages,
                    language: navigator.language,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    locale: Intl.DateTimeFormat().resolvedOptions().locale,
                    screenWidth: screen.width,
                    screenHeight: screen.height,
                    colorDepth: screen.colorDepth,
                    devicePixelRatio: window.devicePixelRatio,
                    hasChrome: window.chrome !== undefined,
                    // Check advanced masking
                    permissionsQueryToString: (navigator.permissions && navigator.permissions.query) ? navigator.permissions.query.toString() : 'N/A',
				};
			</script>
			</body></html>
		`)
	}))
}

// TestApplyStealthEvasions_Integration (Integration Test) verifies that browser properties are correctly spoofed.
func TestApplyStealthEvasions_Integration(t *testing.T) {
	ctx, cancel := setupBrowserContext(t)
	defer cancel()

	server := setupTestServer()
	defer server.Close()

	// 1. Define a comprehensive persona for the test.
	testPersona := schemas.Persona{
		UserAgent:  "Mozilla/5.0 (Scalpel Test Environment) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36",
		Platform:   "TestOS",
		Languages:  []string{"test-LA", "test"},
		Timezone:   "America/New_York",
		Locale:     "test-LA",
		Width:      1024,
		Height:     768,
		PixelDepth: 2, // This is treated as DPR (Device Pixel Ratio)
		ColorDepth: 24,
		Mobile:     false,
	}

	// 2. Apply the stealth evasions.
	err := ApplyStealthEvasions(ctx, testPersona, zap.NewNop())
	require.NoError(t, err, "Applying stealth evasions should not fail")

	// 3. Navigate to the page and evaluate the results.
	var fingerprint map[string]interface{}
	err = chromedp.Run(ctx,
		chromedp.Navigate(server.URL),
		// Wait for the script to execute and set the window.fingerprint object.
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`window.fingerprint`, &fingerprint),
	)
	require.NoError(t, err, "Chromedp run failed")
	require.NotNil(t, fingerprint, "Fingerprint object should be populated by the page script")

	// 4. Assertions
	t.Run("Navigator Properties", func(t *testing.T) {
		assert.Equal(t, testPersona.UserAgent, fingerprint["userAgent"], "UserAgent was not spoofed correctly")
		// Check appVersion (Robustness improvement)
		expectedAppVersion := strings.TrimPrefix(testPersona.UserAgent, "Mozilla/")
		assert.Equal(t, expectedAppVersion, fingerprint["appVersion"], "appVersion was not spoofed correctly")
		assert.Equal(t, testPersona.Platform, fingerprint["platform"], "Platform was not spoofed correctly")

		// Languages assertion
		langSlice, ok := fingerprint["languages"].([]interface{})
		require.True(t, ok, "Languages should be a slice")
		actualLangs := make([]string, len(langSlice))
		for i, v := range langSlice {
			actualLangs[i] = v.(string)
		}
		assert.Equal(t, testPersona.Languages, actualLangs, "Languages array were not spoofed correctly")
		assert.Equal(t, testPersona.Languages[0], fingerprint["language"], "Primary language was not spoofed correctly")
	})

	t.Run("JS Evasions", func(t *testing.T) {
		assert.False(t, fingerprint["webdriver"].(bool), "navigator.webdriver should be false")
		assert.True(t, fingerprint["hasChrome"].(bool), "window.chrome should be defined")
		// Check advanced masking
		assert.Equal(t, "function query() { [native code] }", fingerprint["permissionsQueryToString"], "Permissions API masking failed")
	})

	t.Run("Environment and Metrics", func(t *testing.T) {
		assert.Equal(t, testPersona.Timezone, fingerprint["timezone"], "Timezone was not spoofed correctly")
		// Locale assertion: Browser might normalize the locale string.
		assert.True(t, strings.EqualFold(fingerprint["locale"].(string), testPersona.Locale) || strings.EqualFold(fingerprint["locale"].(string), testPersona.Languages[0]), "Locale was not spoofed correctly")

		// CDP overrides and JS evasions should work together.
		assert.Equal(t, float64(testPersona.Width), fingerprint["screenWidth"], "Screen Width mismatch")
		assert.Equal(t, float64(testPersona.Height), fingerprint["screenHeight"], "Screen Height mismatch")
		assert.Equal(t, float64(testPersona.ColorDepth), fingerprint["colorDepth"], "Color Depth mismatch")

		// Check DPR (Device Pixel Ratio)
		expectedDPR := float64(testPersona.PixelDepth)
		assert.Equal(t, expectedDPR, fingerprint["devicePixelRatio"], "Device Pixel Ratio mismatch")
	})
}

// TestUnit_CreateDeviceMetricsAction (Unit Test) verifies the orientation and DPR logic, including clamping.
func TestUnit_CreateDeviceMetricsAction(t *testing.T) {
	logger := zap.NewNop() // Use Nop logger for unit tests

	tests := []struct {
		name        string
		persona     schemas.Persona
		expectedDPR float64
		expectedOri emulation.OrientationType
	}{
		{
			name: "Landscape Default DPR",
			persona: schemas.Persona{
				Width: 800, Height: 600, Mobile: false,
			},
			expectedDPR: 1.0,
			expectedOri: emulation.OrientationTypeLandscapePrimary,
		},
		{
			name: "Portrait Mobile Custom DPR",
			persona: schemas.Persona{
				Width: 600, Height: 800, Mobile: true, PixelDepth: 3,
			},
			expectedDPR: 3.0,
			expectedOri: emulation.OrientationTypePortraitPrimary,
		},
		{
			name: "Landscape Mobile Zero DPR (should default to 1.0)",
			persona: schemas.Persona{
				Width: 800, Height: 600, Mobile: true, PixelDepth: 0,
			},
			expectedDPR: 1.0,
			expectedOri: emulation.OrientationTypeLandscapePrimary,
		},
		{
			name: "DPR Clamping (Robustness)",
			persona: schemas.Persona{
				Width: 800, Height: 600, PixelDepth: 24, // Mistakenly using color depth
			},
			expectedDPR: MaxDPR, // Clamped to the max defined in stealth.go
			expectedOri: emulation.OrientationTypeLandscapePrimary,
		},
		{
			name: "Negative DPR (Robustness)",
			persona: schemas.Persona{
				Width: 800, Height: 600, PixelDepth: -1,
			},
			expectedDPR: DefaultDPR, // Reset to default
			expectedOri: emulation.OrientationTypeLandscapePrimary,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pass logger to the function
			action := createDeviceMetricsAction(tt.persona, logger)
			require.NotNil(t, action)

			// We need to assert the internal structure of the generated action.
			metrics, ok := action.(*emulation.SetDeviceMetricsOverrideParams)
			require.True(t, ok, "Action should be of type SetDeviceMetricsOverrideParams")

			assert.Equal(t, tt.persona.Width, metrics.Width)
			assert.Equal(t, tt.persona.Height, metrics.Height)
			assert.Equal(t, tt.persona.Mobile, metrics.Mobile)
			assert.Equal(t, tt.expectedDPR, metrics.DeviceScaleFactor, "DPR mismatch")

			require.NotNil(t, metrics.ScreenOrientation, "ScreenOrientation should be set")
			assert.Equal(t, tt.expectedOri, metrics.ScreenOrientation.Type, "Orientation mismatch")
		})
	}
}

// TestApply_EmptyPersona (Integration Test) ensures that Apply handles an empty persona and applies defaults.
func TestApply_EmptyPersona(t *testing.T) {
	ctx, cancel := setupBrowserContext(t)
	defer cancel()

	persona := schemas.Persona{} // Empty persona

	// We expect Apply to succeed and use the defaults.
	// We also test the nil logger path implicitly here.
	err := ApplyStealthEvasions(ctx, persona, nil)
	require.NoError(t, err)

	// Verify that defaults were applied
	var fingerprint map[string]interface{}
	err = chromedp.Run(ctx,
		// Navigate again to ensure evasions apply to the new document
		chromedp.Navigate("about:blank"),
		chromedp.Evaluate(`({ua: navigator.userAgent, platform: navigator.platform, langs: navigator.languages, lang: navigator.language})`, &fingerprint),
	)
	require.NoError(t, err)

	ua := fingerprint["ua"].(string)
	assert.NotEmpty(t, ua)
	assert.NotContains(t, ua, "HeadlessChrome", "UserAgent should be overridden from the headless default")
	assert.Equal(t, DefaultPlatform, fingerprint["platform"], "Platform should use default")

	// Check languages default
	langSlice := fingerprint["langs"].([]interface{})
	require.NotEmpty(t, langSlice)
	assert.Equal(t, DefaultLanguages[0], langSlice[0].(string))

	// Check locale fallback (navigator.language)
	assert.Equal(t, DefaultLanguages[0], fingerprint["lang"], "navigator.language should default to primary language")
}

// TestApply_NilLogger (Unit Test) ensures no panic occurs if a nil logger is passed.
func TestApply_NilLogger(t *testing.T) {
	persona := schemas.Persona{UserAgent: "Test"}
	assert.NotPanics(t, func() {
		tasks := Apply(persona, nil)
		assert.NotEmpty(t, tasks, "Tasks should be generated even with nil logger")
	})
}
