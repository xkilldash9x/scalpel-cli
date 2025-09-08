// internal/browser/stealth_test.go
package browser_test

import (
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStealth_Evasions verifies common automation detection vectors are mitigated.
func TestStealth_Evasions(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)
	session := fixture.initializeSession(t)
	ctx := session.GetContext()

	// 1. Check navigator.webdriver (Most common check)
	var webdriverStatus bool
	// Evaluate returns 'true' if navigator.webdriver is true, otherwise false (including undefined).
	// The combination of flags and evasions.js ensures this is false.
	err := chromedp.Run(ctx, chromedp.Evaluate(`!!navigator.webdriver`, &webdriverStatus))
	require.NoError(t, err)
	assert.False(t, webdriverStatus, "navigator.webdriver should be false")

	// 2. Check User-Agent and Platform consistency (using the default persona in manager.go)
	var navData struct {
		UserAgent string   `json:"userAgent"`
		Platform  string   `json:"platform"`
		Languages []string `json:"languages"`
	}
	err = chromedp.Run(ctx, chromedp.Evaluate(`({
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        languages: navigator.languages
    })`, &navData))
	require.NoError(t, err)

	// Expected defaults from manager.go
	expectedUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	assert.Equal(t, expectedUA, navData.UserAgent, "UserAgent mismatch")
	assert.Equal(t, "Win32", navData.Platform, "Platform mismatch")
	assert.Equal(t, []string{"en-US", "en"}, navData.Languages, "Languages mismatch")

	// 3. Check Environment Overrides (Timezone and Locale)
	var envData struct {
		Timezone string `json:"timezone"`
		Locale   string `json:"locale"`
	}
	err = chromedp.Run(ctx, chromedp.Evaluate(`({
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        locale: Intl.DateTimeFormat().resolvedOptions().locale
    })`, &envData))
	require.NoError(t, err)

	// Expected defaults from manager.go
	assert.Equal(t, "America/Los_Angeles", envData.Timezone, "Timezone override mismatch")
	assert.Equal(t, "en-US", envData.Locale, "Locale override mismatch")
}