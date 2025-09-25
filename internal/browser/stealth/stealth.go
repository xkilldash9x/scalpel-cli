// internal/browser/stealth/stealth.go
package stealth

import (
	_ "embed" // Import embed for go:embed directive
	"encoding/json"
	"fmt"

	"github.com/playwright-community/playwright-go"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// EvasionsJS holds the embedded JavaScript used for browser fingerprint evasion.
//go:embed evasions.js
var EvasionsJS string

// ApplyEvasions injects the stealth evasion scripts into the Playwright BrowserContext.
// This ensures that the evasions (like navigator.webdriver spoofing) are applied before any page scripts run.
// Note: Basic properties like UserAgent, Viewport, etc., must be set via BrowserNewContextOptions during context creation.
func ApplyEvasions(pwContext playwright.BrowserContext, persona schemas.Persona, logger *zap.Logger) error {
	if logger != nil {
		logger.Debug("Applying advanced stealth evasions (JS injection).")
	}

	if EvasionsJS == "" {
		if logger != nil {
			logger.Warn("EvasionsJS is empty. Stealth capabilities may be reduced.")
		}
		return nil
	}

	// 1. Prepare the persona data for injection.
	jsPersona := prepareJSPersona(persona)
	personaJSON, err := json.Marshal(jsPersona)
	if err != nil {
		return fmt.Errorf("failed to marshal persona for stealth injection: %w", err)
	}

	// 2. Define the initialization script.
	// We inject the configuration definition before executing the evasion logic.
	initScript := fmt.Sprintf("window.SCALPEL_PERSONA = %s;\n%s", string(personaJSON), EvasionsJS)

	// 3. Inject the script into the context.
	// AddInitScript runs immediately upon navigation or frame creation.
	// The API was updated; it now takes a playwright.Script struct.
	err = pwContext.AddInitScript(playwright.Script{
		Content: playwright.String(initScript),
	})
	if err != nil {
		return fmt.Errorf("failed to inject stealth evasion script: %w", err)
	}

	return nil
}

// prepareJSPersona converts the Go Persona struct into a map suitable for JS injection.
func prepareJSPersona(persona schemas.Persona) map[string]interface{} {
	jsPersona := map[string]interface{}{
		"userAgent":  persona.UserAgent,
		"platform":   persona.Platform,
		"languages":  persona.Languages,
		"timezoneId": persona.Timezone,
		"locale":     persona.Locale,
		"noiseSeed":  persona.NoiseSeed,
		"screen": map[string]interface{}{
			"width":       persona.Width,
			"height":      persona.Height,
			"availWidth":  persona.AvailWidth,
			"availHeight": persona.AvailHeight,
			"colorDepth":  persona.ColorDepth,
			"pixelDepth":  persona.PixelDepth,
		},
	}
	// Include Client Hints if available (though Playwright often manages this automatically).
	if persona.ClientHintsData != nil {
		jsPersona["clientHintsData"] = persona.ClientHintsData
	}
	return jsPersona
}
