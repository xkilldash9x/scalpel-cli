// internal/browser/stealth/stealth.go
package stealth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// ScreenProperties defines the screen geometry for the persona.
type ScreenProperties struct {
	Width       int64 `json:"width"`
	Height      int64 `json:"height"`
	AvailWidth  int64 `json:"availWidth"`
	AvailHeight int64 `json:"availHeight"`
	ColorDepth  int64 `json:"colorDepth"`
	PixelDepth  int64 `json:"pixelDepth"`
}

// ClientHints defines the User-Agent Client Hints data.
type ClientHints struct {
	Platform        string                        `json:"platform"`
	PlatformVersion string                        `json:"platformVersion"`
	Architecture    string                        `json:"architecture"`
	Bitness         string                        `json:"bitness"`
	Mobile          bool                          `json:"mobile"`
	Brands          []*emulation.UserAgentBrandVersion `json:"brands"`
}

// Persona encapsulates all properties for a consistent browser fingerprint.
type Persona struct {
	UserAgent       string            `json:"userAgent"`
	Platform        string            `json:"platform"`
	Languages       []string          `json:"languages"`
	Screen          ScreenProperties  `json:"screen"`
	TimezoneID      string            `json:"timezoneId"`
	Locale          string            `json:"locale"`
	ClientHintsData *ClientHints      `json:"clientHintsData,omitempty"`
	NoiseSeed       int64             `json:"noiseSeed"`
}

// ApplyStealthEvasions injects JavaScript and configures the browser session to avoid detection.
func ApplyStealthEvasions(ctx context.Context, persona Persona) error {
	// 1. Marshal the persona into a JSON string for injection.
	personaJSON, err := json.Marshal(persona)
	if err != nil {
		return fmt.Errorf("failed to marshal persona for stealth injection: %w", err)
	}

	// 2. Build the full script to be executed.
	// This injects the configuration before the main evasion logic runs.
	injectionScript := fmt.Sprintf("const SCALPEL_PERSONA = %s;", string(personaJSON))
	fullScript := injectionScript + "\n" + EvasionsJS

	var tasks chromedp.Tasks

	// 3. Add script to be evaluated on new document. This is the core of the evasion.
	tasks = append(tasks, page.AddScriptToEvaluateOnNewDocument(fullScript))

	// 4. Set overrides that must be done via CDP commands.
	tasks = append(tasks,
		emulation.SetUserAgentOverride(persona.UserAgent).
			WithAcceptLanguage(strings.Join(persona.Languages, ",")).
			WithPlatform(persona.Platform),
		emulation.SetTimezoneOverride(persona.TimezoneID),
		emulation.SetLocaleOverride(persona.Locale),
		emulation.SetDeviceMetricsOverride(persona.Screen.Width, persona.Screen.Height, 1, persona.Screen.Mobile).
			WithScreenOrientation(&emulation.ScreenOrientation{Type: emulation.OrientationTypePortraitPrimary, Angle: 0}).
			WithDeviceScaleFactor(1).
			WithScreenWidth(persona.Screen.Width).
			WithScreenHeight(persona.Screen.Height),
	)

	// Run all tasks.
	if err := chromedp.Run(ctx, tasks); err != nil {
		return fmt.Errorf("failed to apply stealth evasions: %w", err)
	}

	return nil
}