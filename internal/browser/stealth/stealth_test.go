package stealth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// ClientHints defines the User-Agent Client Hints data.
//type ClientHints struct {
//	Platform        string                             `json:"platform"`
//	PlatformVersion string                             `json:"platformVersion"`
//	Architecture    string                             `json:"architecture"`
//	Bitness         string                             `json:"bitness"`
//	Mobile          bool                               `json:"mobile"`
//	Brands          []*emulation.UserAgentBrandVersion `json:"brands"`
//}

// Persona encapsulates all properties for a consistent browser fingerprint.
// The structure has been updated to flatten screen properties for easier use in Go,
// while maintaining the original nested structure during JSON marshaling for JS compatibility.
//type Persona struct {
//	UserAgent string   `json:"userAgent"`
//	Platform  string   `json:"platform"`
//	Languages []string `json:"languages"`
//
//	// ScreenProperties that were previously in a nested struct
//	Width       int64 `json:"width"`
//	Height      int64 `json:"height"`
//	AvailWidth  int64 `json:"availWidth"`
//	AvailHeight int64 `json:"availHeight"`
//	ColorDepth  int64 `json:"colorDepth"`
//	PixelDepth  int64 `json:"pixelDepth"`
//	Mobile      bool  `json:"mobile"` // Mobile flag, important for device metrics
//
//	// Renamed from TimezoneID for better clarity in Go
//	Timezone      string       `json:"timezoneId"` // JSON tag kept for JS compatibility
//	Locale        string       `json:"locale"`
//	ClientHintsData *ClientHints `json:"clientHintsData,omitempty"`
//	NoiseSeed     int64        `json:"noiseSeed"`
//}

// EvasionsJS is assumed to be an exported variable from another file in this package,
// containing the core JavaScript evasion logic.
//var EvasionsJS string
//
//// Apply returns a chromedp.Action that applies all the stealth configurations.
//// This function acts as a wrapper to integrate with other parts of the application,
//// such as the analysis context.
//func Apply(persona Persona, logger *zap.Logger) chromedp.Action {
//	return chromedp.ActionFunc(func(ctx context.Context) error {
//		if logger != nil {
//			logger.Debug("Applying stealth persona and evasions.")
//		}
//		return ApplyStealthEvasions(ctx, persona)
//	})
//}

// ApplyStealthEvasions injects JavaScript and configures the browser session to avoid detection.
//func ApplyStealthEvasions(ctx context.Context, persona Persona) error {
//	// 1. Prepare the persona for JavaScript injection.
//	// We manually construct a map to create a nested 'screen' object. This ensures
//	// that we don't break the EvasionsJS script which expects the original data structure,
//	// e.g., `SCALPEL_PERSONA.screen.width`.
//	jsPersona := map[string]interface{}{
//		"userAgent":  persona.UserAgent,
//		"platform":   persona.Platform,
//		"languages":  persona.Languages,
//		"timezoneId": persona.Timezone,
//		"locale":     persona.Locale,
//		"noiseSeed":  persona.NoiseSeed,
//		"screen": map[string]interface{}{
//			"width":       persona.Width,
//			"height":      persona.Height,
//			"availWidth":  persona.AvailWidth,
//			"availHeight": persona.AvailHeight,
//			"colorDepth":  persona.ColorDepth,
//			"pixelDepth":  persona.PixelDepth,
//		},
//	}
//	if persona.ClientHintsData != nil {
//		jsPersona["clientHintsData"] = persona.ClientHintsData
//	}
//
//	personaJSON, err := json.Marshal(jsPersona)
//	if err != nil {
//		return fmt.Errorf("failed to marshal persona for stealth injection: %w", err)
//	}
//
//	// 2. Build the full script to be executed on new documents.
//	// This injects our configuration object before the main evasion logic runs.
//	injectionScript := fmt.Sprintf("const SCALPEL_PERSONA = %s;", string(personaJSON))
//	fullScript := injectionScript + "\n" + EvasionsJS
//
//	var tasks chromedp.Tasks
//
//	// 3. Add the script to be evaluated on new document creation.
//	// This is the core of the evasion mechanism. Since the underlying CDP command
//	// returns a value, we must wrap it in an ActionFunc to handle it correctly.
//	tasks = append(tasks, chromedp.ActionFunc(func(c context.Context) error {
//		// We call Do(c) to execute the command and return any error,
//		// ignoring the script identifier that is returned on success.
//		_, err := page.AddScriptToEvaluateOnNewDocument(fullScript).Do(c)
//		return err
//	}))
//
//	// 4. Set various overrides using CDP commands for properties that
//	// cannot be spoofed effectively via JavaScript alone.
//	tasks = append(tasks,
//		emulation.SetUserAgentOverride(persona.UserAgent).
//			WithAcceptLanguage(strings.Join(persona.Languages, ",")).
//			WithPlatform(persona.Platform),
//	)
//
//	// Conditionally apply timezone override if one is provided.
//	if persona.Timezone != "" {
//		tasks = append(tasks, emulation.SetTimezoneOverride(persona.Timezone))
//	}
//
//	// Conditionally apply locale override, using the newer builder pattern API.
//	if persona.Locale != "" {
//		tasks = append(tasks, emulation.SetLocaleOverride().WithLocale(persona.Locale))
//	}
//
//	// 5. Conditionally apply device and screen metrics.
//	if persona.Width > 0 && persona.Height > 0 {
//		orientationType := emulation.OrientationTypeLandscapePrimary
//		angle := int64(90)
//		if persona.Height > persona.Width {
//			orientationType = emulation.OrientationTypePortraitPrimary
//			angle = 0
//		}
//
//		// The SetDeviceMetricsOverride function requires width, height, deviceScaleFactor, and mobile flag.
//		metrics := emulation.SetDeviceMetricsOverride(persona.Width, persona.Height, 1.0, persona.Mobile).
//			WithScreenOrientation(&emulation.ScreenOrientation{
//				Type:  orientationType,
//				Angle: angle,
//			}).
//			WithScreenWidth(persona.Width).   // Spoof total screen width
//			WithScreenHeight(persona.Height) // Spoof total screen height
//
//		tasks = append(tasks, metrics)
//	}
//
//	// Run all configuration tasks.
//	if err := chromedp.Run(ctx, tasks); err != nil {
//		return fmt.Errorf("failed to apply stealth evasions: %w", err)
//	}
//
//	return nil
//}
