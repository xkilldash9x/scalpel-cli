// internal/browser/stealth/stealth.go
// package stealth provides functionality to apply various browser fingerprinting
// evasions. It works by injecting a sophisticated JavaScript payload (`evasions.js`)
// into every new document created in a browser session. This script runs before
// any page scripts, allowing it to override and patch browser APIs that are commonly
// used for fingerprinting (e.g., `navigator.plugins`, `WebGLRenderingContext`).
//
// In addition to the JavaScript evasions, this package also uses the Chrome
// DevTools Protocol (CDP) to apply "defense-in-depth" overrides for fundamental
// browser properties like the User-Agent, platform, viewport dimensions, and
// timezone. These configurations are derived from a `schemas.Persona` object,
// ensuring that the browser's fingerprint is consistent across both the CDP and
// JavaScript layers.
package stealth

import (
	"context"
	_ "embed" // Import embed for go:embed directive
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// EvasionsJS holds the embedded JavaScript used for browser fingerprint evasion.
//
//go:embed evasions.js
var EvasionsJS string

// Constants for default values and limits
const (
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	DefaultPlatform  = "Win32"
	DefaultDPR       = 1.0
	MaxDPR           = 5.0 // Maximum reasonable DPR to prevent browser instability.
)

var DefaultLanguages = []string{"en-US", "en"}

// Apply constructs a `chromedp.Tasks` list that, when executed, will apply all
// the necessary stealth and persona emulation configurations to a browser session.
// It combines JavaScript injection with direct CDP command overrides.
//
// The process includes:
//  1. Marshalling the `Persona` into a JSON object.
//  2. Creating a JavaScript payload that injects the persona and the main evasion script.
//  3. Adding a CDP action to inject this script on all new documents.
//  4. Adding CDP actions to override the User-Agent, platform, languages, timezone,
//     locale, and device metrics.
//
// Note: This function returns a `chromedp.Tasks` object, which is a slice of
// `chromedp.Action`. It must be executed using `chromedp.Run`, as it contains
// low-level CDP commands that are not compatible with `chromedp.Tasks{...}.Do()`.
func Apply(persona schemas.Persona, logger *zap.Logger) chromedp.Tasks {
	if logger == nil {
		// Use a Nop logger if none is provided to avoid nil pointer dereferences.
		logger = zap.NewNop()
	}
	logger.Debug("Applying stealth persona and evasions.")

	// (Fix 3: Ensure derived properties are injected consistently into JS)
	// We determine effective properties (handling defaults/derivation) and update the persona
	// object BEFORE marshalling it for injection.

	// 1. Determine effective properties

	// UserAgent
	if persona.UserAgent == "" {
		persona.UserAgent = DefaultUserAgent
	}

	// Languages
	if len(persona.Languages) == 0 {
		persona.Languages = DefaultLanguages
	}

	// Platform (Fix for Bug 5: Inconsistent Platform Defaulting)
	// If platform is not provided, derive it from the UserAgent.
	if persona.Platform == "" {
		persona.Platform = derivePlatformFromUA(persona.UserAgent)
	}
	// (End Fix 3)

	// 1. Prepare Persona data for injection
	jsPersona, err := json.Marshal(persona)
	if err != nil {
		logger.Error("failed to marshal persona for stealth injection", zap.Error(err))
		// Return an error action if critical data preparation fails
		return chromedp.Tasks{chromedp.ActionFunc(func(ctx context.Context) error {
			return err
		})}
	}

	// 2. Construct the full injection script
	// Inject the persona data safely using JSON.parse() to prevent script breakage
	// from characters like U+2028/U+2029. We use %q to safely quote the JSON string
	// as a Go string literal, ensuring it is correctly interpreted as a JavaScript string literal.
	injectionScript := fmt.Sprintf(
		"const personaJson = %q;\n"+
			"Object.defineProperty(window, 'SCALPEL_PERSONA', {value: JSON.parse(personaJson), writable: false, configurable: false});\n",
		string(jsPersona),
	)

	// Append the evasion logic
	if EvasionsJS != "" {
		injectionScript += EvasionsJS
	} else {
		logger.Error("EvasionsJS is empty. Stealth capabilities are severely reduced.")
	}

	var tasks chromedp.Tasks

	// 3. Inject the script using Page.addScriptToEvaluateOnNewDocument
	// This ensures the script runs before any page scripts in every new frame/document.
	if injectionScript != "" {
		// Use the low-level CDP command wrapped in an ActionFunc.
		tasks = append(tasks, chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(injectionScript).Do(ctx)
			return err
		}))
	}

	// 4. Apply CDP Overrides (Defense in depth)
	
	// Use the finalized persona properties.
	uaOverride := emulation.SetUserAgentOverride(persona.UserAgent).
		WithAcceptLanguage(strings.Join(persona.Languages, ",")).
		WithPlatform(persona.Platform) // Platform is now guaranteed to be set.

	tasks = append(tasks, uaOverride)

	// 5. Apply environment overrides (Timezone, Locale, Device Metrics)
	if persona.Timezone != "" {
		tasks = append(tasks, emulation.SetTimezoneOverride(persona.Timezone))
	}

	// Locale handling: Use persona locale, fallback to primary language if locale is empty.
	locale := persona.Locale
	if locale == "" && len(persona.Languages) > 0 {
		locale = persona.Languages[0]
	}
	if locale != "" {
		tasks = append(tasks, emulation.SetLocaleOverride().WithLocale(locale))
	}

	if persona.Width > 0 && persona.Height > 0 {
		// Pass logger to allow warnings about metric adjustments.
		tasks = append(tasks, createDeviceMetricsAction(persona, logger))
	}

	return tasks
}

// Helper function to derive platform from User Agent string (Improvement 7)
func derivePlatformFromUA(ua string) string {
	lowerUA := strings.ToLower(ua)

	// 1. Check for specific mobile platforms first (Crucial for iOS priority).
	if strings.Contains(lowerUA, "iphone") {
		return "iPhone"
	}
	if strings.Contains(lowerUA, "ipad") {
		return "iPad"
	}
	if strings.Contains(lowerUA, "android") {
		// Modernization: Use "Linux aarch64" for modern 64-bit Android.
		return "Linux aarch64"
	}

	// 2. Check desktop platforms.
	if strings.Contains(lowerUA, "windows") || strings.Contains(lowerUA, "win32") || strings.Contains(lowerUA, "win64") {
		return "Win32"
	}

	// Check Mac (after iPhone/iPad, as iOS UAs often contain "like Mac OS X").
	if strings.Contains(lowerUA, "macintosh") || strings.Contains(lowerUA, "mac os x") {
		return "MacIntel"
	}

	if strings.Contains(lowerUA, "linux") {
		// Detect 32-bit Linux (Check for 32-bit indicators AND absence of 64-bit indicators).
		if (strings.Contains(lowerUA, "i686") || strings.Contains(lowerUA, "i386")) && !strings.Contains(lowerUA, "x86_64") && !strings.Contains(lowerUA, "wow64") {
			return "Linux i686"
		}
		return "Linux x86_64"
	}
	// Fallback
	return "Win32"
}

// createDeviceMetricsAction creates the appropriate emulation action for device metrics.
func createDeviceMetricsAction(persona schemas.Persona, logger *zap.Logger) chromedp.Action {
	orientationType := emulation.OrientationTypeLandscapePrimary
	angle := int64(0)
	// Determine orientation based on dimensions
	if persona.Height > persona.Width {
		orientationType = emulation.OrientationTypePortraitPrimary
	}

	// Determine DPR (Device Pixel Ratio).
	// We use Persona.PixelDepth for DPR, distinct from ColorDepth.
	dpr := DefaultDPR
	if persona.PixelDepth > 0 {
		dpr = float64(persona.PixelDepth)
	}

	// Robustness: Clamp DPR to a reasonable range.
	if dpr > MaxDPR {
		// (Fix 8: Ensure logger is not nil before use)
		if logger != nil {
			logger.Warn("Persona DPR (PixelDepth) exceeds maximum. Clamping.",
				zap.Float64("provided_dpr", dpr),
				zap.Float64("clamped_dpr", MaxDPR),
			)
		}
		dpr = MaxDPR
	} else if dpr < 0.5 {
		// Prevent extremely low or negative DPR.
		dpr = DefaultDPR
	}

	metrics := emulation.SetDeviceMetricsOverride(persona.Width, persona.Height, dpr, persona.Mobile).
		WithScreenOrientation(&emulation.ScreenOrientation{
			Type:  orientationType,
			Angle: angle,
		}).
		WithScreenWidth(persona.Width).
		WithScreenHeight(persona.Height)

	return metrics
}

// ApplyStealthEvasions is a high-level convenience function that constructs the
// stealth configuration tasks via `Apply` and immediately executes them on the
// provided context using `chromedp.Run`. This provides a simple, one-shot way
// to apply all evasions to an active browser context.
func ApplyStealthEvasions(ctx context.Context, persona schemas.Persona, logger *zap.Logger) error {
	tasks := Apply(persona, logger)
	// Must use chromedp.Run as Apply generates low-level CDP actions.
	if err := chromedp.Run(ctx, tasks); err != nil {
		return fmt.Errorf("failed to apply stealth evasions: %w", err)
	}
	return nil
}
