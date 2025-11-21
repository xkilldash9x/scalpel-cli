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

	// 1. Prepare Persona data for injection
	jsPersona, err := json.Marshal(persona)
	if err != nil {
		logger.Error("failed to marshal persona for stealth injection", zap.Error(err))
		// Return an error action if critical data preparation fails
		return chromedp.Tasks{chromedp.ActionFunc(func(ctx context.Context) error {
			return fmt.Errorf("failed to marshal persona: %w", err)
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

	// Determine UserAgent
	userAgent := persona.UserAgent
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}

	// Determine Languages
	languages := persona.Languages
	if len(languages) == 0 {
		languages = DefaultLanguages
	}

	// Determine Platform (Fix for Bug 5: Inconsistent Platform Defaulting)
	platform := persona.Platform
	if platform == "" {
		if userAgent == DefaultUserAgent {
			platform = DefaultPlatform
		} else {
			// FIX: Manually derive platform from UA because CDP won't do it automatically.
			platform = derivePlatformFromUA(userAgent)
		}
	}

	uaOverride := emulation.SetUserAgentOverride(userAgent).
		WithAcceptLanguage(strings.Join(languages, ","))

	// Always set the platform if we have one (which we now always should)
	if platform != "" {
		uaOverride = uaOverride.WithPlatform(platform)
	}

	tasks = append(tasks, uaOverride)

	// 5. Apply environment overrides (Timezone, Locale, Device Metrics)
	if persona.Timezone != "" {
		tasks = append(tasks, emulation.SetTimezoneOverride(persona.Timezone))
	}

	// Locale handling: Use persona locale, fallback to primary language if locale is empty.
	locale := persona.Locale
	if locale == "" && len(languages) > 0 {
		locale = languages[0]
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

// Helper function to derive platform from User Agent string
func derivePlatformFromUA(ua string) string {
	lowerUA := strings.ToLower(ua)
	if strings.Contains(lowerUA, "windows") || strings.Contains(lowerUA, "win32") || strings.Contains(lowerUA, "win64") {
		return "Win32"
	}
	// FIX for Bug 2: Check for iPhone/iPad BEFORE checking for Macintosh.
	// iPad and iPhone UA strings often contain "like Mac OS X", so they would match
	// "mac os x" if checked later, resulting in incorrect "MacIntel" platform.
	if strings.Contains(lowerUA, "iphone") {
		return "iPhone"
	}
	if strings.Contains(lowerUA, "ipad") {
		return "iPad"
	}
	if strings.Contains(lowerUA, "macintosh") || strings.Contains(lowerUA, "mac os x") {
		return "MacIntel"
	}
	if strings.Contains(lowerUA, "android") {
		return "Linux armv8l" // Common default, though variable
	}
	if strings.Contains(lowerUA, "linux") {
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
