// internal/browser/stealth/stealth.go
package stealth

import (
	"context"
	_ "embed" // Required for the go:embed directive
	"encoding/json"
	"fmt"
	"strings"

	// Required for low-level CDP access to manage emulation and network settings.
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

//go:embed evasions.js
var evasionsScript string

// ScreenProperties defines the resolution and depth of the display.
type ScreenProperties struct {
	Width       int64 `json:"width"`
	Height      int64 `json:"height"`
	AvailWidth  int64 `json:"availWidth,omitempty"`
	AvailHeight int64 `json:"availHeight,omitempty"`
	ColorDepth  int   `json:"colorDepth,omitempty"`
	PixelDepth  int   `json:"pixelDepth,omitempty"`
}

// GeolocationProperties defines the spoofed physical location.
type GeolocationProperties struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy"`
}

// ClientHints defines the structure for User-Agent Client Hints (Sec-CH-UA).
type ClientHints struct {
	Brands          []*emulation.UserAgentBrandVersion `json:"brands"`
	FullVersionList []*emulation.UserAgentBrandVersion `json:"fullVersionList,omitempty"`
	Mobile          bool                               `json:"mobile"`
	Platform        string                             `json:"platform"`        // e.g., "Windows"
	PlatformVersion string                             `json:"platformVersion"` // e.g., "10.0.0"
	Architecture    string                             `json:"architecture,omitempty"`
	Model           string                             `json:"model,omitempty"`
	Bitness         string                             `json:"bitness,omitempty"` // e.g., "64"
}

// Persona defines a consistent, high-fidelity profile to be spoofed.
type Persona struct {
	UserAgent string   `json:"userAgent"`
	Platform  string   `json:"platform"` // Legacy JS navigator.platform (e.g., Win32)
	Languages []string `json:"languages"`

	// Environment Consistency
	TimezoneID  string                 `json:"timezoneId,omitempty"`
	Locale      string                 `json:"locale,omitempty"`
	Geolocation *GeolocationProperties `json:"geolocation,omitempty"`

	// Hardware & Rendering
	WebGLVendor         string           `json:"webGLVendor,omitempty"`
	WebGLRenderer       string           `json:"webGLRenderer,omitempty"`
	HardwareConcurrency int              `json:"hardwareConcurrency,omitempty"`
	DeviceMemory        int              `json:"deviceMemory,omitempty"`
	Screen              ScreenProperties `json:"screen"`
	NoiseSeed           int64            `json:"noiseSeed,omitempty"` // Seed for PRNG in JS evasions.

	// Network Information (Note: Currently simulated via JS overrides, not native CDP).
	NetworkType     string  `json:"networkType,omitempty"`
	NetworkDownlink float64 `json:"networkDownlink,omitempty"`
	NetworkRtt      int     `json:"networkRtt,omitempty"`

	// Client Hints configuration.
	ClientHintsData *ClientHints `json:"clientHintsData,omitempty"`
}

// Apply orchestrates the stealth actions using chromedp.Tasks for sequential execution.
// The order is crucial: Network prerequisites, then core emulation overrides, and finally JS injection.
// This function returns a chromedp.Action, making it composable.
func Apply(persona Persona, logger *zap.Logger) chromedp.Action {
	l := logger.Named("stealth")

	// We build a sequence of Actions using chromedp.Tasks.
	return chromedp.Tasks{
		// 1. Network Configuration Prerequisites.
		network.Enable(),
		setExtraHTTPHeaders(persona, l),

		// 2. Core Emulation Overrides (CDP-level spoofing).
		setUserAgentAndClientHints(persona, l),
		setDeviceMetrics(persona, l),
		setEnvironmentOverrides(persona, l),

		// 3. Script Injection (JS Environment Modification and Evasions).
		injectEvasionScript(persona, l),

		// 4. Lifecycle Management (Anti-detection).
		setWebLifecycleState(l),

		// Confirmation logging.
		chromedp.ActionFunc(func(ctx context.Context) error {
			l.Debug("Stealth profile applied successfully", zap.String("UserAgent", persona.UserAgent))
			return nil
		}),
	}
}

// injectEvasionScript prepares and registers the JS evasion script to run on every new document load.
func injectEvasionScript(persona Persona, logger *zap.Logger) chromedp.Action {
	// Wrap in ActionFunc for execution-time evaluation and error handling.
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Serialize the persona configuration for injection into the JS environment.
		personaJSON, err := json.Marshal(persona)
		if err != nil {
			logger.Error("Failed to marshal Persona configuration for injection", zap.Error(err))
			return fmt.Errorf("stealth: failed to marshal persona: %w", err)
		}

		// Prepend the configuration object to the main evasions script.
		scriptWithPersona := fmt.Sprintf(
			"const SCALPEL_PERSONA = %s;\n%s",
			string(personaJSON),
			evasionsScript,
		)

		// Use the low-level CDP command Page.addScriptToEvaluateOnNewDocument and execute immediately.
		if _, err = page.AddScriptToEvaluateOnNewDocument(scriptWithPersona).Do(ctx); err != nil {
			logger.Error("Failed to register evasion script with CDP", zap.Error(err))
			return fmt.Errorf("stealth: failed to add script on new document: %w", err)
		}
		return nil
	})
}

// setUserAgentAndClientHints configures the UserAgent string and the structured Client Hints (Sec-CH-UA).
func setUserAgentAndClientHints(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Determine the platform string: prioritize ClientHints platform if available.
		platform := persona.Platform
		if persona.ClientHintsData != nil && persona.ClientHintsData.Platform != "" {
			platform = persona.ClientHintsData.Platform
		}

		// Build the CDP command using the builder pattern.
		override := emulation.SetUserAgentOverride(persona.UserAgent).
			WithPlatform(platform).
			WithAcceptLanguage(strings.Join(persona.Languages, ","))

		// Attach structured Client Hints metadata if provided.
		if ch := persona.ClientHintsData; ch != nil {
			metadata := &emulation.UserAgentMetadata{
				Brands:          ch.Brands,
				FullVersionList: ch.FullVersionList,
				Mobile:          ch.Mobile,
				Platform:        ch.Platform,
				PlatformVersion: ch.PlatformVersion,
				Architecture:    ch.Architecture,
				Model:           ch.Model,
				Bitness:         ch.Bitness,
			}
			override = override.WithUserAgentMetadata(metadata)
		}

		// Execute the command immediately.
		if err := override.Do(ctx); err != nil {
			logger.Error("Failed to set UserAgent/ClientHints override via CDP", zap.Error(err))
			return fmt.Errorf("stealth: failed to set user agent override: %w", err)
		}
		return nil
	})
}

// setExtraHTTPHeaders configures persistent HTTP headers, primarily Accept-Language with q-factors.
func setExtraHTTPHeaders(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if len(persona.Languages) == 0 {
			return nil
		}

		// Build the Accept-Language header string with realistic q-factor weighting.
		// Example: en-US,en;q=0.9,es;q=0.8
		formattedLanguage := persona.Languages[0]
		for i := 1; i < len(persona.Languages); i++ {
			// Calculate q-value, ensuring it doesn't drop too low.
			qValue := 1.0 - float64(i)*0.1
			if qValue < 0.7 {
				qValue = 0.7
			}
			formattedLanguage += fmt.Sprintf(",%s;q=%.1f", persona.Languages[i], qValue)
		}

		headers := map[string]interface{}{"Accept-Language": formattedLanguage}

		// Use the low-level CDP command Network.setExtraHTTPHeaders and execute immediately.
		if err := network.SetExtraHTTPHeaders(network.Headers(headers)).Do(ctx); err != nil {
			logger.Error("Failed to set extra HTTP headers via CDP", zap.Error(err))
			return fmt.Errorf("stealth: failed to set extra http headers: %w", err)
		}
		return nil
	})
}

// setDeviceMetrics configures the viewport resolution and orientation.
func setDeviceMetrics(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if persona.Screen.Width > 0 && persona.Screen.Height > 0 {
			// Determine orientation based on dimensions.
			orientation := emulation.OrientationTypeLandscapePrimary
			if persona.Screen.Height > persona.Screen.Width {
				orientation = emulation.OrientationTypePortraitPrimary
			}

			// Use the CDP command Emulation.setDeviceMetricsOverride and execute immediately.
			// We assume a standard device pixel ratio (DPR) of 1.0 for typical desktop scenarios.
			err := emulation.SetDeviceMetricsOverride(persona.Screen.Width, persona.Screen.Height, 1.0, false).
				WithScreenOrientation(&emulation.ScreenOrientation{
					Type:  orientation,
					Angle: 0, // Standard angle.
				}).Do(ctx)

			if err != nil {
				logger.Error("Failed to set device metrics override via CDP", zap.Error(err))
				return fmt.Errorf("stealth: failed to set device metrics: %w", err)
			}
		}
		return nil
	})
}

// setEnvironmentOverrides ensures Timezone, Locale, and Geolocation consistency.
func setEnvironmentOverrides(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// 1. Timezone Override.
		if persona.TimezoneID != "" {
			if err := emulation.SetTimezoneOverride(persona.TimezoneID).Do(ctx); err != nil {
				logger.Error("Failed to set timezone override via CDP", zap.Error(err))
				return fmt.Errorf("stealth: failed to set timezone: %w", err)
			}
		}

		// 2. Locale Override.
		locale := persona.Locale
		// Fallback to the primary language if locale is not explicitly set.
		if locale == "" && len(persona.Languages) > 0 {
			locale = persona.Languages[0]
		}

		if locale != "" {
			// Normalize locale format (e.g., en_US to en-US).
			normalizedLocale := strings.ReplaceAll(locale, "_", "-")

			// Use the builder pattern for the CDP command and execute immediately.
			if err := emulation.SetLocaleOverride().WithLocale(normalizedLocale).Do(ctx); err != nil {
				logger.Error("Failed to set locale override via CDP", zap.Error(err))
				return fmt.Errorf("stealth: failed to set locale: %w", err)
			}
		}

		// 3. Geolocation Override.
		if geo := persona.Geolocation; geo != nil {
			if err := emulation.SetGeolocationOverride().
				WithLatitude(geo.Latitude).
				WithLongitude(geo.Longitude).
				WithAccuracy(geo.Accuracy).
				Do(ctx); err != nil {
				logger.Error("Failed to set geolocation override via CDP", zap.Error(err))
				return fmt.Errorf("stealth: failed to set geolocation: %w", err)
			}
		}
		return nil
	})
}

// setWebLifecycleState prevents the browser from being flagged as "frozen" or inactive by detectors.
func setWebLifecycleState(logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Ensure the state is set to "active" and execute immediately.
		if err := page.SetWebLifecycleState(page.SetWebLifecycleStateStateActive).Do(ctx); err != nil {
			logger.Error("Failed to set web lifecycle state via CDP", zap.Error(err))
			return fmt.Errorf("stealth: could not set web lifecycle state: %w", err)
		}
		return nil
	})
}
