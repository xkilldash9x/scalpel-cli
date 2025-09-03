// pkg/browser/stealth/stealth.go
package stealth

import (
	"context"
	_ "embed" // Required for the go:embed directive
	"encoding/json"
	"fmt"
	"strings"

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
	Platform        string                             `json:"platform"`          // e.g., "Windows"
	PlatformVersion string                             `json:"platformVersion"`   // e.g., "10.0.0"
	Architecture    string                             `json:"architecture,omitempty"` // e.g., "x86"
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
	NoiseSeed           int64            `json:"noiseSeed,omitempty"`

	// Network Information
	NetworkType     string  `json:"networkType,omitempty"`
	NetworkDownlink float64 `json:"networkDownlink,omitempty"`
	NetworkRtt      int     `json:"networkRtt,omitempty"`

	// Client Hints configuration.
	ClientHintsData *ClientHints `json:"clientHintsData,omitempty"`
}

// Apply orchestrates the stealth actions using chromedp.Tasks for sequential execution.
func Apply(persona Persona, logger *zap.Logger) chromedp.Action {
	l := logger.Named("stealth")
	return chromedp.Tasks{
		// 1. Network Configuration
		network.Enable(),
		setExtraHTTPHeaders(persona, l),

		// 2. Core Emulation Overrides
		setUserAgentAndClientHints(persona, l),
		setDeviceMetrics(persona, l),
		setEnvironmentOverrides(persona, l),

		// 3. Script Injection (JS Environment Modification)
		injectEvasionScript(persona, l),

		// 4. Lifecycle Management
		page.SetWebLifecycleState(page.WebLifecycleStateActive),

		// Log success
		chromedp.ActionFunc(func(ctx context.Context) error {
			l.Debug("Stealth profile applied successfully", zap.String("UserAgent", persona.UserAgent))
			return nil
		}),
	}
}

// injectEvasionScript prepares and registers the JS evasion script.
func injectEvasionScript(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		personaJSON, err := json.Marshal(persona)
		if err != nil {
			logger.Error("Failed to marshal Persona configuration", zap.Error(err))
			return fmt.Errorf("stealth: failed to marshal persona: %w", err)
		}

		scriptWithPersona := fmt.Sprintf(
			"const SCALPEL_PERSONA = %s;\n%s",
			string(personaJSON),
			evasionsScript,
		)

		if _, err = page.AddScriptToEvaluateOnNewDocument(scriptWithPersona).Do(ctx); err != nil {
			logger.Error("Failed to register evasion script with CDP", zap.Error(err))
			return fmt.Errorf("stealth: failed to add script on new document: %w", err)
		}
		return nil
	})
}

// setUserAgentAndClientHints configures the UserAgent string and Client Hints.
func setUserAgentAndClientHints(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		platform := persona.Platform
		if persona.ClientHintsData != nil && persona.ClientHintsData.Platform != "" {
			platform = persona.ClientHintsData.Platform
		}

		override := emulation.SetUserAgentOverride(persona.UserAgent).
			WithPlatform(platform).
			WithAcceptLanguage(strings.Join(persona.Languages, ","))

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

		if err := override.Do(ctx); err != nil {
			logger.Error("Failed to set UserAgent/ClientHints override via CDP", zap.Error(err))
			return fmt.Errorf("stealth: failed to set user agent override: %w", err)
		}
		return nil
	})
}

// setExtraHTTPHeaders configures persistent HTTP headers.
func setExtraHTTPHeaders(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if len(persona.Languages) == 0 {
			return nil
		}
		formattedLanguage := persona.Languages[0]
		for i := 1; i < len(persona.Languages); i++ {
			qValue := 1.0 - float64(i)*0.1
			if qValue < 0.7 {
				qValue = 0.7
			}
			formattedLanguage += fmt.Sprintf(",%s;q=%.1f", persona.Languages[i], qValue)
		}
		headers := map[string]interface{}{"Accept-Language": formattedLanguage}
		if err := network.SetExtraHTTPHeaders(network.Headers(headers)).Do(ctx); err != nil {
			logger.Error("Failed to set extra HTTP headers via CDP", zap.Error(err))
			return fmt.Errorf("stealth: failed to set extra http headers: %w", err)
		}
		return nil
	})
}

// setDeviceMetrics configures the viewport and resolution.
func setDeviceMetrics(persona Persona, logger *zap.Logger) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if persona.Screen.Width > 0 && persona.Screen.Height > 0 {
			orientation := emulation.OrientationTypeLandscapePrimary
			if persona.Screen.Height > persona.Screen.Width {
				orientation = emulation.OrientationTypePortraitPrimary
			}
			err := emulation.SetDeviceMetricsOverride(persona.Screen.Width, persona.Screen.Height, 1.0, false).
				WithScreenOrientation(&emulation.ScreenOrientation{
					Type:  orientation,
					Angle: 0,
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
		if persona.TimezoneID != "" {
			if err := emulation.SetTimezoneOverride(persona.TimezoneID).Do(ctx); err != nil {
				logger.Error("Failed to set timezone override via CDP", zap.Error(err))
				return fmt.Errorf("stealth: failed to set timezone: %w", err)
			}
		}

		locale := persona.Locale
		if locale == "" && len(persona.Languages) > 0 {
			locale = persona.Languages[0]
		}
		if locale != "" {
			normalizedLocale := strings.ReplaceAll(locale, "_", "-")
			if err := emulation.SetLocaleOverride(normalizedLocale).Do(ctx); err != nil {
				logger.Error("Failed to set locale override via CDP", zap.Error(err))
				return fmt.Errorf("stealth: failed to set locale: %w", err)
			}
		}

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