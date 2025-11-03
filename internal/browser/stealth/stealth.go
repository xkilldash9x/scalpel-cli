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

// Apply returns a chromedp.Tasks action that applies the stealth configurations.
// Note: The returned tasks must be executed using chromedp.Run(ctx, tasks) rather than tasks.Do(ctx).
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
	// Inject the persona data into window.SCALPEL_PERSONA and make it immutable.
	injectionScript := fmt.Sprintf(
		"Object.defineProperty(window, 'SCALPEL_PERSONA', {value: %s, writable: false, configurable: false});\n",
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
	// Merge persona with defaults.
	userAgent := persona.UserAgent
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	platform := persona.Platform
	if platform == "" {
		platform = DefaultPlatform
	}
	languages := persona.Languages
	if len(languages) == 0 {
		languages = DefaultLanguages
	}

	tasks = append(tasks,
		emulation.SetUserAgentOverride(userAgent).
			WithAcceptLanguage(strings.Join(languages, ",")).
			WithPlatform(platform),
	)

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

// ApplyStealthEvasions is a convenience function that runs the Apply tasks using chromedp.Run.
func ApplyStealthEvasions(ctx context.Context, persona schemas.Persona, logger *zap.Logger) error {
	tasks := Apply(persona, logger)
	// Must use chromedp.Run as Apply generates low-level CDP actions.
	if err := chromedp.Run(ctx, tasks); err != nil {
		return fmt.Errorf("failed to apply stealth evasions: %w", err)
	}
	return nil
}
