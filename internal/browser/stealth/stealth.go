package stealth

import (
	"context"
	_ "embed" // Import embed for go:embed directive
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// The ClientHints and Persona structs have been moved to api/schemas.

// EvasionsJS holds the embedded JavaScript used for browser fingerprint evasion.
//go:embed evasions.js
var EvasionsJS string

// The DefaultPersona var has been moved to api/schemas.

// Apply returns a chromedp.Tasks action that applies the stealth configurations.
func Apply(persona schemas.Persona, logger *zap.Logger) chromedp.Tasks {
	if logger != nil {
		logger.Debug("Applying stealth persona and evasions.")
	}
	if EvasionsJS == "" && logger != nil {
		logger.Warn("EvasionsJS is empty. Stealth capabilities may be reduced.")
	}

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
	if persona.ClientHintsData != nil {
		jsPersona["clientHintsData"] = persona.ClientHintsData
	}

	_, err := json.Marshal(jsPersona)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal persona for stealth injection", zap.Error(err))
		}
		return chromedp.Tasks{}
	}

	var tasks chromedp.Tasks

	// -- Temporarily disable JS-based evasions to isolate the problem --
	// This is the likely source of the incompatibility with the older chromedp version.
	if EvasionsJS != "" {
		tasks = append(tasks, chromedp.ActionFunc(func(c context.Context) error {
			logger.Debug("JavaScript evasion script injection is currently disabled for testing.")
			return nil
		}))
	}

	tasks = append(tasks,
		emulation.SetUserAgentOverride(persona.UserAgent).
			WithAcceptLanguage(strings.Join(persona.Languages, ",")).
			WithPlatform(persona.Platform),
	)

	if persona.Timezone != "" {
		tasks = append(tasks, emulation.SetTimezoneOverride(persona.Timezone))
	}

	if persona.Locale != "" {
		tasks = append(tasks, emulation.SetLocaleOverride().WithLocale(persona.Locale))
	}

	if persona.Width > 0 && persona.Height > 0 {
		orientationType := emulation.OrientationTypeLandscapePrimary
		angle := int64(0)
		if persona.Height > persona.Width {
			orientationType = emulation.OrientationTypePortraitPrimary
		}

		metrics := emulation.SetDeviceMetricsOverride(persona.Width, persona.Height, 1.0, persona.Mobile).
			WithScreenOrientation(&emulation.ScreenOrientation{
				Type:  orientationType,
				Angle: angle,
			}).
			WithScreenWidth(persona.Width).
			WithScreenHeight(persona.Height)

		tasks = append(tasks, metrics)
	}

	return tasks
}

// ApplyStealthEvasions is a convenience function that runs the Apply tasks.
func ApplyStealthEvasions(ctx context.Context, persona schemas.Persona, logger *zap.Logger) error {
	tasks := Apply(persona, logger)
	if err := chromedp.Run(ctx, tasks); err != nil {
		return fmt.Errorf("failed to apply stealth evasions: %w", err)
	}
	return nil
}
