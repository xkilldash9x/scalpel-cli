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
    "go.uber.org/zap"
)

// ClientHints defines the User-Agent Client Hints data.
type ClientHints struct {
    Platform        string                             `json:"platform"`
    PlatformVersion string                             `json:"platformVersion"`
    Architecture    string                             `json:"architecture"`
    Bitness         string                             `json:"bitness"`
    Mobile          bool                               `json:"mobile"`
    Brands          []*emulation.UserAgentBrandVersion `json:"brands"`
}

// Persona encapsulates all properties for a consistent browser fingerprint.
type Persona struct {
    UserAgent string   `json:"userAgent"`
    Platform  string   `json:"platform"`
    Languages []string `json:"languages"`

    // Flattened ScreenProperties
    Width       int64 `json:"width"`
    Height      int64 `json:"height"`
    AvailWidth  int64 `json:"availWidth"`
    AvailHeight int64 `json:"availHeight"`
    ColorDepth  int64 `json:"colorDepth"`
    PixelDepth  int64 `json:"pixelDepth"`
    Mobile      bool  `json:"mobile"`

    Timezone        string       `json:"timezoneId"`
    Locale          string       `json:"locale"`
    ClientHintsData *ClientHints `json:"clientHintsData,omitempty"`
    NoiseSeed       int64        `json:"noiseSeed"`
}

// EvasionsJS holds the embedded JavaScript used for browser fingerprint evasion.
// This is populated by the go:embed directive below, assuming a file named evasions.js
// exists in the same directory.
//go:embed evasions.js
var EvasionsJS string

// DefaultPersona provides a fallback persona if none is specified.
var DefaultPersona = Persona{
    UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    Platform:    "Win32",
    Languages:   []string{"en-US", "en"},
    Width:       1920,
    Height:      1080,
    AvailWidth:  1920,
    AvailHeight: 1040,
    ColorDepth:  24,
    PixelDepth:  24,
    Mobile:      false,
    Timezone:    "America/Los_Angeles",
    Locale:      "en-US",
}

// Apply returns a chromedp.Action that applies the stealth configurations.
func Apply(persona Persona, logger *zap.Logger) chromedp.Action {
    return chromedp.ActionFunc(func(ctx context.Context) error {
        if logger != nil {
            logger.Debug("Applying stealth persona and evasions.")
        }
        // Add a check in case embedding fails or the file is empty.
        if EvasionsJS == "" && logger != nil {
            logger.Warn("EvasionsJS is empty. Stealth capabilities may be reduced.")
        }
        return ApplyStealthEvasions(ctx, persona)
    })
}

// ApplyStealthEvasions injects JavaScript and configures the browser session to avoid detection.
func ApplyStealthEvasions(ctx context.Context, persona Persona) error {
    // 1. Marshal the persona into a JSON string for injection.
    // We reconstruct the nested 'screen' object to maintain compatibility with EvasionsJS
    // if it expects the original structure.
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

    personaJSON, err := json.Marshal(jsPersona)
    if err != nil {
        return fmt.Errorf("failed to marshal persona for stealth injection: %w", err)
    }

    // 2. Build the full script to be executed.
    // This injects the configuration before the main evasion logic runs.
    injectionScript := fmt.Sprintf("const SCALPEL_PERSONA = %s;", string(personaJSON))
    fullScript := injectionScript + "\n" + EvasionsJS

    var tasks chromedp.Tasks

    // 3. Add script to be evaluated on new document. This is the core of the evasion.
    // Only inject if EvasionsJS actually contains content to avoid errors.
    if EvasionsJS != "" {
        tasks = append(tasks, chromedp.ActionFunc(func(c context.Context) error {
            _, err := page.AddScriptToEvaluateOnNewDocument(fullScript).Do(c)
            return err
        }))
    }

    // 4. Set overrides that must be done via CDP commands.
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

    // 5. Device Metrics
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

    // Run all tasks.
    if err := chromedp.Run(ctx, tasks); err != nil {
        return fmt.Errorf("failed to apply stealth evasions: %w", err)
    }

    return nil
}
