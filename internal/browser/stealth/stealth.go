package stealth

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

//go:embed evasions.js
var evasionsScript string

// Persona defines the browser characteristics to emulate.
type Persona struct {
	UserAgent string
	Platform  string
	Languages []string
	Timezone  string
	Locale    string
}

// DefaultPersona provides a realistic default browser profile.
var DefaultPersona = Persona{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	Platform:  "Win32",
	Languages: []string{"en-US", "en"},
	Timezone:  "America/Los_Angeles",
	Locale:    "en-US",
}

// Apply constructs a sequence of Chrome DevTools Protocol actions to make the
// headless browser appear more like a standard, user-operated browser.
func Apply(p Persona, logger *zap.Logger) chromedp.Tasks {
	logger.Debug("Applying browser stealth persona",
		zap.String("userAgent", p.UserAgent),
		zap.String("platform", p.Platform),
	)

	return chromedp.Tasks{
		// 1. Set the User-Agent override. This is a direct action.
		emulation.SetUserAgentOverride(p.UserAgent),

		// 2. Inject the evasions.js script. This requires an ActionFunc wrapper
		// because its Do() method returns two values, which doesn't match the
		// chromedp.Action interface.
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(evasionsScript).Do(ctx)
			if err != nil {
				return fmt.Errorf("failed to inject evasions script: %w", err)
			}
			return nil
		}),

		// 3. Set the timezone. This is also a direct action.
		emulation.SetTimezoneOverride(p.Timezone),

		// 4. Set the locale using the correct builder pattern.
		// `SetLocaleOverride()` is called with no arguments, and the locale is
		// provided via the chained `WithLocale()` method. This returns a valid
		// chromedp.Action that can be used directly in the Tasks slice.
		emulation.SetLocaleOverride().WithLocale(p.Locale),

		// 5. Set consistent HTTP headers to match the persona's language settings.
		network.SetExtraHTTPHeaders(network.Headers{
			"Accept-Language": fmt.Sprintf("%s,%s;q=0.9", p.Languages[0], p.Languages[1]),
		}),
	}
}

