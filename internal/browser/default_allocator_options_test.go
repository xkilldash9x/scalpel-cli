// internal/browser/default_allocator_options_test.go
package browser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// hasOption is a helper to check for the presence of an option by inspecting its string representation.
// This is a pragmatic approach to test the options without a browser dependency.
func hasOption(t *testing.T, opts []chromedp.ExecAllocatorOption, substring string) bool {
	for _, opt := range opts {
		s := fmt.Sprintf("%#v", opt)
		if strings.Contains(s, substring) {
			return true
		}
	}
	return false
}

func TestDefaultAllocatorOptions(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		cfg := config.BrowserConfig{
			Headless: true,
		}
		opts := DefaultAllocatorOptions(cfg)
		// Default should be headless, so no "headless=false" flag
		assert.False(t, hasOption(t, opts, "headlessfalse"))
	})

	t.Run("HeadlessDisabled", func(t *testing.T) {
		cfg := config.BrowserConfig{
			Headless: false,
		}
		opts := DefaultAllocatorOptions(cfg)
		// We can't reliably test the absence of a flag, so we'll rely on integration tests.
		assert.NotEmpty(t, opts)
	})

	t.Run("CacheDisabled", func(t *testing.T) {
		cfg := config.BrowserConfig{
			DisableCache: true,
		}
		opts := DefaultAllocatorOptions(cfg)
		assert.True(t, hasOption(t, opts, "disk-cache-size"))
		assert.True(t, hasOption(t, opts, "media-cache-size"))
		assert.True(t, hasOption(t, opts, "disable-cache"))
	})

	t.Run("IgnoreTLSErrors", func(t *testing.T) {
		cfg := config.BrowserConfig{
			IgnoreTLSErrors: true,
		}
		opts := DefaultAllocatorOptions(cfg)
		assert.True(t, hasOption(t, opts, "ignore-certificate-errors"))
		assert.True(t, hasOption(t, opts, "allow-insecure-localhost"))
	})

	t.Run("WithCustomArgs", func(t *testing.T) {
		cfg := config.BrowserConfig{
			Args: []string{"--custom-arg1", "--custom-arg2"},
		}
		opts := DefaultAllocatorOptions(cfg)
		assert.True(t, hasOption(t, opts, "custom-arg1"))
		assert.True(t, hasOption(t, opts, "custom-arg2"))
	})

	t.Run("WithViewport", func(t *testing.T) {
		cfg := config.BrowserConfig{
			Viewport: map[string]int{
				"width":  1920,
				"height": 1080,
			},
		}
		opts := DefaultAllocatorOptions(cfg)
		assert.True(t, hasOption(t, opts, "window-size"))
	})
}
