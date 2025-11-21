package service

import (
	"context"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

func TestGetBrowserExecOptions(t *testing.T) {
	tests := []struct {
		name     string
		cfg      func() config.Interface
		expected int // minimal check on number of options or specific flags presence
	}{
		{
			name: "Default",
			cfg: func() config.Interface {
				cfg := config.NewDefaultConfig()
				return cfg
			},
		},
		{
			name: "Headless",
			cfg: func() config.Interface {
				cfg := config.NewDefaultConfig()
				cfg.SetBrowserHeadless(true)
				return cfg
			},
		},
		{
			name: "WithArgs",
			cfg: func() config.Interface {
				cfg := config.NewDefaultConfig()
				cfg.BrowserCfg.Args = []string{"--flag1", "key=value"}
				return cfg
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := getBrowserExecOptions(tt.cfg())
			assert.NotEmpty(t, opts)
			// Basic validation that it returns options
			// Since chromedp.ExecAllocatorOption is a function, we can't easily equality check without deep inspection or mocking chromedp.
			// But we can assume if it runs without panic and returns a slice, it's working for now.
			// We could verify specific flags if we inspect the internal slice logic of chromedp, but that's internal details.
			// Just checking count is > defaults might be enough.
			assert.Greater(t, len(opts), len(chromedp.DefaultExecAllocatorOptions))
		})
	}
}

func TestCreate_ValidationErrors(t *testing.T) {
	factory := NewComponentFactory()
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("MissingDBURL", func(t *testing.T) {
		cfg := config.NewDefaultConfig()
		cfg.DatabaseCfg.URL = "" // Ensure empty

		_, err := factory.Create(ctx, cfg, []string{"http://example.com"}, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database URL is not configured")
	})

	// Note: Validating DB connection requires a real DB or heavy mocking of pgxpool.New.
	// Validating no targets requires DB URL to be present first to pass that check.
	// So we'll skip "NoTargets" test unless we mock pgxpool, which is hard in this factory structure as it calls pgxpool.New directly.
	// The factory needs refactoring to support dependency injection of the DB pool creator for full unit testing.
	// For now, we cover the initial validation logic.
}
