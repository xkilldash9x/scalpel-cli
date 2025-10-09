// File: cmd/helpers_test.go
package cmd

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// boolp is a helper function to create a pointer to a boolean value.
// This is necessary for config fields that are of type *bool, like Discovery.PassiveEnabled.
func boolp(b bool) *bool {
	return &b
}

// newTestConfig creates a fully populated, default configuration struct for use in tests.
// This mirrors the structure and values of the default config.yaml, providing a consistent
// baseline for test execution without needing to parse a file.
func newTestConfig() *config.Config {
	return &config.Config{
		Logger: config.LoggerConfig{
			ServiceName: "scalpel-cli",
			LogFile:     "logs/scalpel.log",
			Level:       "info",
			Format:      "json",
			AddSource:   false,
			MaxSize:     10,
			MaxBackups:  3,
			MaxAge:      7,
			Compress:    true,
			Colors: config.ColorConfig{ // Corrected: LogColorConfig -> ColorConfig
				Debug:  "cyan",
				Info:   "green",
				Warn:   "yellow",
				Error:  "red",
				DPanic: "magenta",
				Panic:  "magenta",
				Fatal:  "magenta",
			},
		},
		Database: config.DatabaseConfig{
			URL: "", // Expected to be set by env in tests
		},
		Engine: config.EngineConfig{
			QueueSize:          1000,
			WorkerConcurrency:  8,
			DefaultTaskTimeout: 15 * time.Minute,
		},
		Browser: config.BrowserConfig{
			Headless:        true,
			DisableCache:    true,
			IgnoreTLSErrors: false,
			Concurrency:     2,
			Debug:           true,
			Args: []string{
				"--no-sandbox",
				"--disable-setuid-sandbox",
				"--disable-dev-shm-usage",
				"--disable-gpu",
				"--no-first-run",
				"--no-default-browser-check",
				"--disable-popup-blocking",
				"--disable-prompt-on-repost",
				"--disable-extensions",
				"--disable-translate",
				"--disable-sync",
				"--disable-background-networking",
				"--disable-component-update",
				"--metrics-recording-only",
				"--mute-audio",
				"--safebrowsing-disable-auto-update",
			},
			Viewport: map[string]int{"width": 1920, "height": 1080}, // Corrected: Is a map, not a struct
			Humanoid: humanoid.Config{},                             // Corrected: Uses humanoid package type
		},
		Network: config.NetworkConfig{
			Timeout:               30 * time.Second,
			NavigationTimeout:     90 * time.Second,
			PostLoadWait:          2 * time.Second,
			CaptureResponseBodies: true,
			IgnoreTLSErrors:       false,
			Headers: map[string]string{
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 ScalpelV2/1.0",
			},
			Proxy: config.ProxyConfig{
				Enabled: false,
				Address: "127.0.0.1:8080",
			},
		},
		IAST: config.IASTConfig{
			Enabled: false,
		},
		Scanners: config.ScannersConfig{
			Passive: config.PassiveScannersConfig{ // Corrected: ...ScannersConfig
				Headers: config.HeadersConfig{Enabled: true}, // Corrected: HeadersConfig
			},
			Static: config.StaticScannersConfig{ // Corrected: ...ScannersConfig
				JWT: config.JWTConfig{ // Corrected: JWTConfig
					Enabled:           true,
					BruteForceEnabled: true,
					DictionaryFile:    "config/jwt.secrets.list",
				},
			},
			Active: config.ActiveScannersConfig{ // Corrected: ...ScannersConfig
				Taint: config.TaintConfig{ // Corrected: TaintConfig
					Enabled:     true,
					Depth:       3,
					Concurrency: 2,
				},
				ProtoPollution: config.ProtoPollutionConfig{ // Corrected: ProtoPollutionConfig
					Enabled:      true,
					WaitDuration: 8 * time.Second,
				},
				TimeSlip: config.TimeSlipConfig{ // Corrected: TimeSlipConfig
					Enabled:        true,
					RequestCount:   25,
					MaxConcurrency: 10,
					ThresholdMs:    500,
				},
				Auth: config.AuthConfig{ // Corrected: AuthConfig
					ATO: config.ATOConfig{ // Corrected: ATOConfig
						Enabled:                true, // Corrected: Is a plain bool
						Concurrency:            4,
						MinRequestDelayMs:      500,
						RequestDelayJitterMs:   500,
						SuccessKeywords:        []string{"welcome", "redirect", "dashboard", "logout", "\"success\":true"},
						UserFailureKeywords:    []string{"user not found", "invalid user", "no such account", "user does not exist"},
						PassFailureKeywords:    []string{"invalid password", "incorrect password", "authentication failed"},
						GenericFailureKeywords: []string{"login failed", "invalid credentials"},
						LockoutKeywords:        []string{"account locked", "too many attempts"},
					},
					IDOR: config.IDORConfig{ // Corrected: IDORConfig
						Enabled:    true,
						IgnoreList: []string{"csrf_token", "X-CSRF-Token", "nonce", "viewstate"},
						TestStrategies: map[string][]string{
							"NumericID":     {"increment", "decrement"},
							"UUID":          {"horizontal_swap"},
							"Base64Encoded": {"bit_flip"},
							"ObjectID":      {"increment_char"},
						},
					},
				},
			},
		},
		Discovery: config.DiscoveryConfig{
			MaxDepth:           5,
			Concurrency:        20,
			Timeout:            15 * time.Minute,
			PassiveEnabled:     boolp(true), // Corrected: This is the actual *bool field
			IncludeSubdomains:  true,
			CrtShRateLimit:     2.0,
			PassiveConcurrency: 10,
		},
		Agent: config.AgentConfig{
			LLM: config.LLMRouterConfig{ // Corrected: LLMRouterConfig
				DefaultFastModel:     "gemini-2.5-flash",
				DefaultPowerfulModel: "gemini-2.5-pro",
				Models:               make(map[string]config.LLMModelConfig),
			},
			KnowledgeGraph: config.KnowledgeGraphConfig{
				Type: "postgres",
			},
		},
		Autofix: config.AutofixConfig{
			Enabled:                false,
			MinConfidenceThreshold: 0.75,
			CooldownSeconds:        300,
			KeepWorkspaceOnFailure: false,
			Git: config.GitConfig{
				AuthorName:  "Kyle McAllister",
				AuthorEmail: "xkilldash9x@proton.me",
			},
			GitHub: config.GitHubConfig{
				RepoOwner:  "xkilldash9x",
				RepoName:   "scalpel-cli",
				BaseBranch: "main",
			},
		},
	}
}

// setupTestConfig provides a consistent and complete configuration state for tests.
// It starts with a default struct, then applies environment variables and sets
// required values like API keys.
func setupTestConfig(t *testing.T) *config.Config {
	t.Helper()

	// 1. Get the default, fully-populated config struct.
	cfg := newTestConfig()

	// 2. Set environment variables required for tests.
	t.Setenv("SCALPEL_GEMINI_API_KEY", "fake-api-key-for-testing")
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://test:test@localhost/testdb")

	// 3. Use Viper to layer environment variables over the default struct.
	// This correctly simulates the application's config loading priority.
	viper.Reset()
	viper.SetEnvPrefix("SCALPEL")
	viper.AutomaticEnv()

	// We unmarshal into the existing struct to override the defaults with any
	// environment variables that were set.
	err := viper.Unmarshal(cfg)
	require.NoError(t, err, "Failed to unmarshal test config")

	// 4. Manually populate any complex fields that aren't easily set by defaults/env.
	if cfg.Agent.LLM.Models == nil {
		cfg.Agent.LLM.Models = make(map[string]config.LLMModelConfig)
	}
	cfg.Agent.LLM.Models["gemini-2.5-flash"] = config.LLMModelConfig{
		Provider: config.ProviderGemini,
		Model:    "gemini-2.5-flash",
	}

	// 5. Set the now-configured struct as the global instance for the test.
	config.Set(cfg)

	return cfg
}
