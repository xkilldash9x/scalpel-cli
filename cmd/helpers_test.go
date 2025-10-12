// File: cmd/helpers_test.go
package cmd

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// newTestConfig creates a fully populated configuration for use in tests by setting
// values in Viper and unmarshaling them into the config struct. This provides a
// consistent baseline for testing without using struct literals, which is no longer
// possible due to private fields.
func newTestConfig(t *testing.T) config.Interface {
	t.Helper()
	v := viper.New()

	// -- Logger --
	v.Set("logger.service_name", "scalpel-cli")
	v.Set("logger.log_file", "logs/scalpel.log")
	v.Set("logger.level", "info")
	v.Set("logger.format", "json")
	v.Set("logger.add_source", false)
	v.Set("logger.max_size", 10)
	v.Set("logger.max_backups", 3)
	v.Set("logger.max_age", 7)
	v.Set("logger.compress", true)
	v.Set("logger.colors.debug", "cyan")
	v.Set("logger.colors.info", "green")
	v.Set("logger.colors.warn", "yellow")
	v.Set("logger.colors.error", "red")
	v.Set("logger.colors.dpanic", "magenta")
	v.Set("logger.colors.panic", "magenta")
	v.Set("logger.colors.fatal", "magenta")

	// -- Database --
	// URL is expected to be set by env in tests

	// -- Engine --
	v.Set("engine.queue_size", 1000)
	v.Set("engine.worker_concurrency", 8)
	v.Set("engine.default_task_timeout", 15*time.Minute)

	// -- Browser --
	v.Set("browser.headless", true)
	v.Set("browser.disable_cache", true)
	v.Set("browser.ignore_tls_errors", false)
	v.Set("browser.concurrency", 2)
	v.Set("browser.debug", true)
	v.Set("browser.args", []string{
		"--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage",
		"--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--disable-popup-blocking", "--disable-prompt-on-repost", "--disable-extensions",
		"--disable-translate", "--disable-sync", "--disable-background-networking",
		"--disable-component-update", "--metrics-recording-only", "--mute-audio",
		"--safebrowsing-disable-auto-update",
	})
	v.Set("browser.viewport.width", 1920)
	v.Set("browser.viewport.height", 1080)
	v.Set("browser.humanoid.enabled", true)
	v.Set("browser.humanoid.providers", []string{"fingerprint", "header"})

	// -- Network --
	v.Set("network.timeout", 30*time.Second)
	v.Set("network.navigation_timeout", 90*time.Second)
	v.Set("network.post_load_wait", 2*time.Second)
	v.Set("network.capture_response_bodies", true)
	v.Set("network.ignore_tls_errors", false)
	v.Set("network.headers.User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 ScalpelV2/1.0")
	v.Set("network.proxy.enabled", false)
	v.Set("network.proxy.address", "127.0.0.1:8080")

	// -- IAST --
	v.Set("iast.enabled", false)

	// -- Scanners --
	v.Set("scanners.passive.headers.enabled", true)
	v.Set("scanners.static.jwt.enabled", true)
	v.Set("scanners.static.jwt.brute_force_enabled", true)
	v.Set("scanners.static.jwt.dictionary_file", "config/jwt.secrets.list")
	v.Set("scanners.active.taint.enabled", true)
	v.Set("scanners.active.taint.depth", 3)
	v.Set("scanners.active.taint.concurrency", 2)
	v.Set("scanners.active.protopollution.enabled", true)
	v.Set("scanners.active.protopollution.wait_duration", 8*time.Second)
	v.Set("scanners.active.timeslip.enabled", true)
	v.Set("scanners.active.timeslip.request_count", 25)
	v.Set("scanners.active.timeslip.max_concurrency", 10)
	v.Set("scanners.active.timeslip.threshold_ms", 500)
	v.Set("scanners.active.auth.ato.enabled", true)
	v.Set("scanners.active.auth.ato.concurrency", 4)
	v.Set("scanners.active.auth.ato.min_request_delay_ms", 500)
	v.Set("scanners.active.auth.ato.request_delay_jitter_ms", 500)
	v.Set("scanners.active.auth.ato.success_keywords", []string{"welcome", "redirect", "dashboard", "logout", "\"success\":true"})
	v.Set("scanners.active.auth.ato.user_failure_keywords", []string{"user not found", "invalid user", "no such account", "user does not exist"})
	v.Set("scanners.active.auth.ato.pass_failure_keywords", []string{"invalid password", "incorrect password", "authentication failed"})
	v.Set("scanners.active.auth.ato.generic_failure_keywords", []string{"login failed", "invalid credentials"})
	v.Set("scanners.active.auth.ato.lockout_keywords", []string{"account locked", "too many attempts"})
	v.Set("scanners.active.auth.idor.enabled", true)
	v.Set("scanners.active.auth.idor.ignore_list", []string{"csrf_token", "X-CSRF-Token", "nonce", "viewstate"})
	v.Set("scanners.active.auth.idor.test_strategies.NumericID", []string{"increment", "decrement"})
	v.Set("scanners.active.auth.idor.test_strategies.UUID", []string{"horizontal_swap"})
	v.Set("scanners.active.auth.idor.test_strategies.Base64Encoded", []string{"bit_flip"})
	v.Set("scanners.active.auth.idor.test_strategies.ObjectID", []string{"increment_char"})

	// -- Discovery --
	v.Set("discovery.max_depth", 5)
	v.Set("discovery.concurrency", 20)
	v.Set("discovery.timeout", 15*time.Minute)
	v.Set("discovery.passive_enabled", true)
	v.Set("discovery.include_subdomains", true)
	v.Set("discovery.crtsh_rate_limit", 2.0)
	v.Set("discovery.passive_concurrency", 10)

	// -- Agent --
	v.Set("agent.llm.default_fast_model", "gemini-2.5-flash")
	v.Set("agent.llm.default_powerful_model", "gemini-2.5-pro")
	v.Set("agent.knowledge_graph.type", "postgres")

	// -- Autofix --
	v.Set("autofix.enabled", false)
	v.Set("autofix.min_confidence_threshold", 0.75)
	v.Set("autofix.cooldown_seconds", 300)
	v.Set("autofix.keep_workspace_on_failure", false)
	v.Set("autofix.git.author_name", "Kyle McAllister")
	v.Set("autofix.git.author_email", "xkilldash9x@proton.me")
	v.Set("autofix.github.repo_owner", "xkilldash9x")
	v.Set("autofix.github.repo_name", "scalpel-cli")
	v.Set("autofix.github.base_branch", "main")

	cfg, err := config.NewConfigFromViper(v)
	require.NoError(t, err, "Failed to create new test config from viper")

	return cfg
}

// setupCompleteTestConfig provides a consistent and complete configuration state for tests.
// It starts with a default Viper-based config, then layers environment variables over it.
func setupCompleteTestConfig(t *testing.T) config.Interface {
	t.Helper()

	// 1. Get the default, fully-populated config from our helper.
	// This returns an interface, but we know the underlying type is *config.Config
	// for the purpose of unmarshaling.
	cfg := newTestConfig(t)

	// 2. Set environment variables required for tests.
	t.Setenv("SCALPEL_GEMINI_API_KEY", "fake-api-key-for-testing")
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://test:test@localhost/testdb")

	// 3. Use a new Viper instance to layer environment variables over the defaults.
	v := viper.New()
	v.SetEnvPrefix("SCALPEL")
	v.AutomaticEnv()

	// Unmarshal into the existing config struct to override defaults with env vars.
	// We must cast the interface to its concrete type for viper to unmarshal into it.
	err := v.Unmarshal(cfg.(*config.Config))
	require.NoError(t, err, "Failed to unmarshal env vars into test config")

	// 4. Manually populate any complex fields that aren't easily set by defaults/env.
	// This part is tricky now because we have an interface. The best way is to
	// expose a new setter on the interface if this is needed. For this specific
	// case, the model config should ideally be part of the viper setup.
	// For now, this step is removed as it's not compatible with the interface.
	// If required, we would add a `SetLLMModel(key string, model Cfg)` to the interface.

	return cfg
}
