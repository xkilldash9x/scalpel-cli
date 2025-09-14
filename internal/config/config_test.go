package config

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
    // Importing humanoid ensures the Config struct definition is complete,
    // although we don't reference it directly in the tests here.
	_ "github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// resetSingleton resets the singleton instance and the once synchronization primitive.
// This allows us to test initialization logic (Load, Set) in isolation for each test case.
func resetSingleton() {
	instance = nil
	// Resetting sync.Once by assigning a new instance.
	once = sync.Once{}
}

// TestGetUninitialized verifies that Get() panics if called before initialization.
func TestGetUninitialized(t *testing.T) {
	resetSingleton()
	t.Cleanup(resetSingleton)

	assert.PanicsWithValue(t, "Configuration not initialized. Ensure initialization happens in the root command.", func() {
		Get()
	}, "Get() should panic if the configuration is not initialized")
}

// TestSetAndGet verifies the basic Set/Get functionality and the singleton guarantee.
func TestSetAndGet(t *testing.T) {
	resetSingleton()
	t.Cleanup(resetSingleton)

	cfg1 := &Config{
		Logger: LoggerConfig{Level: "info"},
		Engine: EngineConfig{DefaultTaskTimeout: 5 * time.Minute},
	}

	// 1. Initial Set
	Set(cfg1)
	retrievedCfg1 := Get()

	assert.Same(t, cfg1, retrievedCfg1, "Get() should return the exact same instance set by Set()")
	assert.Equal(t, 5*time.Minute, retrievedCfg1.Engine.DefaultTaskTimeout)

	// 2. Test that Set only works once (sync.Once behavior)
	cfg2 := &Config{
		Logger: LoggerConfig{Level: "debug"},
	}
	Set(cfg2)
	retrievedCfg2 := Get()

	// It should still return the first config
	assert.Same(t, cfg1, retrievedCfg2, "Set() should not overwrite the configuration instance if called again")
	assert.NotEqual(t, "debug", retrievedCfg2.Logger.Level, "Configuration values should not change on second Set()")
}

// TestLoad verifies the Load function initializes the singleton using Viper configuration.
func TestLoad(t *testing.T) {
	resetSingleton()
	t.Cleanup(resetSingleton)

	v := viper.New()
	v.SetConfigType("yaml")

	// 1. Test initialization via Load()
	yamlConfig := `
logger:
  level: debug
engine:
  queue_size: 100
  default_task_timeout: 30s
browser:
  headless: true
`
	err := v.ReadConfig(strings.NewReader(yamlConfig))
	require.NoError(t, err, "Viper should read the mock config without error")

	err = Load(v)
	require.NoError(t, err, "Load() should complete without error")

	cfg1 := Get()
	require.NotNil(t, cfg1, "Get() should return a non-nil config after Load()")

	// Verify values
	assert.Equal(t, "debug", cfg1.Logger.Level)
	assert.Equal(t, 100, cfg1.Engine.QueueSize)
	assert.Equal(t, 30*time.Second, cfg1.Engine.DefaultTaskTimeout)
	assert.True(t, cfg1.Browser.Headless)

	// 2. Test singleton behavior (Load only works once)
	v2 := viper.New()
	v2.Set("logger.level", "error")
	err = Load(v2)
	// The error should be nil because Load returns the previous loadErr (which was nil) if once.Do already ran.
	assert.Nil(t, err)

	cfg2 := Get()
    assert.Same(t, cfg1, cfg2)
	// It should still return the first loaded config ("debug")
	assert.Equal(t, "debug", cfg2.Logger.Level, "Load() should not overwrite the configuration if called again")
}

// TestLoadUnmarshalError verifies that Load returns an error and does not initialize the instance on failure.
func TestLoadUnmarshalError(t *testing.T) {
	resetSingleton()
	t.Cleanup(resetSingleton)

	v := viper.New()
	v.SetConfigType("yaml")

	// Invalid configuration: wrong type for queue_size
	yamlConfig := `
engine:
  queue_size: "not_an_int"
`
	err := v.ReadConfig(strings.NewReader(yamlConfig))
	require.NoError(t, err)

	// 1. Test Load failure
	err = Load(v)
	assert.Error(t, err, "Load() should return an error if unmarshaling fails")
	assert.Contains(t, err.Error(), "error unmarshaling config")

	// Ensure instance is still nil (Get() should panic)
	assert.Panics(t, func() { Get() })

	// 2. Test subsequent Load calls return the initial error
    // sync.Once considers the initialization "done", but the captured loadErr holds the error.
	v2 := viper.New()
	err2 := Load(v2)
	assert.Error(t, err2, "Subsequent Load() calls should return the initial error")
	assert.Equal(t, err, err2)
}

// TestConfigStructureMapping tests if the mapstructure tags are correctly defined
// by unmarshaling a comprehensive configuration.
func TestConfigStructureMapping(t *testing.T) {
    // This test does not rely on the singleton and tests the struct definitions directly.
	v := viper.New()

	// Set a comprehensive set of configuration values using Viper keys.
	// Logger
	v.Set("logger.level", "warn")
	v.Set("logger.format", "json")
	v.Set("logger.add_source", true)
	v.Set("logger.max_size", 10)
	v.Set("logger.colors.info", "green")
	v.Set("logger.colors.error", "red")

	// Database
	v.Set("database.url", "postgres://user:pass@localhost:5432/testdb")

	// Engine
	v.Set("engine.queue_size", 1000)
	v.Set("engine.worker_concurrency", 5)
	v.Set("engine.default_task_timeout", "30s")

	// Browser
	v.Set("browser.headless", true)
	v.Set("browser.disableCache", true)
	v.Set("browser.ignore_tls_errors", true)
	v.Set("browser.args", []string{"--no-sandbox", "--disable-gpu"})
	v.Set("browser.viewport.width", 1920)
	v.Set("browser.viewport.height", 1080)
	// Note: humanoid.Config details are tested in the internal/humanoid package.

	// Network
	v.Set("network.timeout", "15s")
	v.Set("network.captureResponseBodies", true)
	// FIX IS HERE: Set the entire map object instead of a nested key.
	v.Set("network.headers", map[string]string{"User-Agent": "Scalpel-Test"})
	v.Set("network.postLoadWait", "1s")

	// IAST (Testing both mapstructure and yaml tags where applicable)
	v.Set("iast.enabled", true)
	v.Set("iast.shimPath", "/path/to/shim.js") // mapstructure:"shimPath"
	// If loading from YAML, "shim_path" would also work.

	// Scanners - Passive
	v.Set("scanners.passive.headers.enabled", true)

	// Scanners - Static
	v.Set("scanners.static.jwt.enabled", true)
	v.Set("scanners.static.jwt.known_secrets", []string{"secret1", "secret2"})
	v.Set("scanners.static.jwt.brute_force_enabled", false)

	// Scanners - Active
	v.Set("scanners.active.taint.enabled", true)
	v.Set("scanners.active.taint.depth", 3)
	v.Set("scanners.active.protopollution.enabled", false)
	v.Set("scanners.active.timeslip.enabled", true)
	v.Set("scanners.active.timeslip.threshold_ms", 500)

	// Scanners - Auth
	v.Set("scanners.active.auth.ato.enabled", true)
	v.Set("scanners.active.auth.ato.concurrency", 2)
	v.Set("scanners.active.auth.ato.successKeywords", []string{"welcome"})

	v.Set("scanners.active.auth.idor.enabled", true)
	v.Set("scanners.active.auth.idor.ignore_list", []string{"/logout"})
	v.Set("scanners.active.auth.idor.test_strategies.numeric", []string{"increment"})

	// Discovery
	v.Set("discovery.maxDepth", 3)
	v.Set("discovery.timeout", "5m")
	v.Set("discovery.passiveEnabled", true) // Testing pointer bool
	v.Set("discovery.crtShRateLimit", 1.5)

	// Agent
	v.Set("agent.enabled", true)
	v.Set("agent.llm.default_fast_model", "fast-model")
	v.Set("agent.llm.models.test-model.provider", "openai")
	v.Set("agent.llm.models.test-model.model", "gpt-3.5-turbo")
	v.Set("agent.llm.models.test-model.api_timeout", "60s")
	v.Set("agent.llm.models.test-model.temperature", 0.7)
    v.Set("agent.llm.models.test-model.safety_filters.harassment", "block_low")

	// Unmarshal directly into a new Config struct
	var cfg Config
	err := v.Unmarshal(&cfg)
	require.NoError(t, err, "Viper unmarshal should succeed")

	// Assertions
	// Logger
	assert.Equal(t, "warn", cfg.Logger.Level)
	assert.True(t, cfg.Logger.AddSource)
	assert.Equal(t, "green", cfg.Logger.Colors.Info)
	assert.Equal(t, "red", cfg.Logger.Colors.Error)

	// Database
	assert.Equal(t, "postgres://user:pass@localhost:5432/testdb", cfg.Database.URL)

	// Engine
	assert.Equal(t, 5, cfg.Engine.WorkerConcurrency)
	assert.Equal(t, 30*time.Second, cfg.Engine.DefaultTaskTimeout)

	// Browser
	assert.True(t, cfg.Browser.Headless)
	assert.True(t, cfg.Browser.IgnoreTLSErrors)
	assert.Contains(t, cfg.Browser.Args, "--no-sandbox")
	assert.Equal(t, 1920, cfg.Browser.Viewport["width"])

	// Network
	assert.Equal(t, 15*time.Second, cfg.Network.Timeout)
	assert.Equal(t, "Scalpel-Test", cfg.Network.Headers["User-Agent"])
	assert.Equal(t, 1*time.Second, cfg.Network.PostLoadWait)

	// IAST
	assert.True(t, cfg.IAST.Enabled)
	assert.Equal(t, "/path/to/shim.js", cfg.IAST.ShimPath)

	// Scanners
	assert.True(t, cfg.Scanners.Passive.Headers.Enabled)
	assert.Contains(t, cfg.Scanners.Static.JWT.KnownSecrets, "secret1")
	assert.False(t, cfg.Scanners.Static.JWT.BruteForceEnabled)
	assert.Equal(t, 3, cfg.Scanners.Active.Taint.Depth)
	assert.False(t, cfg.Scanners.Active.ProtoPollution.Enabled)
	assert.Equal(t, 500, cfg.Scanners.Active.TimeSlip.ThresholdMs)
	assert.True(t, cfg.Scanners.Active.Auth.ATO.Enabled)
	assert.Contains(t, cfg.Scanners.Active.Auth.ATO.SuccessKeywords, "welcome")
	assert.True(t, cfg.Scanners.Active.Auth.IDOR.Enabled)
	assert.Equal(t, []string{"increment"}, cfg.Scanners.Active.Auth.IDOR.TestStrategies["numeric"])

	// Discovery
	assert.Equal(t, 3, cfg.Discovery.MaxDepth)
	assert.Equal(t, 5*time.Minute, cfg.Discovery.Timeout)
	require.NotNil(t, cfg.Discovery.PassiveEnabled)
	assert.True(t, *cfg.Discovery.PassiveEnabled)
    assert.Equal(t, 1.5, cfg.Discovery.CrtShRateLimit)

	// Agent
	assert.True(t, cfg.Agent.Enabled)
	require.Contains(t, cfg.Agent.LLM.Models, "test-model")
	modelCfg := cfg.Agent.LLM.Models["test-model"]
	assert.Equal(t, ProviderOpenAI, modelCfg.Provider)
	assert.Equal(t, float32(0.7), modelCfg.Temperature)
	assert.Equal(t, 60*time.Second, modelCfg.APITimeout)
    assert.Equal(t, "block_low", modelCfg.SafetyFilters["harassment"])

	// ScanConfig (should be empty as it's excluded via `mapstructure:"-"`)
	assert.Empty(t, cfg.Scan.Targets)
}