// File: internal/config/config_test.go
package config

import (
	"bytes"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- Constructor and Defaults Tests --

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()

	// Verify a few key defaults to ensure the mechanism works.
	assert.Equal(t, "info", cfg.Logger().Level)
	assert.Equal(t, 10, cfg.Engine().WorkerConcurrency)
	assert.True(t, cfg.Browser().Headless)
	// FIX: The default network timeout is 2m, not 30s.
	assert.Equal(t, 2*time.Minute, cfg.Network().Timeout)
	assert.Equal(t, "postgres", cfg.Agent().KnowledgeGraph.Type)
	// FIX: The default powerful model is gemini-3-pro, not gemini-2.5-pro.
	assert.Equal(t, "gemini-3-pro", cfg.Agent().LLM.DefaultPowerfulModel)
	assert.False(t, cfg.Autofix().Enabled)
	assert.Equal(t, 0.75, cfg.Autofix().MinConfidenceThreshold)
	assert.Equal(t, "scalpel-autofix-bot", cfg.Autofix().Git.AuthorName)

	// FIX: Verify that the defaults are correctly populated by the fallback logic.
	assert.NotEmpty(t, cfg.Agent().LLM.Models, "Default models map should not be empty")
	assert.Contains(t, cfg.Agent().LLM.Models, "gemini-2.5-flash")
}

// -- Validation Logic Tests --

func TestConfigValidation(t *testing.T) {
	t.Run("Core Validation", func(t *testing.T) {
		// Start with a valid default config.
		cfg := NewDefaultConfig()
		cfg.DatabaseCfg.URL = "postgres://user:pass@host/db"

		// Test Case: Valid Config
		err := cfg.Validate()
		assert.NoError(t, err, "A valid config should not produce a validation error")

		// Test Case: Invalid Engine Concurrency
		cfgInvalidEngine := *cfg
		cfgInvalidEngine.EngineCfg.WorkerConcurrency = 0
		err = cfgInvalidEngine.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "engine.worker_concurrency must be a positive integer")

		// Test Case: Invalid Browser Concurrency
		cfgInvalidBrowser := *cfg
		cfgInvalidBrowser.BrowserCfg.Concurrency = -1
		err = cfgInvalidBrowser.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "browser.concurrency must be a positive integer")
	})

	t.Run("Autofix Validation", func(t *testing.T) {
		validAutofix := AutofixConfig{
			Enabled:                true,
			MinConfidenceThreshold: 0.8,
			GitHub: GitHubConfig{
				Token:      "ghp_testtoken123",
				RepoOwner:  "test-owner",
				RepoName:   "test-repo",
				BaseBranch: "main",
			},
		}

		err := validAutofix.Validate()
		assert.NoError(t, err)

		disabledAutofix := validAutofix
		disabledAutofix.Enabled = false
		disabledAutofix.GitHub.Token = ""
		err = disabledAutofix.Validate()
		assert.NoError(t, err)

		invalidThresholdHigh := validAutofix
		invalidThresholdHigh.MinConfidenceThreshold = 1.1
		err = invalidThresholdHigh.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "min_confidence_threshold must be between 0.0 and 1.0")

		missingRepoOwner := validAutofix
		missingRepoOwner.GitHub.RepoOwner = ""
		err = missingRepoOwner.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "github.repo_owner, github.repo_name, and github.base_branch are required")

		missingToken := validAutofix
		missingToken.GitHub.Token = ""
		err = missingToken.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "GitHub token is required but not found")
	})

	t.Run("Evolution Validation", func(t *testing.T) {
		validEvo := EvolutionConfig{
			Enabled:    true,
			MaxCycles:  10,
			SettleTime: 500 * time.Millisecond,
		}
		assert.NoError(t, validEvo.Validate())

		disabledEvo := validEvo
		disabledEvo.Enabled = false
		assert.NoError(t, disabledEvo.Validate(), "disabled evolution config should always be valid")

		invalidCycles := validEvo
		invalidCycles.MaxCycles = 0
		err := invalidCycles.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max_cycles must be greater than 0")

		invalidSettleTime := validEvo
		invalidSettleTime.SettleTime = -1 * time.Second
		err = invalidSettleTime.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "settle_time must be a positive duration")
	})

	// Add LTM Validation test for completeness
	t.Run("LTM Validation", func(t *testing.T) {
		validLTM := LTMConfig{
			CacheTTLSeconds:             300,
			CacheJanitorIntervalSeconds: 60,
		}
		assert.NoError(t, validLTM.Validate())

		invalidTTL := validLTM
		invalidTTL.CacheTTLSeconds = 0
		err := invalidTTL.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "agent.ltm.cache_ttl_seconds must be a positive integer")

		invalidJanitor := validLTM
		invalidJanitor.CacheJanitorIntervalSeconds = -1
		err = invalidJanitor.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "agent.ltm.cache_janitor_interval_seconds must be a positive integer")
	})

	// FIX: Added LLM Validation tests
	t.Run("LLM Validation", func(t *testing.T) {
		validLLM := NewDefaultConfig().AgentCfg.LLM
		assert.NoError(t, validLLM.Validate())

		// Case: Missing Default Fast Model
		missingFast := validLLM
		missingFast.DefaultFastModel = ""
		err := missingFast.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "default_fast_model must be set")

		// Case: Default Fast Model Not In Map
		invalidFast := validLLM
		invalidFast.DefaultFastModel = "non-existent-model"
		err = invalidFast.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "default_fast_model 'non-existent-model' not found")

		// Case: Missing Provider in a model
		missingProvider := validLLM
		// Create a copy of the map to avoid modifying the original validLLM
		missingProvider.Models = make(map[string]LLMModelConfig)
		for k, v := range validLLM.Models {
			missingProvider.Models[k] = v
		}
		model := missingProvider.Models["gemini-2.5-flash"]
		model.Provider = ""
		missingProvider.Models["gemini-2.5-flash"] = model
		err = missingProvider.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "has no provider")

		// Case: Empty Models Map (Testing the validation safeguard)
		emptyModels := validLLM
		emptyModels.Models = map[string]LLMModelConfig{}
		err = emptyModels.Validate()
		assert.Error(t, err, "Validation should fail if the models map is empty")
		assert.Contains(t, err.Error(), "no LLM models are configured")
	})
}

// -- Factory Function Tests --

func TestNewConfigFromViper(t *testing.T) {
	t.Run("Successful Load from YAML", func(t *testing.T) {
		// This test now *only* checks loading from a YAML buffer,
		// *without* calling NewConfigFromViper, which binds env vars.
		// This is similar to TestConfigStructureMapping but ensures
		// the values are what we expect and not from the env.
		yamlBytes := []byte(`
database:
  url: "postgres://test:test@localhost/test"
engine:
  worker_concurrency: 4
browser:
  concurrency: 2
`)
		v := viper.New()
		SetDefaults(v) // Set defaults first
		v.SetConfigType("yaml")
		err := v.ReadConfig(bytes.NewBuffer(yamlBytes))
		require.NoError(t, err)

		// We unmarshal directly into a Config struct
		var cfg Config
		err = v.Unmarshal(&cfg)
		require.NoError(t, err)

		// We *don't* call cfg.Validate() here because the YAML is incomplete
		// and doesn't contain autofix, etc. This test is just for
		// checking the YAML unmarshal precedence.
		assert.Equal(t, "postgres://test:test@localhost/test", cfg.Database().URL)
		assert.Equal(t, 4, cfg.Engine().WorkerConcurrency)
		// Check a default value was also loaded
		assert.Equal(t, "info", cfg.Logger().Level)
	})

	t.Run("Validation Failure", func(t *testing.T) {
		// This test *does* use NewConfigFromViper to test its
		// *validation* step.
		v := viper.New()
		SetDefaults(v)
		v.Set("engine.worker_concurrency", 0) // Intentionally invalid

		cfg, err := NewConfigFromViper(v)
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "invalid configuration")
		assert.Contains(t, err.Error(), "engine.worker_concurrency must be a positive integer")
	})

	t.Run("Environment Variable Binding", func(t *testing.T) {
		// This test confirms that NewConfigFromViper *correctly*
		// binds and loads from environment variables, *overriding*
		// values from a config file.
		v := viper.New()
		SetDefaults(v)

		// Set values that are required for validation
		v.Set("autofix.enabled", true)
		v.Set("autofix.github.repo_owner", "owner")
		v.Set("autofix.github.repo_name", "repo")
		v.Set("autofix.github.base_branch", "main")

		// --- Simulate loading from a config file ---
		// Set a "config file" value for database.url
		// We use a config buffer to simulate a lower-precedence source.
		yamlConfig := []byte(`
database:
  url: "postgres://configfile/db"
`)
		v.SetConfigType("yaml")
		err := v.ReadConfig(bytes.NewBuffer(yamlConfig))
		require.NoError(t, err, "Failed to read mock config buffer")
		// ------------------------------------------

		// Set environment variables
		testToken := "ghp_env_var_token_456"
		t.Setenv("SCALPEL_AUTOFIX_GH_TOKEN", testToken)
		testKGPassword := "securepassword123"
		t.Setenv("SCALPEL_KG_PASSWORD", testKGPassword)
		testDBURL := "postgres://envvar/db"
		t.Setenv("SCALPEL_DATABASE_URL", testDBURL)

		// Now call the function that binds them
		cfg, err := NewConfigFromViper(v)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Check that env vars were loaded
		assert.Equal(t, testToken, cfg.Autofix().GitHub.Token)
		assert.Equal(t, testKGPassword, cfg.Agent().KnowledgeGraph.Postgres.Password)
		// CRITICAL: Check that the env var *overrode* the value from the config buffer
		assert.Equal(t, testDBURL, cfg.Database().URL)
	})

	// FIX: Added this test to verify the complex LLM model merging/fallback logic.
	t.Run("LLM Model Loading - Partial Override (Viper Merge Behavior)", func(t *testing.T) {
		// Simulate a user config that overrides one default model and adds a new one.
		// This tests how Viper merges maps by default when SetDefaults is used.
		yamlBytes := []byte(`
agent:
  llm:
    default_fast_model: "custom-fast"
    models:
      gemini-2.5-flash: # Overriding a default
        temperature: 0.5
        api_timeout: "5m"
      custom-fast: # Adding a new model
        provider: "ollama"
        model: "llama3-8b"
        api_timeout: "1m"
`)
		v := viper.New()
		SetDefaults(v) // 1. Set defaults (includes all Gemini models)
		v.SetConfigType("yaml")
		err := v.ReadConfig(bytes.NewBuffer(yamlBytes)) // 2. Load user config
		require.NoError(t, err)

		// 3. Call the function that performs the merge and validation
		cfg, err := NewConfigFromViper(v)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		llmConfig := cfg.Agent().LLM

		// Assert: Check the overridden default model
		flashModel, ok := llmConfig.Models["gemini-2.5-flash"]
		require.True(t, ok, "gemini-2.5-flash should exist")
		assert.Equal(t, 0.5, flashModel.Temperature, "Temperature should be overridden by YAML")
		assert.Equal(t, 5*time.Minute, flashModel.APITimeout, "APITimeout should be overridden by YAML")
		assert.Equal(t, ProviderGemini, flashModel.Provider, "Provider should remain the default") // Default not overridden in YAML

		// Assert: Check the new custom model
		customModel, ok := llmConfig.Models["custom-fast"]
		require.True(t, ok, "custom-fast should exist")
		assert.Equal(t, ProviderOllama, customModel.Provider)
		assert.Equal(t, "llama3-8b", customModel.Model)

		// Assert: Check that defaults *not* mentioned in YAML still exist (Viper default merge behavior)
		proModel, ok := llmConfig.Models["gemini-3-pro"]
		require.True(t, ok, "gemini-3-pro should still exist from defaults")
		assert.Equal(t, "gemini-3-pro-preview", proModel.Model, "Model name should be the default")

		// Assert: Check the default fast model override
		assert.Equal(t, "custom-fast", llmConfig.DefaultFastModel)
	})

	// FIX: This test verifies that the fallback still works if the config file is missing the models section entirely.
	t.Run("LLM Model Loading - Fallback to Defaults", func(t *testing.T) {
		// Arrange: A minimal YAML config without the agent.llm.models section.
		yamlBytes := []byte(`
engine:
  worker_concurrency: 5
`)
		v := viper.New()
		SetDefaults(v) // Defaults are set, including LLM models.
		v.SetConfigType("yaml")
		err := v.ReadConfig(bytes.NewBuffer(yamlBytes))
		require.NoError(t, err)

		// Act
		cfg, err := NewConfigFromViper(v)
		require.NoError(t, err)

		// Assert
		// The configuration should contain the default models provided by SetDefaults/Robust Fallback.
		assert.NotEmpty(t, cfg.Agent().LLM.Models)
		assert.Contains(t, cfg.Agent().LLM.Models, "gemini-2.5-flash")
		assert.Equal(t, "gemini-2.5-flash", cfg.Agent().LLM.DefaultFastModel)
	})

	// FIX: This test verifies the behavior when the user explicitly provides an empty map.
	t.Run("LLM Model Loading - Explicitly Empty", func(t *testing.T) {
		// Arrange: YAML config explicitly setting models to empty.
		yamlBytes := []byte(`
agent:
  llm:
    models: {}
`)
		v := viper.New()
		SetDefaults(v)
		v.SetConfigType("yaml")
		err := v.ReadConfig(bytes.NewBuffer(yamlBytes))
		require.NoError(t, err)

		// Act
		// The Robust Fallback logic should detect the map is empty (Viper unmarshals {} as an empty map)
		// and repopulate it with defaults.
		cfg, err := NewConfigFromViper(v)

		// Assert
		require.NoError(t, err)
		assert.NotEmpty(t, cfg.Agent().LLM.Models, "Robust fallback should ensure models are populated if empty in config")
		assert.Contains(t, cfg.Agent().LLM.Models, "gemini-2.5-flash")
	})
}

// -- Struct and Mapping Tests --

func TestConfigStructureMapping(t *testing.T) {
	yamlInput := `
logger:
  level: debug
  log_file: /var/log/app.log
network:
  timeout: 5s
scanners:
  active:
    auth:
      idor:
        test_strategies:
          numericid: ["increment"]
`
	v := viper.New()
	SetDefaults(v) // Set defaults first
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewBufferString(yamlInput))
	require.NoError(t, err)

	var cfg Config
	err = v.Unmarshal(&cfg)
	require.NoError(t, err)

	assert.Equal(t, "debug", cfg.Logger().Level)
	assert.Equal(t, "/var/log/app.log", cfg.Logger().LogFile)
	assert.Equal(t, 5*time.Second, cfg.Network().Timeout)
	require.NotNil(t, cfg.Scanners().Active.Auth.IDOR.TestStrategies)
	assert.Contains(t, cfg.Scanners().Active.Auth.IDOR.TestStrategies["numericid"], "increment")
}
