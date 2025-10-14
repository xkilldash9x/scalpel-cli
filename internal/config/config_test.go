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
	assert.Equal(t, 30*time.Second, cfg.Network().Timeout)
	assert.Equal(t, "postgres", cfg.Agent().KnowledgeGraph.Type)
	assert.Equal(t, "gemini-2.5-pro", cfg.Agent().LLM.DefaultPowerfulModel)
	assert.False(t, cfg.Autofix().Enabled)
	assert.Equal(t, 0.75, cfg.Autofix().MinConfidenceThreshold)
	assert.Equal(t, "scalpel-autofix-bot", cfg.Autofix().Git.AuthorName)
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
}

// -- Factory Function Tests --

func TestNewConfigFromViper(t *testing.T) {
	t.Run("Successful Load", func(t *testing.T) {
		// Renaming this variable to avoid any potential linter confusion or hidden name collisions.
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

		cfg, err := NewConfigFromViper(v)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "postgres://test:test@localhost/test", cfg.Database().URL)
		assert.Equal(t, 4, cfg.Engine().WorkerConcurrency)
	})

	t.Run("Validation Failure", func(t *testing.T) {
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
		v := viper.New()
		SetDefaults(v)

		v.Set("autofix.enabled", true)
		v.Set("autofix.github.repo_owner", "owner")
		v.Set("autofix.github.repo_name", "repo")
		v.Set("autofix.github.base_branch", "main")
		v.Set("database.url", "postgres://localhost/db")

		testToken := "ghp_env_var_token_456"
		t.Setenv("SCALPEL_AUTOFIX_GH_TOKEN", testToken)
		testKGPassword := "securepassword123"
		t.Setenv("SCALPEL_KG_PASSWORD", testKGPassword)

		cfg, err := NewConfigFromViper(v)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, testToken, cfg.Autofix().GitHub.Token)
		assert.Equal(t, testKGPassword, cfg.Agent().KnowledgeGraph.Postgres.Password)
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
