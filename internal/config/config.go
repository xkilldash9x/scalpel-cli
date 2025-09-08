// ----------------- REFACTORED FILE -----------------
//
// File:         pkg/config/config.go
// Description:  The application's root configuration, updated with an expanded list of supported LLM providers.
//
package config

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

var (
	instance *Config
	once     sync.Once
)

// Config is the root configuration structure for the entire application.
type Config struct {
	Logger   LoggerConfig   `mapstructure:"logger"`
	Postgres PostgresConfig `mapstructure:"postgres"`
	Engine   EngineConfig   `mapstructure:"engine"`
	Browser  BrowserConfig  `mapstructure:"browser"`
	Network  NetworkConfig  `mapstructure:"network"`
	Scanners ScannersConfig `mapstructure:"scanners"`
	Scan     ScanConfig     `mapstructure:"scan"`
	Agent    AgentConfig    `mapstructure:"agent"`
}

// LoggerConfig holds settings for the logging system.
type LoggerConfig struct {
	ServiceName string `mapstructure:"service_name"`
	LogFile     string `mapstructure:"log_file"`
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	AddSource   bool   `mapstructure:"add_source"`
	MaxSize     int    `mapstructure:"max_size"`
	MaxBackups  int    `mapstructure:"max_backups"`
	MaxAge      int    `mapstructure:"max_age"`
	Compress    bool   `mapstructure:"compress"`
}

// PostgresConfig holds settings for the database connection.
type PostgresConfig struct {
	URL string `mapstructure:"url"`
}

// EngineConfig holds settings for the task execution engine.
type EngineConfig struct {
	QueueSize          int           `mapstructure:"queue_size"`
	WorkerConcurrency  int           `mapstructure:"worker_concurrency"`
	DefaultTaskTimeout time.Duration `mapstructure:"default_task_timeout"`
}

// BrowserConfig holds settings for the headless browser.
type BrowserConfig struct {
	Headless        bool           `mapstructure:"headless"`
	IgnoreTLSErrors bool           `mapstructure:"ignore_tls_errors"`
	Args            []string       `mapstructure:"args"`
	Viewport        map[string]int `mapstructure:"viewport"`
	Humanoid        humanoid.Config `mapstructure:"humanoid"`
}

// NetworkConfig holds settings for HTTP requests.
type NetworkConfig struct {
	Timeout time.Duration `mapstructure:"timeout"`
	Headers map[string]string `mapstructure:"headers"`
}

// ScannersConfig holds settings for all analysis modules.
type ScannersConfig struct {
	Passive PassiveScannersConfig `mapstructure:"passive"`
	Static  StaticScannersConfig  `mapstructure:"static"`
	Active  ActiveScannersConfig  `mapstructure:"active"`
}

// PassiveScannersConfig holds settings for passive analysis.
type PassiveScannersConfig struct {
	Headers HeadersConfig `mapstructure:"headers"`
}
type HeadersConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// StaticScannersConfig holds settings for static analysis.
type StaticScannersConfig struct {
	JWT JWTConfig `mapstructure:"jwt"`
}
type JWTConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	KnownSecrets      []string `mapstructure:"known_secrets"`
	BruteForceEnabled bool     `mapstructure:"brute_force_enabled"`
	DictionaryFile    string   `mapstructure:"dictionary_file"`
}

// ActiveScannersConfig holds settings for active analysis.
type ActiveScannersConfig struct {
	Taint          TaintConfig          `mapstructure:"taint"`
	ProtoPollution ProtoPollutionConfig `mapstructure:"protopollution"`
	TimeSlip       TimeSlipConfig       `mapstructure:"timeslip"`
	Auth           AuthConfig           `mapstructure:"auth"`
}

type TaintConfig struct {
	Enabled     bool `mapstructure:"enabled"`
	Depth       int  `mapstructure:"depth"`
	Concurrency int  `mapstructure:"concurrency"`
}

type ProtoPollutionConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type TimeSlipConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	RequestCount   int  `mapstructure:"request_count"`
	MaxConcurrency int  `mapstructure:"max_concurrency"`
	ThresholdMs    int  `mapstructure:"threshold_ms"`
}

type AuthConfig struct {
	ATO  ATOConfig  `mapstructure:"ato"`
	IDOR IDORConfig `mapstructure:"idor"`
}

type ATOConfig struct {
	Enabled                bool     `mapstructure:"enabled"`
	UsernameFields         []string `mapstructure:"username_fields"`
	PasswordFields         []string `mapstructure:"password_fields"`
	UsernameWordlist       string   `mapstructure:"username_wordlist"`
	PasswordSprayWordlist  string   `mapstructure:"password_spray_wordlist"`
	SuccessRegex           string   `mapstructure:"success_regex"`
	FailureRegex           string   `mapstructure:"failure_regex"`
	LockoutRegex           string   `mapstructure:"lockout_regex"`
	DelayBetweenAttemptsMs int      `mapstructure:"delay_between_attempts_ms"`
}

type IDORConfig struct {
	Enabled        bool                `mapstructure:"enabled"`
	IgnoreList     []string            `mapstructure:"ignore_list"`
	TestStrategies map[string][]string `mapstructure:"test_strategies"`
}

// ScanConfig holds settings specific to a scan execution (populated by CLI flags).
type ScanConfig struct {
	Targets     []string
	Output      string
	Format      string
	Concurrency int
	Depth       int
	Scope       string
}

// AgentConfig holds settings for the autonomous agent.
type AgentConfig struct {
	Enabled bool             `mapstructure:"enabled"`
	LLM     LLMRouterConfig `mapstructure:"llm"`
}

// LLMProvider defines the supported LLM providers.
type LLMProvider string

const (
	ProviderGemini    LLMProvider = "gemini"
	ProviderOpenAI    LLMProvider = "openai"
	ProviderAnthropic LLMProvider = "anthropic"
	// ProviderOllama is for connecting to a local, self-hosted LLM instance.
	ProviderOllama LLMProvider = "ollama"
)

// LLMRouterConfig holds the configuration for the multi-model LLM setup.
type LLMRouterConfig struct {
	DefaultFastModel     string                    `mapstructure:"default_fast_model"`
	DefaultPowerfulModel string                    `mapstructure:"default_powerful_model"`
	Models               map[string]LLMModelConfig `mapstructure:"models"`
}

// LLMModelConfig holds settings for a single Language Model configuration.
type LLMModelConfig struct {
	Provider      LLMProvider       `mapstructure:"provider"`
	Model         string            `mapstructure:"model"`
	APIKey        string            `mapstructure:"api_key"`
	Endpoint      string            `mapstructure:"endpoint"` // Optional endpoint override
	APITimeout    time.Duration     `mapstructure:"api_timeout"`
	Temperature   float32           `mapstructure:"temperature"`
	TopP          float32           `mapstructure:"top_p"`
	TopK          int               `mapstructure:"top_k"`
	MaxTokens     int               `mapstructure:"max_tokens"`
	SafetyFilters map[string]string `mapstructure:"safety_filters"`
}

// Load initializes the configuration singleton from Viper.
func Load(v *viper.Viper) error {
	var loadErr error
	once.Do(func() {
		var cfg Config
		if err := v.Unmarshal(&cfg); err != nil {
			loadErr = fmt.Errorf("error unmarshaling config: %w", err)
			return
		}
		instance = &cfg
	})
	return loadErr
}

// Get returns the loaded configuration instance.
func Get() *Config {
	if instance == nil {
		panic("Configuration not initialized. Call config.Load() in the root command.")
	}
	return instance
}

