// internal/config/config.go
package config

import (
	"fmt"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

var (
	instance *Config
	loadErr  error // Cache the loading error globally
	once     sync.Once
)
// Config holds the entire application configuration.
// This is the root configuration structure.
type Config struct {
	Logger    LoggerConfig    `mapstructure:"logger" yaml:"logger"`
	Database  PostgresConfig  `mapstructure:"database" yaml:"database"`
	Engine    EngineConfig    `mapstructure:"engine" yaml:"engine"`
	Browser   BrowserConfig   `mapstructure:"browser" yaml:"browser"`
	Network   NetworkConfig   `mapstructure:"network" yaml:"network"`
	IAST      IASTConfig      `mapstructure:"iast" yaml:"iast"`
	Scanners  ScannersConfig  `mapstructure:"scanners" yaml:"scanners"`
	Agent     AgentConfig     `mapstructure:"agent" yaml:"agent"`
	Discovery DiscoveryConfig `mapstructure:"discovery" yaml:"discovery"`
	// ScanConfig is populated dynamically from CLI flags, not from the config file.
	Scan ScanConfig `mapstructure:"-"`
}

// LoggerConfig holds all the configuration for the logger.
// This should be the single source of truth for this struct.
type LoggerConfig struct {
	Level       string      `mapstructure:"level" json:"level" yaml:"level"`
	Format      string      `mapstructure:"format" json:"format" yaml:"format"`
	AddSource   bool        `mapstructure:"add_source" json:"add_source" yaml:"add_source"`
	ServiceName string      `mapstructure:"service_name" json:"service_name" yaml:"service_name"`
	LogFile     string      `mapstructure:"log_file" json:"log_file" yaml:"log_file"`
	MaxSize     int         `mapstructure:"max_size" json:"max_size" yaml:"max_size"`
	MaxBackups  int         `mapstructure:"max_backups" json:"max_backups" yaml:"max_backups"`
	MaxAge      int         `mapstructure:"max_age" json:"max_age" yaml:"max_age"`
	Compress    bool        `mapstructure:"compress" json:"compress" yaml:"compress"`
	Colors      ColorConfig `mapstructure:"colors" json:"colors" yaml:"colors"`
}

// ColorConfig defines the color settings for different log levels.
// These are used for console output to make logs more readable.
type ColorConfig struct {
	Debug  string `mapstructure:"debug" json:"debug" yaml:"debug"`
	Info   string `mapstructure:"info" json:"info" yaml:"info"`
	Warn   string `mapstructure:"warn" json:"warn" yaml:"warn"`
	Error  string `mapstructure:"error" json:"error" yaml:"error"`
	DPanic string `mapstructure:"dpanic" json:"dpanic" yaml:"dpanic"`
	Panic  string `mapstructure:"panic" json:"panic" yaml:"panic"`
	Fatal  string `mapstructure:"fatal" json:"fatal" yaml:"fatal"`
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
	Headless        bool            `mapstructure:"headless" yaml:"headless"`
	DisableCache    bool            `mapstructure:"disableCache"`
	IgnoreTLSErrors bool            `mapstructure:"ignore_tls_errors"`
	Args            []string        `mapstructure:"args"`
	Viewport        map[string]int  `mapstructure:"viewport"`
	Humanoid        humanoid.Config `mapstructure:"humanoid"`
}

// NetworkConfig holds settings for HTTP requests.
type NetworkConfig struct {
	Timeout               time.Duration     `mapstructure:"timeout"`
	CaptureResponseBodies bool              `mapstructure:"captureResponseBodies"`
	Headers               map[string]string `mapstructure:"headers"`
	PostLoadWait          time.Duration     `mapstructure:"postLoadWait"`
}

// IASTConfig holds paths for the Interactive Application Security Testing scripts.
type IASTConfig struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled"`
	ShimPath   string `mapstructure:"shimPath" yaml:"shim_path"`
	ConfigPath string `mapstructure:"configPath" yaml:"config_path"`
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

// ATOConfig holds configuration specific to the Account Takeover analysis module.
type ATOConfig struct {
	Enabled                bool     `mapstructure:"enabled" yaml:"enabled"`
	CredentialFile         string   `mapstructure:"credentialFile" yaml:"credential_file"`
	Concurrency            int      `mapstructure:"concurrency" yaml:"concurrency"`
	MinRequestDelayMs      int      `mapstructure:"minRequestDelayMs" yaml:"min_request_delay_ms"`
	RequestDelayJitterMs   int      `mapstructure:"requestDelayJitterMs" yaml:"request_delay_jitter_ms"`
	SuccessKeywords        []string `mapstructure:"successKeywords" yaml:"success_keywords"`
	UserFailureKeywords    []string `mapstructure:"userFailureKeywords" yaml:"user_failure_keywords"`
	PassFailureKeywords    []string `mapstructure:"passFailureKeywords" yaml:"pass_failure_keywords"`
	GenericFailureKeywords []string `mapstructure:"genericFailureKeywords" yaml:"generic_failure_keywords"`
	LockoutKeywords        []string `mapstructure:"lockoutKeywords" yaml:"lockout_keywords"`
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

// DiscoveryConfig holds settings for the discovery engine.
type DiscoveryConfig struct {
	MaxDepth           int           `mapstructure:"maxDepth" yaml:"maxDepth"`
	Concurrency        int           `mapstructure:"concurrency" yaml:"concurrency"`
	Timeout            time.Duration `mapstructure:"timeout" yaml:"timeout"`
	PassiveEnabled     *bool         `mapstructure:"passiveEnabled" yaml:"passiveEnabled"`
	CrtShRateLimit     float64       `mapstructure:"crtShRateLimit" yaml:"crtShRateLimit"`
	CacheDir           string        `mapstructure:"cacheDir" yaml:"cacheDir"`
	PassiveConcurrency int           `mapstructure:"passiveConcurrency" yaml:"passiveConcurrency"`
}

// KnowledgeGraphConfig holds settings for the agent's knowledge graph.
type KnowledgeGraphConfig struct {
	Type string `yaml:"type"`
}
// AgentConfig holds all settings related to the autonomous agent.
type AgentConfig struct {
	LLM            LLMRouterConfig      `yaml:"llm"`
	KnowledgeGraph KnowledgeGraphConfig `yaml:"knowledge_graph"` // Add this field
}

type LLMProvider string

const (
	ProviderGemini    LLMProvider = "gemini"
	ProviderOpenAI    LLMProvider = "openai"
	ProviderAnthropic LLMProvider = "anthropic"
	ProviderOllama    LLMProvider = "ollama"
)

type LLMRouterConfig struct {
	DefaultFastModel     string                    `mapstructure:"default_fast_model"`
	DefaultPowerfulModel string                    `mapstructure:"default_powerful_model"`
	Models               map[string]LLMModelConfig `mapstructure:"models"`
}

type LLMModelConfig struct {
	Provider      LLMProvider       `mapstructure:"provider"`
	Model         string            `mapstructure:"model"`
	APIKey        string            `mapstructure:"api_key"`
	Endpoint      string            `mapstructure:"endpoint"`
	APITimeout    time.Duration     `mapstructure:"api_timeout"`
	Temperature   float32           `mapstructure:"temperature"`
	TopP          float32           `mapstructure:"top_p"`
	TopK          int               `mapstructure:"top_k"`
	MaxTokens     int               `mapstructure:"max_tokens"`
	SafetyFilters map[string]string `mapstructure:"safety_filters"`
}

// Load initializes the configuration singleton from Viper.
// Deprecated: Use Set() during initialization in the root command instead.
func Load(v *viper.Viper) error {
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
		// This panic is intentional to catch initialization errors early.
		panic("Configuration not initialized. Ensure initialization happens in the root command.")
	}
	return instance
}

// Set initializes the global configuration instance if not already set.
func Set(cfg *Config) {
	once.Do(func() {
		instance = cfg
	})
}