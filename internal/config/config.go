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
	once     sync.Once
)

// Config is the root configuration structure for the entire application.
type Config struct {
	Logger   LoggerConfig   `mapstructure:"logger"`
	Postgres PostgresConfig `mapstructure:"postgres"`
	Engine   EngineConfig   `mapstructure:"engine"`
	Browser  BrowserConfig  `mapstructure:"browser" yaml:"browser"`
	Network  NetworkConfig  `mapstructure:"network"`
	Scanners ScannersConfig `mapstructure:"scanners"`
	Scan     ScanConfig     `mapstructure:"scan"`
	Agent    AgentConfig    `mapstructure:"agent"`
	IAST     IASTConfig     `mapstructure:"iast" yaml:"iast"`
}

// ColorConfig defines the color settings for different log levels.
type ColorConfig struct {
	Debug  string `mapstructure:"debug" yaml:"debug"`
	Info   string `mapstructure:"info" yaml:"info"`
	Warn   string `mapstructure:"warn" yaml:"warn"`
	Error  string `mapstructure:"error" yaml:"error"`
	DPanic string `mapstructure:"dpanic" yaml:"dpanic"`
	Panic  string `mapstructure:"panic" yaml:"panic"`
	Fatal  string `mapstructure:"fatal" yaml:"fatal"`
}

// LoggerConfig holds all the configuration for the logger.
type LoggerConfig struct {
	Level       string      `mapstructure:"level" yaml:"level"`
	Format      string      `mapstructure:"format" yaml:"format"`
	AddSource   bool        `mapstructure:"add_source" yaml:"add_source"`
	ServiceName string      `mapstructure:"service_name" yaml:"service_name"`
	LogFile     string      `mapstructure:"log_file" yaml:"log_file"`
	MaxSize     int         `mapstructure:"max_size" yaml:"max_size"`
	MaxBackups  int         `mapstructure:"max_backups" yaml:"max_backups"`
	MaxAge      int         `mapstructure:"max_age" yaml:"max_age"`
	Compress    bool        `mapstructure:"compress" yaml:"compress"`
	Colors      ColorConfig `mapstructure:"colors" yaml:"colors"`
}

// PostgresConfig holds settings for the database connection.
type PostgresConfig struct {
	URL string `mapstructure:"url"`
}

// EngineConfig holds settings for the task execution engine.
type EngineConfig struct {
	QueueSize         int           `mapstructure:"queue_size"`
	WorkerConcurrency int           `mapstructure:"worker_concurrency"`
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
	Enabled              bool     `mapstructure:"enabled" yaml:"enabled"`
	CredentialFile       string   `mapstructure:"credentialFile" yaml:"credential_file"`
	Concurrency          int      `mapstructure:"concurrency" yaml:"concurrency"`
	MinRequestDelayMs    int      `mapstructure:"minRequestDelayMs" yaml:"min_request_delay_ms"`
	RequestDelayJitterMs int      `mapstructure:"requestDelayJitterMs" yaml:"request_delay_jitter_ms"`
	SuccessKeywords      []string `mapstructure:"successKeywords" yaml:"success_keywords"`
	UserFailureKeywords  []string `mapstructure:"userFailureKeywords" yaml:"user_failure_keywords"`
	PassFailureKeywords  []string `mapstructure:"passFailureKeywords" yaml:"pass_failure_keywords"`
	GenericFailureKeywords []string `mapstructure:"genericFailureKeywords" yaml:"generic_failure_keywords"`
	LockoutKeywords      []string `mapstructure:"lockoutKeywords" yaml:"lockout_keywords"`
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
	Enabled bool            `mapstructure:"enabled"`
	LLM     LLMRouterConfig `mapstructure:"llm"`
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

