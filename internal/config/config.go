// File: internal/config/config.go
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Interface defines the contract for accessing application configuration.
// This allows for dependency injection and mocking in tests.
type Interface interface {
	Logger() LoggerConfig
	Database() DatabaseConfig
	Engine() EngineConfig
	Browser() BrowserConfig
	Network() NetworkConfig
	IAST() IASTConfig
	Scanners() ScannersConfig
	JWT() JWTConfig // Specific getter for JWT config
	Agent() AgentConfig
	Discovery() DiscoveryConfig
	Autofix() AutofixConfig
	Scan() ScanConfig
	SetScanConfig(sc ScanConfig)

	// Discovery Setters
	SetDiscoveryMaxDepth(int)
	SetDiscoveryIncludeSubdomains(bool)

	// Engine Setters
	SetEngineWorkerConcurrency(int)

	// Browser Setters
	SetBrowserHeadless(bool)
	SetBrowserDisableCache(bool)
	SetBrowserIgnoreTLSErrors(bool)
	SetBrowserDebug(bool)

	// Humanoid Setters
	SetBrowserHumanoidEnabled(bool)
	SetBrowserHumanoidClickHoldMinMs(ms int)
	SetBrowserHumanoidClickHoldMaxMs(ms int)
	SetBrowserHumanoidKeyHoldMu(ms float64)

	// Network Setters
	SetNetworkCaptureResponseBodies(bool)
	SetNetworkNavigationTimeout(d time.Duration)
	SetNetworkPostLoadWait(d time.Duration)
	SetNetworkIgnoreTLSErrors(bool)

	// IAST Setters
	SetIASTEnabled(bool)

	// JWT Setters
	SetJWTEnabled(bool)
	SetJWTBruteForceEnabled(bool)

	// ATO Setter
	SetATOConfig(atoCfg ATOConfig)
}

// Config holds the entire application configuration, minus any module-specific configs.
// It uses private fields to enforce access through the Interface's getter methods.
type Config struct {
	logger    LoggerConfig    `mapstructure:"logger" yaml:"logger"`
	database  DatabaseConfig  `mapstructure:"database" yaml:"database"`
	engine    EngineConfig    `mapstructure:"engine" yaml:"engine"`
	browser   BrowserConfig   `mapstructure:"browser" yaml:"browser"`
	network   NetworkConfig   `mapstructure:"network" yaml:"network"`
	iast      IASTConfig      `mapstructure:"iast" yaml:"iast"`
	scanners  ScannersConfig  `mapstructure:"scanners" yaml:"scanners"`
	agent     AgentConfig     `mapstructure:"agent" yaml:"agent"`
	discovery DiscoveryConfig `mapstructure:"discovery" yaml:"discovery"`
	autofix   AutofixConfig   `mapstructure:"autofix" yaml:"autofix"`
	// scanConfig gets its marching orders from CLI flags, not the config file.
	scan ScanConfig `mapstructure:"-" yaml:"-"`
}

func (c *Config) SetBrowserHumanoidKeyHoldMeanMs(f float64) {
	panic("unimplemented")
}

// --- Interface Method Implementations (Getters) ---

func (c *Config) Logger() LoggerConfig       { return c.logger }
func (c *Config) Database() DatabaseConfig   { return c.database }
func (c *Config) Engine() EngineConfig       { return c.engine }
func (c *Config) Browser() BrowserConfig     { return c.browser }
func (c *Config) Network() NetworkConfig     { return c.network }
func (c *Config) IAST() IASTConfig           { return c.iast }
func (c *Config) Scanners() ScannersConfig   { return c.scanners }
func (c *Config) JWT() JWTConfig             { return c.scanners.Static.JWT }
func (c *Config) Agent() AgentConfig         { return c.agent }
func (c *Config) Discovery() DiscoveryConfig { return c.discovery }
func (c *Config) Autofix() AutofixConfig     { return c.autofix }
func (c *Config) Scan() ScanConfig           { return c.scan }

// --- Interface Method Implementations (Setters) ---

func (c *Config) SetScanConfig(sc ScanConfig) { c.scan = sc }

// Discovery Setters
func (c *Config) SetDiscoveryMaxDepth(d int) { c.discovery.MaxDepth = d }
func (c *Config) SetDiscoveryIncludeSubdomains(b bool) {
	c.discovery.IncludeSubdomains = b
}

// Engine Setters
func (c *Config) SetEngineWorkerConcurrency(w int) { c.engine.WorkerConcurrency = w }

// Browser Setters
func (c *Config) SetBrowserHeadless(b bool)        { c.browser.Headless = b }
func (c *Config) SetBrowserDisableCache(b bool)    { c.browser.DisableCache = b }
func (c *Config) SetBrowserIgnoreTLSErrors(b bool) { c.browser.IgnoreTLSErrors = b }
func (c *Config) SetBrowserDebug(b bool)           { c.browser.Debug = b }

// Humanoid Setters
func (c *Config) SetBrowserHumanoidEnabled(b bool) { c.browser.Humanoid.Enabled = b }
func (c *Config) SetBrowserHumanoidClickHoldMinMs(ms int) {
	c.browser.Humanoid.ClickHoldMinMs = ms
}
func (c *Config) SetBrowserHumanoidClickHoldMaxMs(ms int) {
	c.browser.Humanoid.ClickHoldMaxMs = ms
}
func (c *Config) SetBrowserHumanoidKeyHoldMu(ms float64) {
	c.browser.Humanoid.KeyHoldMu = ms
}

// Network Setters
func (c *Config) SetNetworkCaptureResponseBodies(b bool) {
	c.network.CaptureResponseBodies = b
}
func (c *Config) SetNetworkNavigationTimeout(d time.Duration) {
	c.network.NavigationTimeout = d
}
func (c *Config) SetNetworkPostLoadWait(d time.Duration) { c.network.PostLoadWait = d }
func (c *Config) SetNetworkIgnoreTLSErrors(b bool)       { c.network.IgnoreTLSErrors = b }

// IAST Setters
func (c *Config) SetIASTEnabled(b bool) { c.iast.Enabled = b }

// JWT Setters
func (c *Config) SetJWTEnabled(b bool) { c.scanners.Static.JWT.Enabled = b }
func (c *Config) SetJWTBruteForceEnabled(b bool) {
	c.scanners.Static.JWT.BruteForceEnabled = b
}

// ATO Setter
func (c *Config) SetATOConfig(atoCfg ATOConfig) {
	c.scanners.Active.Auth.ATO = atoCfg
}

// AutofixConfig holds settings for the self-healing (autofix) subsystem.
type AutofixConfig struct {
	Enabled                bool         `mapstructure:"enabled" yaml:"enabled"`
	ProjectRoot            string       `mapstructure:"project_root" yaml:"project_root"`
	DASTLogPath            string       `mapstructure:"dast_log_path" yaml:"dast_log_path"`
	MinConfidenceThreshold float64      `mapstructure:"min_confidence_threshold" yaml:"min_confidence_threshold"`
	CooldownSeconds        int          `mapstructure:"cooldown_seconds" yaml:"cooldown_seconds"`
	KeepWorkspaceOnFailure bool         `mapstructure:"keep_workspace_on_failure" yaml:"keep_workspace_on_failure"`
	Git                    GitConfig    `mapstructure:"git" yaml:"git"`
	GitHub                 GitHubConfig `mapstructure:"github" yaml:"github"`
}

// Agent implements Interface.
func (a AutofixConfig) Agent() AgentConfig {
	panic("unimplemented")
}

// Autofix implements Interface.
func (a AutofixConfig) Autofix() AutofixConfig {
	panic("unimplemented")
}

// Browser implements Interface.
func (a AutofixConfig) Browser() BrowserConfig {
	panic("unimplemented")
}

// Database implements Interface.
func (a AutofixConfig) Database() DatabaseConfig {
	panic("unimplemented")
}

// Discovery implements Interface.
func (a AutofixConfig) Discovery() DiscoveryConfig {
	panic("unimplemented")
}

// Engine implements Interface.
func (a AutofixConfig) Engine() EngineConfig {
	panic("unimplemented")
}

// IAST implements Interface.
func (a AutofixConfig) IAST() IASTConfig {
	panic("unimplemented")
}

// JWT implements Interface.
func (a AutofixConfig) JWT() JWTConfig {
	panic("unimplemented")
}

// Logger implements Interface.
func (a AutofixConfig) Logger() LoggerConfig {
	panic("unimplemented")
}

// Network implements Interface.
func (a AutofixConfig) Network() NetworkConfig {
	panic("unimplemented")
}

// Scan implements Interface.
func (a AutofixConfig) Scan() ScanConfig {
	panic("unimplemented")
}

// Scanners implements Interface.
func (a AutofixConfig) Scanners() ScannersConfig {
	panic("unimplemented")
}

// SetATOConfig implements Interface.
func (a AutofixConfig) SetATOConfig(atoCfg ATOConfig) {
	panic("unimplemented")
}

// SetBrowserDebug implements Interface.
func (a AutofixConfig) SetBrowserDebug(bool) {
	panic("unimplemented")
}

// SetBrowserDisableCache implements Interface.
func (a AutofixConfig) SetBrowserDisableCache(bool) {
	panic("unimplemented")
}

// SetBrowserHeadless implements Interface.
func (a AutofixConfig) SetBrowserHeadless(bool) {
	panic("unimplemented")
}

// SetBrowserHumanoidClickHoldMaxMs implements Interface.
func (a AutofixConfig) SetBrowserHumanoidClickHoldMaxMs(ms int) {
	panic("unimplemented")
}

// SetBrowserHumanoidClickHoldMinMs implements Interface.
func (a AutofixConfig) SetBrowserHumanoidClickHoldMinMs(ms int) {
	panic("unimplemented")
}

// SetBrowserHumanoidEnabled implements Interface.
func (a AutofixConfig) SetBrowserHumanoidEnabled(bool) {
	panic("unimplemented")
}

// SetBrowserHumanoidKeyHoldMu implements Interface.
func (a AutofixConfig) SetBrowserHumanoidKeyHoldMu(ms float64) {
	panic("unimplemented")
}

// SetBrowserIgnoreTLSErrors implements Interface.
func (a AutofixConfig) SetBrowserIgnoreTLSErrors(bool) {
	panic("unimplemented")
}

// SetDiscoveryIncludeSubdomains implements Interface.
func (a AutofixConfig) SetDiscoveryIncludeSubdomains(bool) {
	panic("unimplemented")
}

// SetDiscoveryMaxDepth implements Interface.
func (a AutofixConfig) SetDiscoveryMaxDepth(int) {
	panic("unimplemented")
}

// SetEngineWorkerConcurrency implements Interface.
func (a AutofixConfig) SetEngineWorkerConcurrency(int) {
	panic("unimplemented")
}

// SetIASTEnabled implements Interface.
func (a AutofixConfig) SetIASTEnabled(bool) {
	panic("unimplemented")
}

// SetJWTBruteForceEnabled implements Interface.
func (a AutofixConfig) SetJWTBruteForceEnabled(bool) {
	panic("unimplemented")
}

// SetJWTEnabled implements Interface.
func (a AutofixConfig) SetJWTEnabled(bool) {
	panic("unimplemented")
}

// SetNetworkCaptureResponseBodies implements Interface.
func (a AutofixConfig) SetNetworkCaptureResponseBodies(bool) {
	panic("unimplemented")
}

// SetNetworkIgnoreTLSErrors implements Interface.
func (a AutofixConfig) SetNetworkIgnoreTLSErrors(bool) {
	panic("unimplemented")
}

// SetNetworkNavigationTimeout implements Interface.
func (a AutofixConfig) SetNetworkNavigationTimeout(d time.Duration) {
	panic("unimplemented")
}

// SetNetworkPostLoadWait implements Interface.
func (a AutofixConfig) SetNetworkPostLoadWait(d time.Duration) {
	panic("unimplemented")
}

// SetScanConfig implements Interface.
func (a AutofixConfig) SetScanConfig(sc ScanConfig) {
	panic("unimplemented")
}

// GitConfig defines the committer identity.
type GitConfig struct {
	AuthorName  string `mapstructure:"author_name" yaml:"author_name"`
	AuthorEmail string `mapstructure:"author_email" yaml:"author_email"`
}

// GitHubConfig defines the configuration for GitHub integration.
type GitHubConfig struct {
	Token      string `mapstructure:"token" yaml:"-"`
	RepoOwner  string `mapstructure:"repo_owner" yaml:"repo_owner"`
	RepoName   string `mapstructure:"repo_name" yaml:"repo_name"`
	BaseBranch string `mapstructure:"base_branch" yaml:"base_branch"`
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

// ColorConfig defines the color codes for different log levels.
type ColorConfig struct {
	Debug  string `mapstructure:"debug" yaml:"debug"`
	Info   string `mapstructure:"info" yaml:"info"`
	Warn   string `mapstructure:"warn" yaml:"warn"`
	Error  string `mapstructure:"error" yaml:"error"`
	DPanic string `mapstructure:"dpanic" yaml:"dpanic"`
	Panic  string `mapstructure:"panic" yaml:"panic"`
	Fatal  string `mapstructure:"fatal" yaml:"fatal"`
}

// DatabaseConfig holds the database connection details.
type DatabaseConfig struct {
	URL string `mapstructure:"url" yaml:"url"`
}

// EngineConfig configures the core task processing engine.
type EngineConfig struct {
	QueueSize          int           `mapstructure:"queue_size" yaml:"queue_size"`
	WorkerConcurrency  int           `mapstructure:"worker_concurrency" yaml:"worker_concurrency"`
	DefaultTaskTimeout time.Duration `mapstructure:"default_task_timeout" yaml:"default_task_timeout"`
}

// NOTE: HumanoidConfig is now defined in internal/config/humanoid_config.go

// BrowserConfig holds settings for the headless browser instances.
type BrowserConfig struct {
	Headless        bool           `mapstructure:"headless" yaml:"headless"`
	DisableCache    bool           `mapstructure:"disable_cache" yaml:"disable_cache"`
	IgnoreTLSErrors bool           `mapstructure:"ignore_tls_errors" yaml:"ignore_tls_errors"`
	Concurrency     int            `mapstructure:"concurrency" yaml:"concurrency"`
	Debug           bool           `mapstructure:"debug" yaml:"debug"`
	Args            []string       `mapstructure:"args" yaml:"args"`
	Viewport        map[string]int `mapstructure:"viewport" yaml:"viewport"`
	Humanoid        HumanoidConfig `mapstructure:"humanoid" yaml:"humanoid"`
}

// ProxyConfig defines the configuration for an outbound proxy.
type ProxyConfig struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled"`
	Address string `mapstructure:"address" yaml:"address"`
	CACert  string `mapstructure:"ca_cert" yaml:"ca_cert"`
	CAKey   string `mapstructure:"ca_key" yaml:"ca_key"`
}

// NetworkConfig tunes the network behavior of the application.
type NetworkConfig struct {
	Timeout               time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	NavigationTimeout     time.Duration     `mapstructure:"navigation_timeout" yaml:"navigation_timeout"`
	CaptureResponseBodies bool              `mapstructure:"capture_response_bodies" yaml:"capture_response_bodies"`
	Headers               map[string]string `mapstructure:"headers" yaml:"headers"`
	PostLoadWait          time.Duration     `mapstructure:"post_load_wait" yaml:"post_load_wait"`
	Proxy                 ProxyConfig       `mapstructure:"proxy" yaml:"proxy"`
	IgnoreTLSErrors       bool              `mapstructure:"ignore_tls_errors" yaml:"ignore_tls_errors"`
}

// IASTConfig holds configuration for the Interactive Application Security Testing module.
type IASTConfig struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled"`
	ShimPath   string `mapstructure:"shim_path" yaml:"shim_path"`
	ConfigPath string `mapstructure:"config_path" yaml:"config_path"`
}

// ScannersConfig is a container for all scanner related configurations.
type ScannersConfig struct {
	Passive PassiveScannersConfig `mapstructure:"passive" yaml:"passive"`
	Static  StaticScannersConfig  `mapstructure:"static" yaml:"static"`
	Active  ActiveScannersConfig  `mapstructure:"active" yaml:"active"`
}

// PassiveScannersConfig holds settings for passive scanners.
type PassiveScannersConfig struct {
	Headers HeadersConfig `mapstructure:"headers" yaml:"headers"`
}
type HeadersConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

// StaticScannersConfig holds settings for static analysis scanners.
type StaticScannersConfig struct {
	JWT JWTConfig `mapstructure:"jwt" yaml:"jwt"`
}

// JWTConfig defines settings for the JSON Web Token scanner.
type JWTConfig struct {
	Enabled           bool     `mapstructure:"enabled" yaml:"enabled"`
	KnownSecrets      []string `mapstructure:"known_secrets" yaml:"known_secrets"`
	BruteForceEnabled bool     `mapstructure:"brute_force_enabled" yaml:"brute_force_enabled"`
	DictionaryFile    string   `mapstructure:"dictionary_file" yaml:"dictionary_file"`
}

// ActiveScannersConfig holds settings for active scanners that send payloads.
type ActiveScannersConfig struct {
	Taint          TaintConfig          `mapstructure:"taint" yaml:"taint"`
	ProtoPollution ProtoPollutionConfig `mapstructure:"protopollution" yaml:"protopollution"`
	TimeSlip       TimeSlipConfig       `mapstructure:"timeslip" yaml:"timeslip"`
	Auth           AuthConfig           `mapstructure:"auth" yaml:"auth"`
}

// TaintConfig configures the taint analysis scanner.
type TaintConfig struct {
	Enabled     bool `mapstructure:"enabled" yaml:"enabled"`
	Depth       int  `mapstructure:"depth" yaml:"depth"`
	Concurrency int  `mapstructure:"concurrency" yaml:"concurrency"`
}

// ProtoPollutionConfig defines the configuration for the Prototype Pollution analyzer.
type ProtoPollutionConfig struct {
	Enabled      bool          `mapstructure:"enabled" yaml:"enabled"`
	WaitDuration time.Duration `mapstructure:"wait_duration" yaml:"wait_duration"`
}

// TimeSlipConfig configures the time based vulnerability scanner.
type TimeSlipConfig struct {
	Enabled        bool `mapstructure:"enabled" yaml:"enabled"`
	RequestCount   int  `mapstructure:"request_count" yaml:"request_count"`
	MaxConcurrency int  `mapstructure:"max_concurrency" yaml:"max_concurrency"`
	ThresholdMs    int  `mapstructure:"threshold_ms" yaml:"threshold_ms"`
}

// AuthConfig holds configurations for authentication related scanners.
type AuthConfig struct {
	ATO  ATOConfig  `mapstructure:"ato" yaml:"ato"`
	IDOR IDORConfig `mapstructure:"idor" yaml:"idor"`
}

// ATOConfig configures the Account Takeover scanner.
type ATOConfig struct {
	Enabled                bool     `mapstructure:"enabled" yaml:"enabled"`
	CredentialFile         string   `mapstructure:"credential_file" yaml:"credential_file"`
	Concurrency            int      `mapstructure:"concurrency" yaml:"concurrency"`
	MinRequestDelayMs      int      `mapstructure:"min_request_delay_ms" yaml:"min_request_delay_ms"`
	RequestDelayJitterMs   int      `mapstructure:"request_delay_jitter_ms" yaml:"request_delay_jitter_ms"`
	SuccessKeywords        []string `mapstructure:"success_keywords" yaml:"success_keywords"`
	UserFailureKeywords    []string `mapstructure:"user_failure_keywords" yaml:"user_failure_keywords"`
	PassFailureKeywords    []string `mapstructure:"pass_failure_keywords" yaml:"pass_failure_keywords"`
	GenericFailureKeywords []string `mapstructure:"generic_failure_keywords" yaml:"generic_failure_keywords"`
	LockoutKeywords        []string `mapstructure:"lockout_keywords" yaml:"lockout_keywords"`
}

// IDORConfig defines the settings for the Insecure Direct Object Reference scanner.
type IDORConfig struct {
	Enabled        bool                `mapstructure:"enabled" yaml:"enabled"`
	IgnoreList     []string            `mapstructure:"ignore_list" yaml:"ignore_list"`
	TestStrategies map[string][]string `mapstructure:"test_strategies" yaml:"test_strategies"`
}

// ScanConfig holds settings populated from CLI flags for a specific scan job.
type ScanConfig struct {
	Targets     []string
	Output      string
	Format      string
	Concurrency int
	Depth       int
	Scope       string
}

// DiscoveryConfig configures the asset discovery process.
type DiscoveryConfig struct {
	MaxDepth           int           `mapstructure:"max_depth" yaml:"max_depth"`
	Concurrency        int           `mapstructure:"concurrency" yaml:"concurrency"`
	Timeout            time.Duration `mapstructure:"timeout" yaml:"timeout"`
	PassiveEnabled     *bool         `mapstructure:"passive_enabled" yaml:"passive_enabled"`
	IncludeSubdomains  bool          `mapstructure:"include_subdomains" yaml:"include_subdomains"`
	CrtShRateLimit     float64       `mapstructure:"crtsh_rate_limit" yaml:"crtsh_rate_limit"`
	CacheDir           string        `mapstructure:"cache_dir" yaml:"cache_dir"`
	PassiveConcurrency int           `mapstructure:"passive_concurrency" yaml:"passive_concurrency"`
}

// PostgresConfig holds the connection details for a PostgreSQL database.
type PostgresConfig struct {
	Host     string `mapstructure:"host" yaml:"host"`
	Port     int    `mapstructure:"port" yaml:"port"`
	User     string `mapstructure:"user" yaml:"user"`
	Password string `mapstructure:"password" yaml:"password"`
	DBName   string `mapstructure:"dbname" yaml:"dbname"`
	SSLMode  string `mapstructure:"sslmode" yaml:"sslmode"`
}

// KnowledgeGraphConfig specifies the backend for the knowledge graph.
type KnowledgeGraphConfig struct {
	Type     string         `mapstructure:"type" yaml:"type"`
	Postgres PostgresConfig `mapstructure:"postgres" yaml:"postgres"`
}

// AgentConfig holds settings related to the AI agent and its components.
type AgentConfig struct {
	LLM            LLMRouterConfig      `mapstructure:"llm" yaml:"llm"`
	Evolution      EvolutionConfig      `mapstructure:"evolution" yaml:"evolution"`
	KnowledgeGraph KnowledgeGraphConfig `mapstructure:"knowledge_graph" yaml:"knowledge_graph"`
}

// EvolutionConfig holds settings for the proactive self-improvement (evolution) subsystem.
type EvolutionConfig struct {
	Enabled    bool          `mapstructure:"enabled" yaml:"enabled"`
	MaxCycles  int           `mapstructure:"max_cycles" yaml:"max_cycles"`
	SettleTime time.Duration `mapstructure:"settle_time" yaml:"settle_time"`
}

// LLMProvider defines the supported LLM providers.
type LLMProvider string

const (
	ProviderGemini    LLMProvider = "gemini"
	ProviderOpenAI    LLMProvider = "openai"
	ProviderAnthropic LLMProvider = "anthropic"
	ProviderOllama    LLMProvider = "ollama"
)

// LLMRouterConfig configures the model routing logic.
type LLMRouterConfig struct {
	DefaultFastModel     string                    `mapstructure:"default_fast_model" yaml:"default_fast_model"`
	DefaultPowerfulModel string                    `mapstructure:"default_powerful_model" yaml:"default_powerful_model"`
	Models               map[string]LLMModelConfig `mapstructure:"models" yaml:"models"`
}

// LLMModelConfig defines the configuration for a single LLM.
type LLMModelConfig struct {
	Provider      LLMProvider       `mapstructure:"provider" yaml:"provider"`
	Model         string            `mapstructure:"model" yaml:"model"`
	APIKey        string            `mapstructure:"api_key" yaml:"api_key"`
	Endpoint      string            `mapstructure:"endpoint" yaml:"endpoint"`
	APITimeout    time.Duration     `mapstructure:"api_timeout" yaml:"api_timeout"`
	Temperature   float32           `mapstructure:"temperature" yaml:"temperature"`
	TopP          float32           `mapstructure:"top_p" yaml:"top_p"`
	TopK          int               `mapstructure:"top_k" yaml:"top_k"`
	MaxTokens     int               `mapstructure:"max_tokens" yaml:"max_tokens"`
	SafetyFilters map[string]string `mapstructure:"safety_filters" yaml:"safety_filters"`
}

// NewDefaultConfig creates a new configuration struct populated with default values.
func NewDefaultConfig() *Config {
	v := viper.New()
	SetDefaults(v)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		// This should not happen with defaults, but good to be safe.
		panic(fmt.Sprintf("failed to unmarshal default config: %v", err))
	}
	return &cfg
}

// SetDefaults initializes default values for various configuration parameters.
func SetDefaults(v *viper.Viper) {
	// -- Logger --
	v.SetDefault("logger.level", "info")
	v.SetDefault("logger.format", "console")
	v.SetDefault("logger.add_source", false)
	v.SetDefault("logger.service_name", "scalpel-cli")
	v.SetDefault("logger.log_file", "scalpel.log")
	v.SetDefault("logger.max_size", 100)
	v.SetDefault("logger.max_backups", 5)
	v.SetDefault("logger.max_age", 30)
	v.SetDefault("logger.compress", true)

	// -- Engine --
	v.SetDefault("engine.queue_size", 1000)
	v.SetDefault("engine.worker_concurrency", 10)
	v.SetDefault("engine.default_task_timeout", "5m")

	// -- Browser --
	v.SetDefault("browser.headless", true)
	v.SetDefault("browser.disable_cache", true)
	v.SetDefault("browser.ignore_tls_errors", false)
	v.SetDefault("browser.concurrency", 4)
	v.SetDefault("browser.debug", true)
	// Initialize all Humanoid defaults using the centralized function in humanoid_config.go.
	setHumanoidDefaults(v)

	// -- Network --
	v.SetDefault("network.timeout", "30s")
	v.SetDefault("network.navigation_timeout", "90s")
	v.SetDefault("network.capture_response_bodies", true)
	v.SetDefault("network.post_load_wait", "2s")
	v.SetDefault("network.proxy.enabled", false)

	// -- IAST --
	v.SetDefault("iast.enabled", false)

	// -- Scanners --
	v.SetDefault("scanners.passive.headers.enabled", true)
	v.SetDefault("scanners.static.jwt.enabled", true)
	v.SetDefault("scanners.active.taint.enabled", true)
	v.SetDefault("scanners.active.taint.depth", 5)
	v.SetDefault("scanners.active.taint.concurrency", 10)
	v.SetDefault("scanners.active.protopollution.enabled", true)
	v.SetDefault("scanners.active.protopollution.wait_duration", 8*time.Second)
	v.SetDefault("scanners.active.timeslip.enabled", false)
	v.SetDefault("scanners.active.auth.ato.enabled", false)
	v.SetDefault("scanners.active.auth.idor.enabled", false)

	// -- Discovery --
	v.SetDefault("discovery.max_depth", 5)
	v.SetDefault("discovery.concurrency", 20)
	v.SetDefault("discovery.timeout", "15m")
	v.SetDefault("discovery.passive_enabled", true)
	v.SetDefault("discovery.include_subdomains", true)
	v.SetDefault("discovery.crtsh_rate_limit", 2.0)
	v.SetDefault("discovery.passive_concurrency", 10)

	// -- Agent --
	v.SetDefault("agent.llm.default_fast_model", "gemini-2.5-flash")
	v.SetDefault("agent.llm.default_powerful_model", "gemini-2.5-pro")
	v.SetDefault("agent.knowledge_graph.type", "postgres")
	v.SetDefault("agent.knowledge_graph.postgres.host", "localhost")
	v.SetDefault("agent.knowledge_graph.postgres.port", 5432)
	v.SetDefault("agent.knowledge_graph.postgres.user", "postgres")
	v.SetDefault("agent.knowledge_graph.postgres.password", "") // Should be set via env var
	v.SetDefault("agent.knowledge_graph.postgres.dbname", "scalpel_kg")
	v.SetDefault("agent.knowledge_graph.postgres.sslmode", "disable")

	// -- Agent Evolution --
	v.SetDefault("agent.evolution.enabled", false)
	v.SetDefault("agent.evolution.max_cycles", 15)
	v.SetDefault("agent.evolution.settle_time", "500ms")

	// -- Autofix --
	v.SetDefault("autofix.enabled", false)
	v.SetDefault("autofix.min_confidence_threshold", 0.75)
	v.SetDefault("autofix.cooldown_seconds", 300)
	v.SetDefault("autofix.keep_workspace_on_failure", false)
	v.SetDefault("autofix.git.author_name", "scalpel-autofix-bot")
	v.SetDefault("autofix.git.author_email", "autofix@scalpel.security")
	v.SetDefault("autofix.github.base_branch", "main")
}

// NewConfigFromViper creates a new configuration instance from a viper object.
func NewConfigFromViper(v *viper.Viper) (*Config, error) {
	var cfg Config

	// Bind environment variables for sensitive data
	v.BindEnv("autofix.github.token", "SCALPEL_AUTOFIX_GH_TOKEN")
	v.BindEnv("agent.knowledge_graph.postgres.password", "SCALPEL_KG_PASSWORD")

	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Manually load the token if Unmarshal didn't pick it up
	if cfg.autofix.Enabled && cfg.autofix.GitHub.Token == "" {
		cfg.autofix.GitHub.Token = os.Getenv("SCALPEL_AUTOFIX_GH_TOKEN")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return &cfg, nil
}

// Validate checks the configuration for required fields and sane values.
func (c *Config) Validate() error {
	// Relaxing the requirement for database.url as it might not be needed in all contexts.
	/*
		if c.database.URL == "" {
			return fmt.Errorf("database.url is a required configuration field")
		}
	*/
	if c.engine.WorkerConcurrency <= 0 {
		return fmt.Errorf("engine.worker_concurrency must be a positive integer")
	}
	if c.browser.Concurrency <= 0 {
		return fmt.Errorf("browser.concurrency must be a positive integer")
	}
	if err := c.autofix.Validate(); err != nil {
		return fmt.Errorf("autofix configuration invalid: %w", err)
	}
	if err := c.agent.Evolution.Validate(); err != nil {
		return fmt.Errorf("agent.evolution configuration invalid: %w", err)
	}
	return nil
}

// Validate checks the Autofix configuration.
func (a *AutofixConfig) Validate() error {
	if !a.Enabled {
		return nil
	}
	if a.MinConfidenceThreshold < 0.0 || a.MinConfidenceThreshold > 1.0 {
		return fmt.Errorf("min_confidence_threshold must be between 0.0 and 1.0")
	}
	if a.GitHub.RepoOwner == "" || a.GitHub.RepoName == "" || a.GitHub.BaseBranch == "" {
		return fmt.Errorf("github.repo_owner, github.repo_name, and github.base_branch are required")
	}
	if a.GitHub.Token == "" {
		return fmt.Errorf("GitHub token is required but not found. Ensure SCALPEL_AUTOFIX_GH_TOKEN is set")
	}
	return nil
}

// Validate checks the EvolutionConfig settings.
func (e *EvolutionConfig) Validate() error {
	if !e.Enabled {
		return nil
	}
	if e.MaxCycles <= 0 {
		return fmt.Errorf("max_cycles must be greater than 0")
	}
	if e.SettleTime <= 0 {
		return fmt.Errorf("settle_time must be a positive duration")
	}
	return nil
}
