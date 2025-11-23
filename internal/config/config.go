// File: internal/config/config.go
// This file defines the core configuration structures for the application,
// using a combination of struct tags for file-based configuration loading (via Viper)
// and an interface-based approach for dependency injection and mocking.
//
// The `Config` struct aggregates all configuration sub-modules (e.g., Logger,
// Database, Browser), while the `Interface` defines a contract for accessing these
// configurations. This separation allows other parts of the application to depend
// on the `Interface` rather than the concrete `Config` struct, promoting loose
// coupling.
//
// The file also includes functions for setting default values (`SetDefaults`),
// creating a default configuration (`NewDefaultConfig`), loading from a Viper
// instance (`NewConfigFromViper`), and validating the loaded configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Interface defines a contract for accessing application configuration settings.
// It uses a getter/setter pattern to provide a stable, decoupled interface that
// hides the underlying implementation of the configuration struct. This allows
// different parts of the application to depend on this interface, making them
// easier to test and more resilient to changes in the configuration structure.
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
	SetBrowserDisableGPU(bool)
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

// Config is the top-level struct that aggregates all configuration modules for
// the application. It uses `mapstructure` tags to facilitate loading from
// configuration files (e.g., YAML, JSON) via the Viper library.
type Config struct {
	LoggerCfg    LoggerConfig    `mapstructure:"logger" yaml:"logger"`
	DatabaseCfg  DatabaseConfig  `mapstructure:"database" yaml:"database"`
	EngineCfg    EngineConfig    `mapstructure:"engine" yaml:"engine"`
	BrowserCfg   BrowserConfig   `mapstructure:"browser" yaml:"browser"`
	NetworkCfg   NetworkConfig   `mapstructure:"network" yaml:"network"`
	IASTCfg      IASTConfig      `mapstructure:"iast" yaml:"iast"`
	ScannersCfg  ScannersConfig  `mapstructure:"scanners" yaml:"scanners"`
	AgentCfg     AgentConfig     `mapstructure:"agent" yaml:"agent"`
	DiscoveryCfg DiscoveryConfig `mapstructure:"discovery" yaml:"discovery"`
	AutofixCfg   AutofixConfig   `mapstructure:"autofix" yaml:"autofix"`
	// ScanCfg holds settings for a specific scan job, typically populated from
	// CLI flags rather than a configuration file, hence the ignored tags.
	ScanCfg ScanConfig `mapstructure:"-" yaml:"-"`
}

// -- Interface Method Implementations (Getters) --

func (c *Config) Logger() LoggerConfig       { return c.LoggerCfg }
func (c *Config) Database() DatabaseConfig   { return c.DatabaseCfg }
func (c *Config) Engine() EngineConfig       { return c.EngineCfg }
func (c *Config) Browser() BrowserConfig     { return c.BrowserCfg }
func (c *Config) Network() NetworkConfig     { return c.NetworkCfg }
func (c *Config) IAST() IASTConfig           { return c.IASTCfg }
func (c *Config) Scanners() ScannersConfig   { return c.ScannersCfg }
func (c *Config) JWT() JWTConfig             { return c.ScannersCfg.Static.JWT }
func (c *Config) Agent() AgentConfig         { return c.AgentCfg }
func (c *Config) Discovery() DiscoveryConfig { return c.DiscoveryCfg }
func (c *Config) Autofix() AutofixConfig     { return c.AutofixCfg }
func (c *Config) Scan() ScanConfig           { return c.ScanCfg }

// -- Interface Method Implementations (Setters) --

func (c *Config) SetScanConfig(sc ScanConfig) { c.ScanCfg = sc }

// Discovery Setters
func (c *Config) SetDiscoveryMaxDepth(d int) { c.DiscoveryCfg.MaxDepth = d }
func (c *Config) SetDiscoveryIncludeSubdomains(b bool) {
	c.DiscoveryCfg.IncludeSubdomains = b
}

// Engine Setters
func (c *Config) SetEngineWorkerConcurrency(w int) { c.EngineCfg.WorkerConcurrency = w }

// Browser Setters
func (c *Config) SetBrowserHeadless(b bool)        { c.BrowserCfg.Headless = b }
func (c *Config) SetBrowserDisableCache(b bool)    { c.BrowserCfg.DisableCache = b }
func (c *Config) SetBrowserDisableGPU(b bool)      { c.BrowserCfg.DisableGPU = b }
func (c *Config) SetBrowserIgnoreTLSErrors(b bool) { c.BrowserCfg.IgnoreTLSErrors = b }
func (c *Config) SetBrowserDebug(b bool)           { c.BrowserCfg.Debug = b }

// Humanoid Setters
func (c *Config) SetBrowserHumanoidEnabled(b bool) { c.BrowserCfg.Humanoid.Enabled = b }
func (c *Config) SetBrowserHumanoidClickHoldMinMs(ms int) {
	c.BrowserCfg.Humanoid.ClickHoldMinMs = ms
}
func (c *Config) SetBrowserHumanoidClickHoldMaxMs(ms int) {
	c.BrowserCfg.Humanoid.ClickHoldMaxMs = ms
}
func (c *Config) SetBrowserHumanoidKeyHoldMu(ms float64) {
	c.BrowserCfg.Humanoid.KeyHoldMu = ms
}

// Network Setters
func (c *Config) SetNetworkCaptureResponseBodies(b bool) {
	c.NetworkCfg.CaptureResponseBodies = b
}
func (c *Config) SetNetworkNavigationTimeout(d time.Duration) {
	c.NetworkCfg.NavigationTimeout = d
}
func (c *Config) SetNetworkPostLoadWait(d time.Duration) { c.NetworkCfg.PostLoadWait = d }
func (c *Config) SetNetworkIgnoreTLSErrors(b bool)       { c.NetworkCfg.IgnoreTLSErrors = b }

// IAST Setters
func (c *Config) SetIASTEnabled(b bool) { c.IASTCfg.Enabled = b }

// JWT Setters
func (c *Config) SetJWTEnabled(b bool) { c.ScannersCfg.Static.JWT.Enabled = b }
func (c *Config) SetJWTBruteForceEnabled(b bool) {
	c.ScannersCfg.Static.JWT.BruteForceEnabled = b
}

// ATO Setter
func (c *Config) SetATOConfig(atoCfg ATOConfig) {
	c.ScannersCfg.Active.Auth.ATO = atoCfg
}

// AutofixConfig contains settings for the experimental self-healing and
// auto-patching features of the agent.
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

// GitConfig defines the author identity for commits made by the autofix agent.
type GitConfig struct {
	AuthorName  string `mapstructure:"author_name" yaml:"author_name"`
	AuthorEmail string `mapstructure:"author_email" yaml:"author_email"`
}

// GitHubConfig holds the necessary information for the autofix agent to create
// pull requests on GitHub.
type GitHubConfig struct {
	Token      string `mapstructure:"token" yaml:"-"` // Loaded from env, not config file.
	RepoOwner  string `mapstructure:"repo_owner" yaml:"repo_owner"`
	RepoName   string `mapstructure:"repo_name" yaml:"repo_name"`
	BaseBranch string `mapstructure:"base_branch" yaml:"base_branch"`
}

// LoggerConfig defines all settings related to logging, including level, format,
// file rotation, and colorization.
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

// ColorConfig specifies the terminal color codes for different log levels.
type ColorConfig struct {
	Debug  string `mapstructure:"debug" yaml:"debug"`
	Info   string `mapstructure:"info" yaml:"info"`
	Warn   string `mapstructure:"warn" yaml:"warn"`
	Error  string `mapstructure:"error" yaml:"error"`
	DPanic string `mapstructure:"dpanic" yaml:"dpanic"`
	Panic  string `mapstructure:"panic" yaml:"panic"`
	Fatal  string `mapstructure:"fatal" yaml:"fatal"`
}

// DatabaseConfig holds the connection string for the application's database.
type DatabaseConfig struct {
	URL string `mapstructure:"url" yaml:"url"`
}

// EngineConfig provides settings for the core task processing engine, controlling
// concurrency, queue sizes, and timeouts.
type EngineConfig struct {
	QueueSize             int           `mapstructure:"queue_size" yaml:"queue_size"`
	WorkerConcurrency     int           `mapstructure:"worker_concurrency" yaml:"worker_concurrency"`
	DefaultTaskTimeout    time.Duration `mapstructure:"default_task_timeout" yaml:"default_task_timeout"`
	FindingsBatchSize     int           `mapstructure:"findings_batch_size" yaml:"findings_batch_size"`
	FindingsFlushInterval time.Duration `mapstructure:"findings_flush_interval" yaml:"findings_flush_interval"`
}

// BrowserConfig contains all settings for controlling headless browser instances,
// including viewport size, concurrency, and behavioral flags.
type BrowserConfig struct {
	Headless        bool           `mapstructure:"headless" yaml:"headless"`
	DisableCache    bool           `mapstructure:"disable_cache" yaml:"disable_cache"`
	DisableGPU      bool           `mapstructure:"disable_gpu" yaml:"disable_gpu"`
	IgnoreTLSErrors bool           `mapstructure:"ignore_tls_errors" yaml:"ignore_tls_errors"`
	Concurrency     int            `mapstructure:"concurrency" yaml:"concurrency"`
	Debug           bool           `mapstructure:"debug" yaml:"debug"`
	Args            []string       `mapstructure:"args" yaml:"args"`
	Viewport        map[string]int `mapstructure:"viewport" yaml:"viewport"`
	Humanoid        HumanoidConfig `mapstructure:"humanoid" yaml:"humanoid"`
}

// HumanoidConfig contains all settings for the humanoid simulation model,
// which aims to produce realistic, non-deterministic mouse movements,
// typing, and scrolling behavior to evade bot detection.
type HumanoidConfig struct {
	// -- Main Switch --
	Enabled   bool     `mapstructure:"enabled" yaml:"enabled"`
	Providers []string `mapstructure:"providers" yaml:"providers"`

	// -- General Physics & Limits --
	MaxVelocity float64       `mapstructure:"max_velocity" yaml:"max_velocity"`
	TimeStep    time.Duration `mapstructure:"time_step" yaml:"time_step"`
	MaxSimTime  time.Duration `mapstructure:"max_sim_time" yaml:"max_sim_time"`

	// -- Movement Physics (Spring-Damped Model) --
	// Omega: Angular frequency (stiffness of the "spring"). Higher is faster.
	Omega float64 `mapstructure:"omega" yaml:"omega"`
	// Zeta: Damping ratio. Zeta=1 is critically damped, >1 is overdamped (slow),
	// <1 is underdamped (overshoots). 0.85 is a good "human-like" value.
	Zeta float64 `mapstructure:"zeta" yaml:"zeta"`

	// -- Fitts's Law (Terminal Pause Estimation) --
	// Models the time taken to hit a target. Used to estimate pause times.
	// t = a + b * log2(D/W + 1)
	FittsA             float64 `mapstructure:"fitts_a" yaml:"fitts_a"`
	FittsB             float64 `mapstructure:"fitts_b" yaml:"fitts_b"`
	FittsWTerminal     float64 `mapstructure:"fitts_w_terminal" yaml:"fitts_w_terminal"`
	FittsJitterPercent float64 `mapstructure:"fitts_jitter_percent" yaml:"fitts_jitter_percent"`

	// -- Ex-Gaussian Timing Model (Cognitive & Action Delays) --
	// Models human reaction times. Sum of a Normal(mu, sigma) and Exponential(tau).
	// Used for delays *before* an action (e.g., time to "find" the button).
	ExGaussianMu    float64 `mapstructure:"ex_gaussian_mu" yaml:"ex_gaussian_mu"`
	ExGaussianSigma float64 `mapstructure:"ex_gaussian_sigma" yaml:"ex_gaussian_sigma"`
	ExGaussianTau   float64 `mapstructure:"ex_gaussian_tau" yaml:"ex_gaussian_tau"`
	// Separate model for the "task switch" cost (e.g., moving from typing to mousing).
	TaskSwitchMu    float64 `mapstructure:"task_switch_mu" yaml:"task_switch_mu"`
	TaskSwitchSigma float64 `mapstructure:"task_switch_sigma" yaml:"task_switch_sigma"`
	TaskSwitchTau   float64 `mapstructure:"task_switch_tau" yaml:"task_switch_tau"`

	// -- Noise and Perturbations --
	// Pink Noise: Simulates 1/f noise (tremor) in human motor control.
	PinkNoiseAmplitude float64 `mapstructure:"pink_noise_amplitude" yaml:"pink_noise_amplitude"`
	// Gaussian Strength: General random noise added to the physics model.
	GaussianStrength float64 `mapstructure:"gaussian_strength" yaml:"gaussian_strength"`
	// ClickNoise: Random pixel offset when clicking.
	ClickNoise float64 `mapstructure:"click_noise" yaml:"click_noise"`
	// HesitationDriftFactor: How much the cursor "drifts" during a cognitive pause.
	HesitationDriftFactor float64 `mapstructure:"hesitation_drift_factor" yaml:"hesitation_drift_factor"`
	// SDNFactor: State-Dependent Noise factor (noise increases with velocity).
	SDNFactor float64 `mapstructure:"sdn_factor" yaml:"sdn_factor"`

	// -- Anti-Periodicity (Breaking Rhythmic Patterns) --
	AntiPeriodicityMinPause      time.Duration `mapstructure:"anti_periodicity_min_pause" yaml:"anti_periodicity_min_pause"`
	AntiPeriodicityTimeJitter    time.Duration `mapstructure:"anti_periodicity_time_jitter" yaml:"anti_periodicity_time_jitter"`
	AntiPeriodicityFrameDropProb float64       `mapstructure:"anti_periodicity_frame_drop_prob" yaml:"anti_periodicity_frame_drop_prob"`

	// -- Trajectory Behavior & Micro-corrections --
	// If the cursor is > this distance from the "ideal" path, a correction may occur.
	MicroCorrectionThreshold float64 `mapstructure:"micro_correction_threshold" yaml:"micro_correction_threshold"`
	// How far "into" the target to aim (0.8 = 80% of the way to the center).
	TargetInnerAimPercent float64 `mapstructure:"target_inner_aim_percent" yaml:"target_inner_aim_percent"`
	// Biases the aim point based on velocity (aims "ahead" of the target).
	TargetVelocityBiasMax    float64 `mapstructure:"target_velocity_bias_max" yaml:"target_velocity_bias_max"`
	TargetVelocityBiasThresh float64 `mapstructure:"target_velocity_bias_thresh" yaml:"target_velocity_bias_thresh"`
	// Don't bother simulating a move if it's less than this many pixels.
	MinMoveDistance float64 `mapstructure:"min_move_distance" yaml:"min_move_distance"`
	// How close to the target to be considered "arrived".
	TerminalDistThreshold     float64 `mapstructure:"terminal_dist_threshold" yaml:"terminal_dist_threshold"`
	TerminalVelocityThreshold float64 `mapstructure:"terminal_velocity_threshold" yaml:"terminal_velocity_threshold"`
	// Threshold to trigger an "anticipatory" move (e.g., moving the mouse
	// *towards* an element before the "cognitive delay" has finished).
	AnticipatoryMovementThreshold   float64       `mapstructure:"anticipatory_movement_threshold" yaml:"anticipatory_movement_threshold"`
	AnticipatoryMovementDistance    float64       `mapstructure:"anticipatory_movement_distance" yaml:"anticipatory_movement_distance"`
	AnticipatoryMovementDuration    time.Duration `mapstructure:"anticipatory_movement_duration" yaml:"anticipatory_movement_duration"`
	AnticipatoryMovementOmegaFactor float64       `mapstructure:"anticipatory_movement_omega_factor" yaml:"anticipatory_movement_omega_factor"`
	AnticipatoryMovementZetaFactor  float64       `mapstructure:"anticipatory_movement_zeta_factor" yaml:"anticipatory_movement_zeta_factor"`

	// -- Fatigue & Habituation Modeling --
	// Simulates long-term session behavior.
	FatigueIncreaseRate float64 `mapstructure:"fatigue_increase_rate" yaml:"fatigue_increase_rate"`
	FatigueRecoveryRate float64 `mapstructure:"fatigue_recovery_rate" yaml:"fatigue_recovery_rate"`
	HabituationRate     float64 `mapstructure:"habituation_rate" yaml:"habituation_rate"`

	// -- Clicking Behavior --
	ClickHoldMinMs int `mapstructure:"click_hold_min_ms" yaml:"click_hold_min_ms"`
	ClickHoldMaxMs int `mapstructure:"click_hold_max_ms" yaml:"click_hold_max_ms"`

	// -- Inter-Key Delay (IKD) Modeling --
	// KeyHold: How long a single key is pressed down (Ex-Gaussian).
	KeyHoldMu    float64 `mapstructure:"key_hold_mu" yaml:"key_hold_mu"`
	KeyHoldSigma float64 `mapstructure:"key_hold_sigma" yaml:"key_hold_sigma"`
	KeyHoldTau   float64 `mapstructure:"key_hold_tau" yaml:"key_hold_tau"`
	// IKD: Time *between* key presses (Ex-Gaussian).
	IKDMu    float64 `mapstructure:"ikd_mu" yaml:"ikd_mu"`
	IKDSigma float64 `mapstructure:"ikd_sigma" yaml:"ikd_sigma"`
	IKDTau   float64 `mapstructure:"ikd_tau" yaml:"ikd_tau"`
	// Modifiers for IKD based on typing patterns.
	KeyPauseMin              float64 `mapstructure:"key_pause_min" yaml:"key_pause_min"`
	KeyPauseNgramFactor2     float64 `mapstructure:"key_pause_ngram_factor_2" yaml:"key_pause_ngram_factor_2"`
	KeyPauseNgramFactor3     float64 `mapstructure:"key_pause_ngram_factor_3" yaml:"key_pause_ngram_factor_3"`
	IKDHandAlternationBonus  float64 `mapstructure:"ikd_hand_alternation_bonus" yaml:"ikd_hand_alternation_bonus"`
	IKDSameFingerPenalty     float64 `mapstructure:"ikd_same_finger_penalty" yaml:"ikd_same_finger_penalty"`
	IKDDistanceFactor        float64 `mapstructure:"ikd_distance_factor" yaml:"ikd_distance_factor"`
	KeyPauseFatigueFactor    float64 `mapstructure:"key_pause_fatigue_factor" yaml:"key_pause_fatigue_factor"`
	KeyBurstPauseProbability float64 `mapstructure:"key_burst_pause_probability" yaml:"key_burst_pause_probability"`

	// -- Typo Simulation --
	TypoRate                       float64 `mapstructure:"typo_rate" yaml:"typo_rate"`
	TypoHomoglyphRate              float64 `mapstructure:"typo_homoglyph_rate" yaml:"typo_homoglyph_rate"`
	TypoNeighborRate               float64 `mapstructure:"typo_neighbor_rate" yaml:"typo_neighbor_rate"`
	TypoTransposeRate              float64 `mapstructure:"typo_transpose_rate" yaml:"typo_transpose_rate"`
	TypoOmissionRate               float64 `mapstructure:"typo_omission_rate" yaml:"typo_omission_rate"`
	TypoCorrectionProbability      float64 `mapstructure:"typo_correction_probability" yaml:"typo_correction_probability"`
	TypoShiftCorrectionProbability float64 `mapstructure:"typo_shift_correction_probability" yaml:"typo_shift_correction_probability"`
	TypoOmissionNoticeProbability  float64 `mapstructure:"typo_omission_notice_probability" yaml:"typo_omission_notice_probability"`
	TypoInsertionNoticeProbability float64 `mapstructure:"typo_insertion_notice_probability" yaml:"typo_insertion_notice_probability"`
	TypoCorrectionPauseMeanScale   float64 `mapstructure:"typo_correction_pause_mean_scale" yaml:"typo_correction_pause_mean_scale"`
	TypoCorrectionPauseStdDevScale float64 `mapstructure:"typo_correction_pause_std_dev_scale" yaml:"typo_correction_pause_std_dev_scale"`

	// -- Scrolling Behavior --
	ScrollReadDensityFactor      float64 `mapstructure:"scroll_read_density_factor" yaml:"scroll_read_density_factor"`
	ScrollOvershootProbability   float64 `mapstructure:"scroll_overshoot_probability" yaml:"scroll_overshoot_probability"`
	ScrollRegressionProbability  float64 `mapstructure:"scroll_regression_probability" yaml:"scroll_regression_probability"`
	ScrollMouseWheelProbability  float64 `mapstructure:"scroll_mouse_wheel_probability" yaml:"scroll_mouse_wheel_probability"`
	ScrollDetentWheelProbability float64 `mapstructure:"scroll_detent_wheel_probability" yaml:"scroll_detent_wheel_probability"`

	// -- Session Persona Randomization --
	// Applies a jitter to key parameters at the start of each session
	// to create a unique "persona".
	PersonaJitterMovement float64 `mapstructure:"persona_jitter_movement" yaml:"persona_jitter_movement"`
	PersonaJitterDamping  float64 `mapstructure:"persona_jitter_damping" yaml:"persona_jitter_damping"`
	PersonaJitterSkill    float64 `mapstructure:"persona_jitter_skill" yaml:"persona_jitter_skill"`
}

// ProxyConfig defines the settings for an outbound proxy to be used by the
// application's network clients.
type ProxyConfig struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled"`
	Address string `mapstructure:"address" yaml:"address"`
	CACert  string `mapstructure:"ca_cert" yaml:"ca_cert"`
	CAKey   string `mapstructure:"ca_key" yaml:"ca_key"`
}

// NetworkConfig tunes the global network behavior for HTTP clients, such as
// timeouts, default headers, and proxy settings.
type NetworkConfig struct {
	Timeout               time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	NavigationTimeout     time.Duration     `mapstructure:"navigation_timeout" yaml:"navigation_timeout"`
	CaptureResponseBodies bool              `mapstructure:"capture_response_bodies" yaml:"capture_response_bodies"`
	Headers               map[string]string `mapstructure:"headers" yaml:"headers"`
	PostLoadWait          time.Duration     `mapstructure:"post_load_wait" yaml:"post_load_wait"`
	Proxy                 ProxyConfig       `mapstructure:"proxy" yaml:"proxy"`
	IgnoreTLSErrors       bool              `mapstructure:"ignore_tls_errors" yaml:"ignore_tls_errors"`
}

// IASTConfig holds settings for the Interactive Application Security Testing (IAST)
// module, which injects a JavaScript shim to perform taint tracking.
type IASTConfig struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled"`
	ShimPath   string `mapstructure:"shim_path" yaml:"shim_path"`
	ConfigPath string `mapstructure:"config_path" yaml:"config_path"`
}

// ScannersConfig is a container that aggregates the configurations for all
// passive, static, and active security scanners.
type ScannersConfig struct {
	Passive PassiveScannersConfig `mapstructure:"passive" yaml:"passive"`
	Static  StaticScannersConfig  `mapstructure:"static" yaml:"static"`
	Active  ActiveScannersConfig  `mapstructure:"active" yaml:"active"`
}

// PassiveScannersConfig holds settings for scanners that only analyze
// traffic without sending new requests.
type PassiveScannersConfig struct {
	Headers HeadersConfig `mapstructure:"headers" yaml:"headers"`
}

// HeadersConfig enables or disables the passive HTTP header scanner.
type HeadersConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

// StaticScannersConfig holds settings for scanners that perform static analysis
// on response content.
type StaticScannersConfig struct {
	JWT JWTConfig `mapstructure:"jwt" yaml:"jwt"`
}

// JWTConfig defines settings for the JSON Web Token (JWT) static scanner, including
// known secrets and options for brute-force attacks.
type JWTConfig struct {
	Enabled           bool     `mapstructure:"enabled" yaml:"enabled"`
	KnownSecrets      []string `mapstructure:"known_secrets" yaml:"known_secrets"`
	BruteForceEnabled bool     `mapstructure:"brute_force_enabled" yaml:"brute_force_enabled"`
	DictionaryFile    string   `mapstructure:"dictionary_file" yaml:"dictionary_file"`
}

// ActiveScannersConfig holds settings for scanners that actively send malicious
// or malformed requests to probe for vulnerabilities.
type ActiveScannersConfig struct {
	Taint    TaintConfig    `mapstructure:"taint" yaml:"taint"`
	TimeSlip TimeSlipConfig `mapstructure:"timeslip" yaml:"timeslip"`
	Auth     AuthConfig     `mapstructure:"auth" yaml:"auth"`
}

// TaintConfig configures the active taint analysis scanner.
type TaintConfig struct {
	Enabled     bool `mapstructure:"enabled" yaml:"enabled"`
	Depth       int  `mapstructure:"depth" yaml:"depth"`
	Concurrency int  `mapstructure:"concurrency" yaml:"concurrency"`
}

// TimeSlipConfig configures the time-based vulnerability scanner, which looks
// for timing side-channel vulnerabilities.
type TimeSlipConfig struct {
	Enabled        bool `mapstructure:"enabled" yaml:"enabled"`
	RequestCount   int  `mapstructure:"request_count" yaml:"request_count"`
	MaxConcurrency int  `mapstructure:"max_concurrency" yaml:"max_concurrency"`
	ThresholdMs    int  `mapstructure:"threshold_ms" yaml:"threshold_ms"`
}

// AuthConfig aggregates configurations for all authentication-related scanners.
type AuthConfig struct {
	ATO    ATOConfig     `mapstructure:"ato" yaml:"ato"`
	IDOR   IDORConfig    `mapstructure:"idor" yaml:"idor"`
	SignUp *SignUpConfig `mapstructure:"signup" yaml:"signup"`
}

// SignUpConfig defines settings for the autonomous sign-up feature.
type SignUpConfig struct {
	Enabled     bool   `mapstructure:"enabled" yaml:"enabled"`
	EmailDomain string `mapstructure:"email_domain" yaml:"email_domain"`
}

// ATOConfig configures the Account Takeover (ATO) scanner, which performs
// credential stuffing and password spraying attacks.
type ATOConfig struct {
	Enabled                bool     `mapstructure:"enabled" yaml:"enabled"`
	CredentialFile         string   `mapstructure:"credential_file" yaml:"credential_file"`
	SecListsPath           string   `mapstructure:"seclists_path" yaml:"seclists_path"`
	Concurrency            int      `mapstructure:"concurrency" yaml:"concurrency"`
	MinRequestDelayMs      int      `mapstructure:"min_request_delay_ms" yaml:"min_request_delay_ms"`
	RequestDelayJitterMs   int      `mapstructure:"request_delay_jitter_ms" yaml:"request_delay_jitter_ms"`
	SuccessKeywords        []string `mapstructure:"success_keywords" yaml:"success_keywords"`
	UserFailureKeywords    []string `mapstructure:"user_failure_keywords" yaml:"user_failure_keywords"`
	PassFailureKeywords    []string `mapstructure:"pass_failure_keywords" yaml:"pass_failure_keywords"`
	GenericFailureKeywords []string `mapstructure:"generic_failure_keywords" yaml:"generic_failure_keywords"`
	LockoutKeywords        []string `mapstructure:"lockout_keywords" yaml:"lockout_keywords"`
	MFAKeywords            []string `mapstructure:"mfa_keywords" yaml:"mfa_keywords"`
}

// IDORConfig defines settings for the Insecure Direct Object Reference (IDOR) scanner.
type IDORConfig struct {
	Enabled        bool                `mapstructure:"enabled" yaml:"enabled"`
	IgnoreList     []string            `mapstructure:"ignore_list" yaml:"ignore_list"`
	TestStrategies map[string][]string `mapstructure:"test_strategies" yaml:"test_strategies"`
}

// ScanConfig holds settings for a specific scan job, typically populated from
// command-line flags.
type ScanConfig struct {
	Targets     []string
	Output      string
	Format      string
	Concurrency int
	Depth       int
	Scope       string
}

// DiscoveryConfig contains settings for the initial asset discovery and
// enumeration phase of a scan.
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

// KnowledgeGraphConfig specifies the backend database for the agent's knowledge graph.
type KnowledgeGraphConfig struct {
	Type     string         `mapstructure:"type" yaml:"type"`
	Postgres PostgresConfig `mapstructure:"postgres" yaml:"postgres"`
}

// AgentConfig aggregates settings for the AI agent, including its LLM router,
// knowledge graph, long-term memory, and self-improvement (evolution) features.
type AgentConfig struct {
	LLM            LLMRouterConfig      `mapstructure:"llm" yaml:"llm"`
	Evolution      EvolutionConfig      `mapstructure:"evolution" yaml:"evolution"`
	KnowledgeGraph KnowledgeGraphConfig `mapstructure:"knowledge_graph" yaml:"knowledge_graph"`
	LTM            LTMConfig            `mapstructure:"ltm" yaml:"ltm"`
}

// LTMConfig holds settings for the agent's Long-Term Memory (LTM) module,
// which is used for caching and knowledge retention.
type LTMConfig struct {
	CacheTTLSeconds             int `mapstructure:"cache_ttl_seconds" yaml:"cache_ttl_seconds"`
	CacheJanitorIntervalSeconds int `mapstructure:"cache_janitor_interval_seconds" yaml:"cache_janitor_interval_seconds"`
}

// EvolutionConfig contains settings for the agent's self-improvement and
// code evolution capabilities.
type EvolutionConfig struct {
	Enabled    bool          `mapstructure:"enabled" yaml:"enabled"`
	MaxCycles  int           `mapstructure:"max_cycles" yaml:"max_cycles"`
	SettleTime time.Duration `mapstructure:"settle_time" yaml:"settle_time"`
}

// LLMProvider is an enumeration of the supported Large Language Model providers.
type LLMProvider string

// Supported LLM providers.
const (
	ProviderGemini    LLMProvider = "gemini"
	ProviderOpenAI    LLMProvider = "openai"
	ProviderAnthropic LLMProvider = "anthropic"
	ProviderOllama    LLMProvider = "ollama"
)

// LLMRouterConfig defines the settings for routing requests to different LLMs
// based on whether a "fast" or "powerful" model is required.
type LLMRouterConfig struct {
	DefaultFastModel     string                    `mapstructure:"default_fast_model" yaml:"default_fast_model"`
	DefaultPowerfulModel string                    `mapstructure:"default_powerful_model" yaml:"default_powerful_model"`
	Models               map[string]LLMModelConfig `mapstructure:"models" yaml:"models"`
}

// LLMModelConfig specifies the connection and generation parameters for a single
// Large Language Model.
type LLMModelConfig struct {
	Provider LLMProvider `mapstructure:"provider" yaml:"provider"`
	Model    string      `mapstructure:"model" yaml:"model"`
	// APIKey can be set in YAML or injected via environment variables (preferred).
	APIKey string `mapstructure:"api_key" yaml:"api_key"`
	// Endpoint specifies the API endpoint. Format depends on the provider and SDK (e.g., "hostname:port" for Gemini SDK).
	Endpoint      string            `mapstructure:"endpoint" yaml:"endpoint"`
	APITimeout    time.Duration     `mapstructure:"api_timeout" yaml:"api_timeout"`
	Temperature   float64           `mapstructure:"temperature" yaml:"temperature"`
	TopP          float64           `mapstructure:"top_p" yaml:"top_p"`
	TopK          int               `mapstructure:"top_k" yaml:"top_k"`
	MaxTokens     int               `mapstructure:"max_tokens" yaml:"max_tokens"`
	SafetyFilters map[string]string `mapstructure:"safety_filters" yaml:"safety_filters"`
}

// NewDefaultConfig creates a new Config struct and populates it with default
// values by calling SetDefaults. This ensures that the application has a
// sensible baseline configuration even if a config file is missing.
func NewDefaultConfig() *Config {
	v := viper.New()
	SetDefaults(v)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		// This should not happen with defaults, but good to be safe.
		panic(fmt.Sprintf("failed to unmarshal default config: %v", err))
	}

	// Apply the robust fallback logic here too, just in case Viper fails to unmarshal defaults correctly.
	if cfg.AgentCfg.LLM.Models == nil {
		cfg.AgentCfg.LLM.Models = make(map[string]LLMModelConfig)
	}

	// FIX: Apply the corrected fallback logic. If the map is empty after unmarshaling defaults, populate it.
	if len(cfg.AgentCfg.LLM.Models) == 0 {
		cfg.AgentCfg.LLM.Models = getDefaultLLMModels()
	}

	return &cfg
}

// SetDefaults applies a comprehensive set of default values to a `viper.Viper`
// instance. This ensures that all configuration parameters have a sensible
// fallback value, preventing nil pointer errors and establishing a baseline
// behavior for the application out-of-the-box.
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
	v.SetDefault("logger.colors.debug", "cyan")
	v.SetDefault("logger.colors.info", "green")
	v.SetDefault("logger.colors.warn", "yellow")
	v.SetDefault("logger.colors.error", "red")
	v.SetDefault("logger.colors.dpanic", "magenta")
	v.SetDefault("logger.colors.panic", "magenta")
	v.SetDefault("logger.colors.fatal", "magenta")

	// -- Engine --
	v.SetDefault("engine.queue_size", 1000)
	v.SetDefault("engine.worker_concurrency", 10)
	v.SetDefault("engine.default_task_timeout", "30m")
	v.SetDefault("engine.findings_batch_size", 100)
	v.SetDefault("engine.findings_flush_interval", "2s")

	// -- Browser --
	v.SetDefault("browser.headless", true)
	v.SetDefault("browser.disable_cache", true)
	v.SetDefault("browser.disable_gpu", true)
	v.SetDefault("browser.ignore_tls_errors", false)
	v.SetDefault("browser.concurrency", 4)
	v.SetDefault("browser.debug", true)
	// Initialize all Humanoid defaults
	setHumanoidDefaults(v)

	// -- Network --
	v.SetDefault("network.timeout", "2m")
	v.SetDefault("network.navigation_timeout", "5m")
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
	v.SetDefault("scanners.active.timeslip.enabled", false)
	v.SetDefault("scanners.active.auth.ato.enabled", true)
	v.SetDefault("scanners.active.auth.ato.seclists_path", "~/SecLists")
	v.SetDefault("scanners.active.auth.idor.enabled", true)
	v.SetDefault("scanners.active.auth.signup.enabled", false)
	v.SetDefault("scanners.active.auth.signup.email_domain", "example.com")

	// -- Discovery --
	v.SetDefault("discovery.max_depth", 5)
	v.SetDefault("discovery.concurrency", 20)
	v.SetDefault("discovery.timeout", "30m")
	v.SetDefault("discovery.passive_enabled", true)
	v.SetDefault("discovery.include_subdomains", true)
	v.SetDefault("discovery.crtsh_rate_limit", 2.0)
	v.SetDefault("discovery.passive_concurrency", 10)

	// -- Agent --
	v.SetDefault("agent.llm.default_fast_model", "gemini-2.5-flash")
	v.SetDefault("agent.llm.default_powerful_model", "gemini-3-pro")
	// Set up default model configurations in the map using the robust method.
	setLLMDefaults(v)
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

	// -- Agent LTM --
	v.SetDefault("agent.ltm.cache_ttl_seconds", 300)             // 5 minutes
	v.SetDefault("agent.ltm.cache_janitor_interval_seconds", 60) // 1 minute

	// -- Autofix --
	v.SetDefault("autofix.enabled", false)
	v.SetDefault("autofix.min_confidence_threshold", 0.75)
	v.SetDefault("autofix.cooldown_seconds", 300)
	v.SetDefault("autofix.keep_workspace_on_failure", false)
	v.SetDefault("autofix.git.author_name", "scalpel-autofix-bot")
	v.SetDefault("autofix.git.author_email", "autofix@scalpel.security")
	v.SetDefault("autofix.github.base_branch", "main")
}

// setHumanoidDefaults provides a comprehensive set of default values for the humanoid simulation.
func setHumanoidDefaults(v *viper.Viper) {
	const prefix = "browser.humanoid."
	// -- Main Switch --
	v.SetDefault(prefix+"enabled", true)

	// -- General Physics & Limits --
	v.SetDefault(prefix+"max_velocity", 2500.0)
	v.SetDefault(prefix+"time_step", "8ms")
	v.SetDefault(prefix+"max_sim_time", "5s")

	// -- Movement Physics (Spring-Damped Model) --
	v.SetDefault(prefix+"omega", 25.0)
	v.SetDefault(prefix+"zeta", 0.85)

	// -- Fitts's Law (Terminal Pause Estimation) --
	v.SetDefault(prefix+"fitts_a", 120.0)
	v.SetDefault(prefix+"fitts_b", 140.0)
	v.SetDefault(prefix+"fitts_w_terminal", 10.0)
	v.SetDefault(prefix+"fitts_jitter_percent", 0.15)

	// -- Ex-Gaussian Timing Model (Cognitive & Action Delays) --
	v.SetDefault(prefix+"ex_gaussian_mu", 150.0)
	v.SetDefault(prefix+"ex_gaussian_sigma", 40.0)
	v.SetDefault(prefix+"ex_gaussian_tau", 80.0)
	v.SetDefault(prefix+"task_switch_mu", 200.0)
	v.SetDefault(prefix+"task_switch_sigma", 60.0)
	v.SetDefault(prefix+"task_switch_tau", 120.0)

	// -- Noise and Perturbations --
	v.SetDefault(prefix+"pink_noise_amplitude", 2.5)
	v.SetDefault(prefix+"gaussian_strength", 0.7)
	v.SetDefault(prefix+"click_noise", 1.5)
	v.SetDefault(prefix+"hesitation_drift_factor", 1.5)
	v.SetDefault(prefix+"sdn_factor", 0.001)

	// -- Anti-Periodicity (Breaking Rhythmic Patterns) --
	v.SetDefault(prefix+"anti_periodicity_min_pause", "200ms")
	v.SetDefault(prefix+"anti_periodicity_time_jitter", "3ms")
	v.SetDefault(prefix+"anti_periodicity_frame_drop_prob", 0.05)

	// -- Trajectory Behavior & Micro-corrections --
	v.SetDefault(prefix+"micro_correction_threshold", 150.0)
	v.SetDefault(prefix+"target_inner_aim_percent", 0.8)
	v.SetDefault(prefix+"target_velocity_bias_max", 0.1)
	v.SetDefault(prefix+"target_velocity_bias_thresh", 800.0)
	v.SetDefault(prefix+"min_move_distance", 2.0)
	v.SetDefault(prefix+"terminal_dist_threshold", 1.5)
	v.SetDefault(prefix+"terminal_velocity_threshold", 20.0)
	v.SetDefault(prefix+"anticipatory_movement_threshold", 200.0)
	v.SetDefault(prefix+"anticipatory_movement_distance", 5.0)
	v.SetDefault(prefix+"anticipatory_movement_duration", "50ms")
	v.SetDefault(prefix+"anticipatory_movement_omega_factor", 0.3)
	v.SetDefault(prefix+"anticipatory_movement_zeta_factor", 2.0)

	// -- Fatigue & Habituation Modeling --
	v.SetDefault(prefix+"fatigue_increase_rate", 0.01)
	v.SetDefault(prefix+"fatigue_recovery_rate", 0.02)
	v.SetDefault(prefix+"habituation_rate", 0.005)

	// -- Clicking Behavior --
	v.SetDefault(prefix+"click_hold_min_ms", 40)
	v.SetDefault(prefix+"click_hold_max_ms", 120)

	// -- Inter-Key Delay (IKD) Modeling --
	v.SetDefault(prefix+"key_hold_mu", 50.0)
	v.SetDefault(prefix+"key_hold_sigma", 15.0)
	v.SetDefault(prefix+"key_hold_tau", 25.0)
	v.SetDefault(prefix+"ikd_mu", 90.0)
	v.SetDefault(prefix+"ikd_sigma", 30.0)
	v.SetDefault(prefix+"ikd_tau", 40.0)
	v.SetDefault(prefix+"key_pause_min", 20.0)
	v.SetDefault(prefix+"key_pause_ngram_factor_2", 0.75)
	v.SetDefault(prefix+"key_pause_ngram_factor_3", 0.65)
	v.SetDefault(prefix+"ikd_hand_alternation_bonus", 0.8)
	v.SetDefault(prefix+"ikd_same_finger_penalty", 1.4)
	v.SetDefault(prefix+"ikd_distance_factor", 0.05)
	v.SetDefault(prefix+"key_pause_fatigue_factor", 0.4)
	v.SetDefault(prefix+"key_burst_pause_probability", 0.03)

	// -- Typo Simulation --
	v.SetDefault(prefix+"typo_rate", 0.04)
	v.SetDefault(prefix+"typo_homoglyph_rate", 0.10)
	v.SetDefault(prefix+"typo_neighbor_rate", 0.40)
	v.SetDefault(prefix+"typo_transpose_rate", 0.15)
	v.SetDefault(prefix+"typo_omission_rate", 0.15)
	v.SetDefault(prefix+"typo_correction_probability", 0.85)
	v.SetDefault(prefix+"typo_shift_correction_probability", 0.95)
	v.SetDefault(prefix+"typo_omission_notice_probability", 0.60)
	v.SetDefault(prefix+"typo_insertion_notice_probability", 0.70)
	v.SetDefault(prefix+"typo_correction_pause_mean_scale", 4.0)
	v.SetDefault(prefix+"typo_correction_pause_std_dev_scale", 2.0)

	// -- Scrolling Behavior --
	v.SetDefault(prefix+"scroll_read_density_factor", 0.7)
	v.SetDefault(prefix+"scroll_overshoot_probability", 0.20)
	v.SetDefault(prefix+"scroll_regression_probability", 0.10)
	v.SetDefault(prefix+"scroll_mouse_wheel_probability", 0.60)
	v.SetDefault(prefix+"scroll_detent_wheel_probability", 0.75)

	// -- Session Persona Randomization --
	v.SetDefault(prefix+"persona_jitter_movement", 0.15)
	v.SetDefault(prefix+"persona_jitter_damping", 0.10)
	v.SetDefault(prefix+"persona_jitter_skill", 0.20)
}

// NewConfigFromViper unmarshals a `viper.Viper` instance into a `Config` struct.
// It is the primary mechanism for loading configuration from files and environment
// variables. It also binds specific environment variables for sensitive data
// (like API keys and database URLs) and performs validation on the resulting
// configuration.
func NewConfigFromViper(v *viper.Viper) (*Config, error) {
	var cfg Config

	// Bind environment variables for sensitive data and critical configuration.
	v.BindEnv("database.url", "SCALPEL_DATABASE_URL")
	v.BindEnv("autofix.github.token", "SCALPEL_AUTOFIX_GH_TOKEN")
	v.BindEnv("agent.knowledge_graph.postgres.password", "SCALPEL_KG_PASSWORD")

	// Bind environment variables for LLM API keys.
	// We define internal Viper keys (e.g., "llm.keys.gemini") for binding, as binding directly
	// to nested map elements (agent.llm.models.gemini-2.5-pro.api_key) can be unreliable in Viper.
	// We allow multiple environment variable names for flexibility (e.g., standard GEMINI_API_KEY, GOOGLE_API_KEY or app-specific SCALPEL_GEMINI_API_KEY).
	v.BindEnv("llm.keys.gemini", "SCALPEL_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
	v.BindEnv("llm.keys.openai", "SCALPEL_OPENAI_API_KEY", "OPENAI_API_KEY")
	v.BindEnv("llm.keys.anthropic", "SCALPEL_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")

	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Manually load the token if Unmarshal didn't pick it up (fallback)
	if cfg.AutofixCfg.Enabled && cfg.AutofixCfg.GitHub.Token == "" {
		if token := v.GetString("autofix.github.token"); token != "" {
			cfg.AutofixCfg.GitHub.Token = token
		} else {
			cfg.AutofixCfg.GitHub.Token = os.Getenv("SCALPEL_AUTOFIX_GH_TOKEN")
		}
	}

	// -- MERGE DEFAULTS BLOCK --
	// Viper overwrites maps completely. If config.yaml defines ANY models,
	// the default "gemini-2.5-flash" entries are lost.
	// We must manually merge the hardcoded defaults back in if they are missing.
	defaults := getDefaultLLMModels()

	// Ensure map exists
	if cfg.AgentCfg.LLM.Models == nil {
		cfg.AgentCfg.LLM.Models = make(map[string]LLMModelConfig)
	}

	// Loop through defaults and add them only if the user hasn't defined them
	for key, defaultModel := range defaults {
		if _, exists := cfg.AgentCfg.LLM.Models[key]; !exists {
			cfg.AgentCfg.LLM.Models[key] = defaultModel
		}
	}
	// -- END MERGE DEFAULTS BLOCK --

	// -- API KEY INJECTION BLOCK --
	// Manually inject API keys from environment variables if they are not set in the config file.
	// This follows security best practices by allowing users to keep secrets out of config.yaml.

	geminiKey := v.GetString("llm.keys.gemini")
	openAIKey := v.GetString("llm.keys.openai")
	anthropicKey := v.GetString("llm.keys.anthropic")

	// Iterate over the models (must iterate over keys and update the map because range iteration variables are copies)
	for key, modelCfg := range cfg.AgentCfg.LLM.Models {
		// Check if the APIKey is empty (not present in YAML or explicitly empty).
		if modelCfg.APIKey == "" {
			switch modelCfg.Provider {
			case ProviderGemini:
				if geminiKey != "" {
					modelCfg.APIKey = geminiKey
				}
			case ProviderOpenAI:
				if openAIKey != "" {
					modelCfg.APIKey = openAIKey
				}
			case ProviderAnthropic:
				if anthropicKey != "" {
					modelCfg.APIKey = anthropicKey
				}
				// Ollama typically doesn't require an API key.
			}
			// Update the map entry with the potentially modified config
			cfg.AgentCfg.LLM.Models[key] = modelCfg
		}
	}
	// -- END API KEY INJECTION BLOCK --

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return &cfg, nil
}

// Validate performs a top-level validation of the main `Config` struct, ensuring
// that essential parameters are set and have sane values. It delegates more
// specific validation to the `Validate` methods of its sub-configuration structs.
func (c *Config) Validate() error {
	if c.EngineCfg.WorkerConcurrency <= 0 {
		return fmt.Errorf("engine.worker_concurrency must be a positive integer")
	}
	if c.BrowserCfg.Concurrency <= 0 {
		return fmt.Errorf("browser.concurrency must be a positive integer")
	}
	if err := c.AutofixCfg.Validate(); err != nil {
		return fmt.Errorf("autofix configuration invalid: %w", err)
	}
	if err := c.AgentCfg.Validate(); err != nil {
		return fmt.Errorf("agent configuration invalid: %w", err)
	}
	return nil
}

// getDefaultSafetyFilters returns the standard set of safety filters applied to LLM requests by default.
func getDefaultSafetyFilters() map[string]string {
	// We set these to BLOCK_NONE by default to ensure the LLM can analyze security-related content.
	// Users can override this in their config.yaml if they prefer stricter settings.
	return map[string]string{
		"HARM_CATEGORY_HATE_SPEECH":       "BLOCK_NONE",
		"HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
		"HARM_CATEGORY_HARASSMENT":        "BLOCK_NONE",
		"HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
		// Added CIVIC_INTEGRITY to match the updated client map.
		"HARM_CATEGORY_CIVIC_INTEGRITY": "BLOCK_NONE",
	}
}

// getDefaultLLMModels returns the default LLM configuration map.
// This provides a definitive source of truth for defaults, used for robust merging.
func getDefaultLLMModels() map[string]LLMModelConfig {
	return map[string]LLMModelConfig{
		// Gemini 2.5 Flash (Stable) - High speed, lower cost
		"gemini-2.5-flash": {
			Provider:      ProviderGemini,
			Model:         "gemini-2-5-flash",
			APIKey:        "", // Should be loaded from env
			APITimeout:    90 * time.Second,
			Temperature:   0.8,
			TopP:          0.95,
			TopK:          50,
			MaxTokens:     8192, // Increased standard for 2.5
			SafetyFilters: getDefaultSafetyFilters(),
		},
		// Gemini 2.5 Pro (Stable) - Reliable production workhorse
		"gemini-2.5-pro": {
			Provider:      ProviderGemini,
			Model:         "gemini-2-5-pro",
			APIKey:        "", // Should be loaded from env
			APITimeout:    2 * time.Minute,
			Temperature:   0.7,
			TopP:          0.9,
			TopK:          40,
			MaxTokens:     8192,
			SafetyFilters: getDefaultSafetyFilters(),
		},
		// Gemini 3.0 Pro (Preview) - The new default for complex reasoning
		"gemini-3-pro": {
			Provider:      ProviderGemini,
			Model:         "gemini-3-pro-preview",
			APIKey:        "",
			APITimeout:    4 * time.Minute, // Increased timeout for deep reasoning
			Temperature:   0.7,
			TopP:          0.95,
			TopK:          64,
			MaxTokens:     65536, // Significantly higher output limit
			SafetyFilters: getDefaultSafetyFilters(),
		},
	}
}

// setLLMDefaults populates the models map with default configurations for the LLM router.
func setLLMDefaults(v *viper.Viper) {
	defaultModels := getDefaultLLMModels()

	// Convert the structured Go map to the map[string]interface{} format Viper prefers for defaults.
	// This ensures Viper can correctly merge defaults when keys contain dots.
	viperDefaults := make(map[string]interface{})
	for key, model := range defaultModels {
		// We need to convert the struct to a map[string]interface{}.
		// We use json Marshal/Unmarshal for a quick conversion.
		// We must use standard encoding/json here for reliability in this conversion step.

		// Create a temporary struct using json tags that match the mapstructure/yaml tags for conversion.
		// This is necessary because the main LLMModelConfig uses mapstructure tags, not json tags.
		type viperModel struct {
			Provider LLMProvider `json:"provider"`
			Model    string      `json:"model"`
			APIKey   string      `json:"api_key"`
			Endpoint string      `json:"endpoint,omitempty"`
			// APITimeout is handled separately below
			Temperature   float64           `json:"temperature"`
			TopP          float64           `json:"top_p"`
			TopK          int               `json:"top_k"`
			MaxTokens     int               `json:"max_tokens"`
			SafetyFilters map[string]string `json:"safety_filters"`
		}

		tempModel := viperModel{
			Provider:      model.Provider,
			Model:         model.Model,
			APIKey:        model.APIKey,
			Endpoint:      model.Endpoint,
			Temperature:   model.Temperature,
			TopP:          model.TopP,
			TopK:          model.TopK,
			MaxTokens:     model.MaxTokens,
			SafetyFilters: model.SafetyFilters,
		}

		modelBytes, err := json.Marshal(tempModel)
		if err != nil {
			// Should not happen with this struct, but good practice.
			panic(fmt.Sprintf("Failed to marshal default LLM model config for Viper: %v", err))
		}

		modelMap := make(map[string]interface{})
		if err := json.Unmarshal(modelBytes, &modelMap); err != nil {
			panic(fmt.Sprintf("Failed to unmarshal default LLM model config for Viper: %v", err))
		}

		// Viper needs time.Duration represented as strings for defaults/config files.
		modelMap["api_timeout"] = model.APITimeout.String()

		viperDefaults[key] = modelMap
	}

	// Set the default for the entire map key.
	v.SetDefault("agent.llm.models", viperDefaults)
}

// Validate checks the AutofixConfig for correctness, ensuring that if the feature
// is enabled, all required fields (like GitHub repository details and token)
// are present.
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

// Validate checks the EvolutionConfig, ensuring that if the feature is enabled,
// its parameters (like `MaxCycles`) are valid.
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

// Validate checks the AgentConfig, delegating validation to its sub-modules
// like Evolution and LTM.
func (a *AgentConfig) Validate() error {
	if err := a.Evolution.Validate(); err != nil {
		return err
	}
	if err := a.LTM.Validate(); err != nil {
		return err
	}
	// -- MERGED LINE --
	if err := a.LLM.Validate(); err != nil {
		return fmt.Errorf("llm config invalid: %w", err)
	}
	return nil
}

// Validate checks the LLMRouterConfig to ensure the specified default
// models actually exist in the models map.
func (l *LLMRouterConfig) Validate() error {
	// FIX: Handle the case where the map might be empty (e.g., if initialization failed).
	// Although NewConfigFromViper aims to prevent this, this provides defense-in-depth.
	if len(l.Models) == 0 {
		// If no models are configured at all, we cannot proceed.
		return fmt.Errorf("no LLM models are configured. At least one model must be defined in agent.llm.models")
	}

	if l.DefaultFastModel == "" {
		return fmt.Errorf("default_fast_model must be set")
	}
	if _, exists := l.Models[l.DefaultFastModel]; !exists {
		return fmt.Errorf("default_fast_model '%s' not found in the models map", l.DefaultFastModel)
	}

	if l.DefaultPowerfulModel == "" {
		return fmt.Errorf("default_powerful_model must be set")
	}
	if _, exists := l.Models[l.DefaultPowerfulModel]; !exists {
		return fmt.Errorf("default_powerful_model '%s' not found in the models map", l.DefaultPowerfulModel)
	}

	// Also validate that all configured models are valid
	for key, modelCfg := range l.Models {
		if modelCfg.Provider == "" {
			return fmt.Errorf("model '%s' (key: %s) has no provider", modelCfg.Model, key)
		}
		if modelCfg.Model == "" {
			return fmt.Errorf("model key '%s' has no 'model' name property", key)
		}
		// Note: We do not strictly validate the presence of APIKey here, as some providers (like Ollama) do not require it,
		// and keys might be loaded via environment variables just before this validation runs.
		// The specific client implementation (e.g., NewGoogleClient) will perform the final validation if a key is required.
	}

	return nil
}

// Validate checks the LTMConfig, ensuring that cache TTL and janitor intervals
// are positive values.
func (l *LTMConfig) Validate() error {
	if l.CacheTTLSeconds <= 0 {
		return fmt.Errorf("agent.ltm.cache_ttl_seconds must be a positive integer")
	}
	if l.CacheJanitorIntervalSeconds <= 0 {
		return fmt.Errorf("agent.ltm.cache_janitor_interval_seconds must be a positive integer")
	}
	return nil
}
