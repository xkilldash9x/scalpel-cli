// File: internal/config/humanoid_config.go
package config

import (
	"time"

	"github.com/spf13/viper"
)

// HumanoidConfig holds all settings for the humanoid browser interaction library.
type HumanoidConfig struct {
	Enabled   bool     `mapstructure:"enabled" yaml:"enabled"`
	Providers []string `mapstructure:"providers" yaml:"providers"`

	// -- General Physics & Limits --
	MaxVelocity float64       `mapstructure:"max_velocity" yaml:"max_velocity"`
	TimeStep    time.Duration `mapstructure:"time_step" yaml:"time_step"`
	MaxSimTime  time.Duration `mapstructure:"max_sim_time" yaml:"max_sim_time"`

	// -- Movement Physics (Spring-Damped Model) --
	Omega float64 `mapstructure:"omega" yaml:"omega"` // Natural frequency (speed)
	Zeta  float64 `mapstructure:"zeta" yaml:"zeta"`   // Damping ratio (smoothness)

	// -- Fitts's Law (Used for Terminal Pause Estimation) --
	FittsA             float64 `mapstructure:"fitts_a" yaml:"fitts_a"`
	FittsB             float64 `mapstructure:"fitts_b" yaml:"fitts_b"`
	FittsWTerminal     float64 `mapstructure:"fitts_w_terminal" yaml:"fitts_w_terminal"`
	FittsJitterPercent float64 `mapstructure:"fitts_jitter_percent" yaml:"fitts_jitter_percent"`

	// -- Ex-Gaussian Timing Model (Cognitive & Action Delays) --
	ExGaussianMu    float64 `mapstructure:"ex_gaussian_mu" yaml:"ex_gaussian_mu"`
	ExGaussianSigma float64 `mapstructure:"ex_gaussian_sigma" yaml:"ex_gaussian_sigma"`
	ExGaussianTau   float64 `mapstructure:"ex_gaussian_tau" yaml:"ex_gaussian_tau"`
	TaskSwitchMu    float64 `mapstructure:"task_switch_mu" yaml:"task_switch_mu"`
	TaskSwitchSigma float64 `mapstructure:"task_switch_sigma" yaml:"task_switch_sigma"`
	TaskSwitchTau   float64 `mapstructure:"task_switch_tau" yaml:"task_switch_tau"`

	// -- Noise and Perturbations --
	PinkNoiseAmplitude    float64 `mapstructure:"pink_noise_amplitude" yaml:"pink_noise_amplitude"`
	GaussianStrength      float64 `mapstructure:"gaussian_strength" yaml:"gaussian_strength"`
	ClickNoise            float64 `mapstructure:"click_noise" yaml:"click_noise"`
	HesitationDriftFactor float64 `mapstructure:"hesitation_drift_factor" yaml:"hesitation_drift_factor"`
	SDNFactor             float64 `mapstructure:"sdn_factor" yaml:"sdn_factor"` // Signal-Dependent Noise

	// -- Anti-Periodicity (Breaking Rhythmic Patterns) --
	AntiPeriodicityMinPause      time.Duration `mapstructure:"anti_periodicity_min_pause" yaml:"anti_periodicity_min_pause"`
	AntiPeriodicityTimeJitter    time.Duration `mapstructure:"anti_periodicity_time_jitter" yaml:"anti_periodicity_time_jitter"`
	AntiPeriodicityFrameDropProb float64       `mapstructure:"anti_periodicity_frame_drop_prob" yaml:"anti_periodicity_frame_drop_prob"`

	// -- Trajectory Behavior & Micro-corrections --
	MicroCorrectionThreshold        float64       `mapstructure:"micro_correction_threshold" yaml:"micro_correction_threshold"`
	TargetInnerAimPercent           float64       `mapstructure:"target_inner_aim_percent" yaml:"target_inner_aim_percent"`
	TargetVelocityBiasMax           float64       `mapstructure:"target_velocity_bias_max" yaml:"target_velocity_bias_max"`
	TargetVelocityBiasThresh        float64       `mapstructure:"target_velocity_bias_thresh" yaml:"target_velocity_bias_thresh"`
	MinMoveDistance                 float64       `mapstructure:"min_move_distance" yaml:"min_move_distance"`
	TerminalDistThreshold           float64       `mapstructure:"terminal_dist_threshold" yaml:"terminal_dist_threshold"`
	TerminalVelocityThreshold       float64       `mapstructure:"terminal_velocity_threshold" yaml:"terminal_velocity_threshold"`
	AnticipatoryMovementThreshold   float64       `mapstructure:"anticipatory_movement_threshold" yaml:"anticipatory_movement_threshold"`
	AnticipatoryMovementDistance    float64       `mapstructure:"anticipatory_movement_distance" yaml:"anticipatory_movement_distance"`
	AnticipatoryMovementDuration    time.Duration `mapstructure:"anticipatory_movement_duration" yaml:"anticipatory_movement_duration"`
	AnticipatoryMovementOmegaFactor float64       `mapstructure:"anticipatory_movement_omega_factor" yaml:"anticipatory_movement_omega_factor"`
	AnticipatoryMovementZetaFactor  float64       `mapstructure:"anticipatory_movement_zeta_factor" yaml:"anticipatory_movement_zeta_factor"`

	// -- Fatigue & Habituation Modeling --
	FatigueIncreaseRate float64 `mapstructure:"fatigue_increase_rate" yaml:"fatigue_increase_rate"`
	FatigueRecoveryRate float64 `mapstructure:"fatigue_recovery_rate" yaml:"fatigue_recovery_rate"`
	HabituationRate     float64 `mapstructure:"habituation_rate" yaml:"habituation_rate"`

	// -- Clicking Behavior ---
	ClickHoldMinMs int `mapstructure:"click_hold_min_ms" yaml:"click_hold_min_ms"`
	ClickHoldMaxMs int `mapstructure:"click_hold_max_ms" yaml:"click_hold_max_ms"`

	// -- Inter-Key Delay (IKD) Modeling ---
	KeyHoldMu                float64 `mapstructure:"key_hold_mu" yaml:"key_hold_mu"`
	KeyHoldSigma             float64 `mapstructure:"key_hold_sigma" yaml:"key_hold_sigma"`
	KeyHoldTau               float64 `mapstructure:"key_hold_tau" yaml:"key_hold_tau"`
	IKDMu                    float64 `mapstructure:"ikd_mu" yaml:"ikd_mu"`
	IKDSigma                 float64 `mapstructure:"ikd_sigma" yaml:"ikd_sigma"`
	IKDTau                   float64 `mapstructure:"ikd_tau" yaml:"ikd_tau"`
	KeyPauseMin              float64 `mapstructure:"key_pause_min" yaml:"key_pause_min"`
	KeyPauseNgramFactor2     float64 `mapstructure:"key_pause_ngram_factor_2" yaml:"key_pause_ngram_factor_2"`
	KeyPauseNgramFactor3     float64 `mapstructure:"key_pause_ngram_factor_3" yaml:"key_pause_ngram_factor_3"`
	IKDHandAlternationBonus  float64 `mapstructure:"ikd_hand_alternation_bonus" yaml:"ikd_hand_alternation_bonus"`
	IKDSameFingerPenalty     float64 `mapstructure:"ikd_same_finger_penalty" yaml:"ikd_same_finger_penalty"`
	IKDDistanceFactor        float64 `mapstructure:"ikd_distance_factor" yaml:"ikd_distance_factor"`
	KeyPauseFatigueFactor    float64 `mapstructure:"key_pause_fatigue_factor" yaml:"key_pause_fatigue_factor"`
	KeyBurstPauseProbability float64 `mapstructure:"key_burst_pause_probability" yaml:"key_burst_pause_probability"`

	// --- Typo Simulation ---
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

	// --- Scrolling Behavior ---
	ScrollReadDensityFactor      float64 `mapstructure:"scroll_read_density_factor" yaml:"scroll_read_density_factor"`
	ScrollOvershootProbability   float64 `mapstructure:"scroll_overshoot_probability" yaml:"scroll_overshoot_probability"`
	ScrollRegressionProbability  float64 `mapstructure:"scroll_regression_probability" yaml:"scroll_regression_probability"`
	ScrollMouseWheelProbability  float64 `mapstructure:"scroll_mouse_wheel_probability" yaml:"scroll_mouse_wheel_probability"`
	ScrollDetentWheelProbability float64 `mapstructure:"scroll_detent_wheel_probability" yaml:"scroll_detent_wheel_probability"`

	// --- Session Persona Randomization ---
	PersonaJitterMovement float64 `mapstructure:"persona_jitter_movement" yaml:"persona_jitter_movement"`
	PersonaJitterDamping  float64 `mapstructure:"persona_jitter_damping" yaml:"persona_jitter_damping"`
	PersonaJitterSkill    float64 `mapstructure:"persona_jitter_skill" yaml:"persona_jitter_skill"`
}

// Agent implements Interface.
func (h HumanoidConfig) Agent() AgentConfig {
	panic("unimplemented")
}

// Autofix implements Interface.
func (h HumanoidConfig) Autofix() AutofixConfig {
	panic("unimplemented")
}

// Browser implements Interface.
func (h HumanoidConfig) Browser() BrowserConfig {
	panic("unimplemented")
}

// Database implements Interface.
func (h HumanoidConfig) Database() DatabaseConfig {
	panic("unimplemented")
}

// Discovery implements Interface.
func (h HumanoidConfig) Discovery() DiscoveryConfig {
	panic("unimplemented")
}

// Engine implements Interface.
func (h HumanoidConfig) Engine() EngineConfig {
	panic("unimplemented")
}

// IAST implements Interface.
func (h HumanoidConfig) IAST() IASTConfig {
	panic("unimplemented")
}

// JWT implements Interface.
func (h HumanoidConfig) JWT() JWTConfig {
	panic("unimplemented")
}

// Logger implements Interface.
func (h HumanoidConfig) Logger() LoggerConfig {
	panic("unimplemented")
}

// Network implements Interface.
func (h HumanoidConfig) Network() NetworkConfig {
	panic("unimplemented")
}

// Scan implements Interface.
func (h HumanoidConfig) Scan() ScanConfig {
	panic("unimplemented")
}

// Scanners implements Interface.
func (h HumanoidConfig) Scanners() ScannersConfig {
	panic("unimplemented")
}

// SetATOConfig implements Interface.
func (h HumanoidConfig) SetATOConfig(atoCfg ATOConfig) {
	panic("unimplemented")
}

// SetBrowserDebug implements Interface.
func (h HumanoidConfig) SetBrowserDebug(bool) {
	panic("unimplemented")
}

// SetBrowserDisableCache implements Interface.
func (h HumanoidConfig) SetBrowserDisableCache(bool) {
	panic("unimplemented")
}

// SetBrowserHeadless implements Interface.
func (h HumanoidConfig) SetBrowserHeadless(bool) {
	panic("unimplemented")
}

// SetBrowserHumanoidClickHoldMaxMs implements Interface.
func (h HumanoidConfig) SetBrowserHumanoidClickHoldMaxMs(ms int) {
	panic("unimplemented")
}

// SetBrowserHumanoidClickHoldMinMs implements Interface.
func (h HumanoidConfig) SetBrowserHumanoidClickHoldMinMs(ms int) {
	panic("unimplemented")
}

// SetBrowserHumanoidEnabled implements Interface.
func (h HumanoidConfig) SetBrowserHumanoidEnabled(bool) {
	panic("unimplemented")
}

// SetBrowserHumanoidKeyHoldMu implements Interface.
func (h HumanoidConfig) SetBrowserHumanoidKeyHoldMu(ms float64) {
	panic("unimplemented")
}

// SetBrowserIgnoreTLSErrors implements Interface.
func (h HumanoidConfig) SetBrowserIgnoreTLSErrors(bool) {
	panic("unimplemented")
}

// SetDiscoveryIncludeSubdomains implements Interface.
func (h HumanoidConfig) SetDiscoveryIncludeSubdomains(bool) {
	panic("unimplemented")
}

// SetDiscoveryMaxDepth implements Interface.
func (h HumanoidConfig) SetDiscoveryMaxDepth(int) {
	panic("unimplemented")
}

// SetEngineWorkerConcurrency implements Interface.
func (h HumanoidConfig) SetEngineWorkerConcurrency(int) {
	panic("unimplemented")
}

// SetIASTEnabled implements Interface.
func (h HumanoidConfig) SetIASTEnabled(bool) {
	panic("unimplemented")
}

// SetJWTBruteForceEnabled implements Interface.
func (h HumanoidConfig) SetJWTBruteForceEnabled(bool) {
	panic("unimplemented")
}

// SetJWTEnabled implements Interface.
func (h HumanoidConfig) SetJWTEnabled(bool) {
	panic("unimplemented")
}

// SetNetworkCaptureResponseBodies implements Interface.
func (h HumanoidConfig) SetNetworkCaptureResponseBodies(bool) {
	panic("unimplemented")
}

// SetNetworkIgnoreTLSErrors implements Interface.
func (h HumanoidConfig) SetNetworkIgnoreTLSErrors(bool) {
	panic("unimplemented")
}

// SetNetworkNavigationTimeout implements Interface.
func (h HumanoidConfig) SetNetworkNavigationTimeout(d time.Duration) {
	panic("unimplemented")
}

// SetNetworkPostLoadWait implements Interface.
func (h HumanoidConfig) SetNetworkPostLoadWait(d time.Duration) {
	panic("unimplemented")
}

// SetScanConfig implements Interface.
func (h HumanoidConfig) SetScanConfig(sc ScanConfig) {
	panic("unimplemented")
}

// setHumanoidDefaults sets the default values for all humanoid-related configuration.
func setHumanoidDefaults(v *viper.Viper) {
	v.SetDefault("browser.humanoid.enabled", true)
	v.SetDefault("browser.humanoid.providers", []string{"fingerprint", "header"})

	// -- General Physics & Limits --
	v.SetDefault("browser.humanoid.max_velocity", 6000.0)
	v.SetDefault("browser.humanoid.time_step", 5*time.Millisecond)
	v.SetDefault("browser.humanoid.max_sim_time", 10*time.Second)

	// -- Movement Physics (Spring-Damped Model) --
	v.SetDefault("browser.humanoid.omega", 25.0)
	v.SetDefault("browser.humanoid.zeta", 0.75)

	// -- Fitts's Law --
	v.SetDefault("browser.humanoid.fitts_a", 120.0)
	v.SetDefault("browser.humanoid.fitts_b", 160.0)
	v.SetDefault("browser.humanoid.fitts_w_terminal", 20.0)
	v.SetDefault("browser.humanoid.fitts_jitter_percent", 0.15) // +/- 15%

	// -- Ex-Gaussian Timing Model --
	v.SetDefault("browser.humanoid.ex_gaussian_mu", 250.0)   // Base reaction time component
	v.SetDefault("browser.humanoid.ex_gaussian_sigma", 50.0) // Variability in reaction time
	v.SetDefault("browser.humanoid.ex_gaussian_tau", 100.0)  // Cognitive processing / long tail
	v.SetDefault("browser.humanoid.task_switch_mu", 150.0)
	v.SetDefault("browser.humanoid.task_switch_sigma", 40.0)
	v.SetDefault("browser.humanoid.task_switch_tau", 80.0)

	// -- Noise and Perturbations --
	v.SetDefault("browser.humanoid.pink_noise_amplitude", 2.0)
	v.SetDefault("browser.humanoid.gaussian_strength", 0.6)
	v.SetDefault("browser.humanoid.click_noise", 1.2)
	v.SetDefault("browser.humanoid.hesitation_drift_factor", 1.5)
	v.SetDefault("browser.humanoid.sdn_factor", 0.0015)

	// -- Anti-Periodicity --
	v.SetDefault("browser.humanoid.anti_periodicity_min_pause", 200*time.Millisecond)
	v.SetDefault("browser.humanoid.anti_periodicity_time_jitter", 2*time.Millisecond)
	v.SetDefault("browser.humanoid.anti_periodicity_frame_drop_prob", 0.05) // 5% chance

	// -- Trajectory Behavior & Micro-corrections --
	v.SetDefault("browser.humanoid.micro_correction_threshold", 100.0)
	v.SetDefault("browser.humanoid.target_inner_aim_percent", 0.80)
	v.SetDefault("browser.humanoid.target_velocity_bias_max", 0.10)     // 10% max bias
	v.SetDefault("browser.humanoid.target_velocity_bias_thresh", 500.0) // Pixels/sec
	v.SetDefault("browser.humanoid.min_move_distance", 1.5)
	v.SetDefault("browser.humanoid.terminal_dist_threshold", 1.0)
	v.SetDefault("browser.humanoid.terminal_velocity_threshold", 50.0)
	v.SetDefault("browser.humanoid.anticipatory_movement_threshold", 200.0)
	v.SetDefault("browser.humanoid.anticipatory_movement_distance", 15.0)
	v.SetDefault("browser.humanoid.anticipatory_movement_duration", 150*time.Millisecond)
	v.SetDefault("browser.humanoid.anticipatory_movement_omega_factor", 0.2)
	v.SetDefault("browser.humanoid.anticipatory_movement_zeta_factor", 1.5)

	// -- Fatigue & Habituation Modeling --
	v.SetDefault("browser.humanoid.fatigue_increase_rate", 0.01) // Rate per action/second
	v.SetDefault("browser.humanoid.fatigue_recovery_rate", 0.02) // Rate per second of inactivity
	v.SetDefault("browser.humanoid.habituation_rate", 0.005)

	// -- Clicking Behavior --
	v.SetDefault("browser.humanoid.click_hold_min_ms", 50)
	v.SetDefault("browser.humanoid.click_hold_max_ms", 150)

	// -- Inter-Key Delay (IKD) Modeling --
	v.SetDefault("browser.humanoid.key_hold_mu", 65.0)
	v.SetDefault("browser.humanoid.key_hold_sigma", 20.0)
	v.SetDefault("browser.humanoid.key_hold_tau", 15.0)
	v.SetDefault("browser.humanoid.ikd_mu", 110.0)
	v.SetDefault("browser.humanoid.ikd_sigma", 45.0)
	v.SetDefault("browser.humanoid.ikd_tau", 30.0)
	v.SetDefault("browser.humanoid.key_pause_min", 40.0)
	v.SetDefault("browser.humanoid.key_pause_ngram_factor_2", 0.85)
	v.SetDefault("browser.humanoid.key_pause_ngram_factor_3", 0.75)
	v.SetDefault("browser.humanoid.ikd_hand_alternation_bonus", 0.8)
	v.SetDefault("browser.humanoid.ikd_same_finger_penalty", 1.3)
	v.SetDefault("browser.humanoid.ikd_distance_factor", 0.05)
	v.SetDefault("browser.humanoid.key_pause_fatigue_factor", 0.4)
	v.SetDefault("browser.humanoid.key_burst_pause_probability", 0.03) // 3% chance between keys

	// -- Typo Simulation --
	v.SetDefault("browser.humanoid.typo_rate", 0.025)
	v.SetDefault("browser.humanoid.typo_homoglyph_rate", 0.15) // 15% of typos are homoglyphs
	v.SetDefault("browser.humanoid.typo_neighbor_rate", 0.4)   // 40% are neighbor keys
	v.SetDefault("browser.humanoid.typo_transpose_rate", 0.2)  // 20% are transpositions
	v.SetDefault("browser.humanoid.typo_omission_rate", 0.1)   // 10% are omissions
	// The remaining 15% of typos are insertions (the fallback).
	v.SetDefault("browser.humanoid.typo_correction_probability", 0.85)
	v.SetDefault("browser.humanoid.typo_shift_correction_probability", 0.95)
	v.SetDefault("browser.humanoid.typo_omission_notice_probability", 0.7)
	v.SetDefault("browser.humanoid.typo_insertion_notice_probability", 0.8)
	v.SetDefault("browser.humanoid.typo_correction_pause_mean_scale", 2.5)
	v.SetDefault("browser.humanoid.typo_correction_pause_std_dev_scale", 1.5)

	// -- Scrolling Behavior --
	v.SetDefault("browser.humanoid.scroll_read_density_factor", 0.7)
	v.SetDefault("browser.humanoid.scroll_overshoot_probability", 0.25)
	v.SetDefault("browser.humanoid.scroll_regression_probability", 0.1)
	v.SetDefault("browser.humanoid.scroll_mouse_wheel_probability", 0.6)
	v.SetDefault("browser.humanoid.scroll_detent_wheel_probability", 0.7) // 70% of wheel mice are detent

	// -- Session Persona Randomization --
	v.SetDefault("browser.humanoid.persona_jitter_movement", 0.15) // +/- 15%
	v.SetDefault("browser.humanoid.persona_jitter_damping", 0.10)  // +/- 10%
	v.SetDefault("browser.humanoid.persona_jitter_skill", 0.2)     // std dev from mean of 1.0
}
