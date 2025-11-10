// File: internal/config/humanoid_config.go
// This file defines the HumanoidConfig struct, which contains all the tunable
// parameters for the humanoid interaction simulation library. These settings
// control the underlying models that generate realistic user behavior, including
// mouse movement physics, cognitive delays, typing patterns, and error simulation.
//
// The configuration is designed to be loaded from a file (e.g., YAML) using
// Viper, allowing for easy customization of the humanoid's "personality" and
// skill level without changing the core code.
package config

import (
	"time"
)

// HumanoidConfig holds all settings for the humanoid browser interaction library.
// These parameters control the various models that simulate human-like behavior,
// from the physics of mouse movement to the statistical patterns of typing errors.
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
