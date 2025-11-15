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
