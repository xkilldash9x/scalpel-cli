// File: internal/browser/humanoid/trajectory.go
// This file contains the core logic for simulating realistic mouse movement trajectories.
// The simulation is based on a critically-damped mass-spring-damper model, which
// produces the characteristic smooth, curved paths of human motion.
//
// To ensure stable and consistent performance across different movement speeds and
// distances, the system uses a control theory concept called Gain Scheduling. This
// technique dynamically adjusts the parameters (gains) of a PID (Proportional-Integral-Derivative)
// controller that corrects the cursor's path, making the movement robust and preventing
// oscillations or sluggishness.
//
// The trajectory is further enhanced by several layers of noise modeling:
// - Pink Noise (1/f noise): Simulates low-frequency, long-term drift, like a user slowly wavering.
// - Gaussian Noise: Simulates high-frequency, random tremor.
// - Signal-Dependent Noise: Models the phenomenon where motor control becomes less precise
//   at higher speeds, introducing noise proportional to the cursor's velocity.
//
// The combination of these physics-based models and realistic noise sources allows the
// humanoid to generate trajectories that are difficult to distinguish from those of a real user.
package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// R6: Reference parameters.
// The previous implementation used flawed scaling logic (RefKp, RefKi, RefKd, RefOmega)
// where gains were incorrectly proportional to the plant's stiffness.
// This has been replaced by a physics-based Gain Scheduling approach derived from control theory.
const (
	// RefTimeStep is kept for historical context but is not used for PID scaling,
	// as gain scheduling uses continuous-time gains. The simulation loop uses the dynamic TimeStep from configuration.
	RefTimeStep = 0.005 // 5ms
)

// --- Gain Scheduling Constants (Derived from Analysis Report) ---
//
// This system implements Gain Scheduling to maintain consistent closed-loop (CL)
// performance despite variations in the plant's (P) dynamics (omega_p, zeta_p).
// The approach calculates PID *acceleration* gains (Kp/m, Ki/m, Kd/m), making
// the controller mass-independent.
//
// The formulas are derived by matching the closed-loop characteristic equation
// to the desired standard second-order form:
// Kp_a = Kp/m = omega_cl^2 - omega_p^2
// Kd_a = Kd/m = (2 * zeta_cl * omega_cl) - (2 * zeta_p * omega_p)
// Ki_a = Kp_a * KI_KP_RATIO
//
// These constants define the *desired* closed-loop performance. They are tuned
// based on system requirements (e.g., robust disturbance rejection < 15.0) and stability analysis.
const (
	// TARGET_OMEGA_CL_SQUARED (omega_cl^2): Defines the desired closed-loop stiffness.
	// This is the primary tuning knob for the controller's aggressiveness.
	// Tuned value: 2200.0. This ensures sufficient gain to meet the <15.0 deviation requirement.
	TARGET_OMEGA_CL_SQUARED = 2200.0

	// TARGET_OMEGA_CL (omega_cl): The desired closed-loop natural frequency (rad/s).
	// sqrt(2200.0) = 46.9041...
	TARGET_OMEGA_CL = 46.9041575982343

	// TARGET_DAMPING_TERM (2 * zeta_cl * omega_cl): Defines the desired closed-loop damping.
	// Tuned value: 100.0 (Increased from 98.0). Increased damping ensures consistency across the active range (addressing the variance failure > 5.0).
	TARGET_DAMPING_TERM = 100.0

	// TARGET_ZETA_CL (zeta_cl): The resulting desired closed-loop damping ratio (dimensionless).
	// Derived: 100.0 / (2 * 46.9041...) = 1.0659...
	// This ensures a stable, overdamped response, maximizing consistency.
	TARGET_ZETA_CL = 1.0659003262322052

	// KI_KP_RATIO: Ratio of Integral gain to Proportional gain.
	// Maintained at a standard stable ratio (0.1) to ensure steady-state error elimination without excessive oscillation.
	KI_KP_RATIO = 0.1
)

// calculateScheduledAccelerationGains computes the PID acceleration gains
// (Kp_a, Ki_a, Kd_a) required to achieve the desired closed-loop performance,
// given the plant's current dynamics (omega_p, zeta_p).
//
// This function implements the core Gain Scheduling logic. It ensures controller gains
// are inversely related to the plant's stiffness, providing strong control when the plant
// is compliant and reducing it when the plant is inherently stiff.
func calculateScheduledAccelerationGains(current_omega_p, current_zeta_p float64) (kp_a, ki_a, kd_a float64) {

	// Input validation: Physical dynamics (ω_p and ζ_p) must be non-negative.
	// Negative frequencies are non-physical, and negative damping implies an unstable plant.
	// Handle NaN inputs defensively.
	omega_p := current_omega_p
	if omega_p < 0.0 || math.IsNaN(omega_p) {
		omega_p = 0.0
	}
	zeta_p := current_zeta_p
	if zeta_p < 0.0 || math.IsNaN(zeta_p) {
		zeta_p = 0.0
	}

	// 1. Calculate the plant's inherent acceleration damping (c_p/m).
	// c_p/m = 2 * ζ_p * ω_p
	c_a_plant := 2.0 * zeta_p * omega_p

	// 2. Calculate Proportional acceleration gain (Kp_a).
	// Kp_a = ω_cl^2 - ω_p^2
	// This ensures the combined stiffness (plant + controller) meets the target ω_cl^2.
	kp_a = TARGET_OMEGA_CL_SQUARED - (omega_p * omega_p)

	// 3. Calculate Derivative acceleration gain (Kd_a).
	// Kd_a = (2ζ_clω_cl) - (c_p/m)
	// This ensures the combined damping meets the target damping term.
	kd_a = TARGET_DAMPING_TERM - c_a_plant

	// 4. Safety Clamps: Prevent negative gains.
	// Negative gains result in positive feedback and catastrophic instability.
	// This occurs if the plant's dynamics already exceed the desired targets (e.g., ω_p > ω_cl).
	if kp_a < 0.0 {
		kp_a = 0.0
	}
	if kd_a < 0.0 {
		kd_a = 0.0
	}

	// 5. Calculate Integral acceleration gain (Ki_a).
	// Ki_a is scaled proportionally to Kp_a. Must be done after clamping Kp_a.
	ki_a = kp_a * KI_KP_RATIO

	return kp_a, ki_a, kd_a
}

// simulateTrajectory simulates mouse movement using a second-order mass-spring-damper (MSD) system
// influenced by external potential fields and stabilized by a Gain-Scheduled PID controller.
// It also incorporates human noise models (SDN, pink noise).
// It assumes the caller holds the lock on the Humanoid instance.
func (h *Humanoid) simulateTrajectory(ctx context.Context, start, end Vector2D, field *PotentialField, buttonState schemas.MouseButton) (Vector2D, error) {
	// Initialize simulation state.
	currentPos := start
	velocity := Vector2D{X: 0, Y: 0} // Start with zero velocity.
	t := time.Duration(0)

	// Capture the plant's current dynamics (omega_p, zeta_p).
	// These may vary due to factors like fatigue modeled in dynamicConfig.
	omega_p := h.dynamicConfig.Omega
	zeta_p := h.dynamicConfig.Zeta
	sdnFactor := h.dynamicConfig.SDNFactor
	pinkNoiseMagnitude := h.dynamicConfig.PinkNoiseAmplitude
	microCorrectionThresh := h.dynamicConfig.MicroCorrectionThreshold

	// Capture base configuration for timing, limits, and anti-periodicity.
	baseCfg := h.baseConfig
	timeStepBase := baseCfg.TimeStep
	maxSimTime := baseCfg.MaxSimTime
	maxVelocity := baseCfg.MaxVelocity
	terminalDistThresh := baseCfg.TerminalDistThreshold
	terminalVelThresh := baseCfg.TerminalVelocityThreshold
	stochasticJitter := baseCfg.AntiPeriodicityTimeJitter
	frameDropProb := baseCfg.AntiPeriodicityFrameDropProb

	if field == nil {
		field = NewPotentialField()
	}

	buttonsBitfield := h.calculateButtonsBitfield(buttonState)
	rng := h.rng

	// --- Trajectory Setup ---
	initialDist := start.Dist(end)

	// Handle zero distance movement gracefully, including potential NaN inputs.
	if initialDist == 0 || math.IsNaN(initialDist) {
		return velocity, nil
	}

	// Ideal trajectory vector (straight line from start to end).
	idealTrajectory := end.Sub(start)
	idealTrajectoryNorm := idealTrajectory.Normalize()
	// Robustness check for normalization failure (should be prevented by initialDist check, but defensive coding).
	if math.IsNaN(idealTrajectoryNorm.X) || math.IsNaN(idealTrajectoryNorm.Y) {
		h.logger.Error("Humanoid: Ideal trajectory normalization failed despite non-zero distance.", zap.Any("start", start), zap.Any("end", end), zap.Float64("initialDist", initialDist))
		return velocity, nil // Cannot proceed if the path direction is unknown.
	}

	// --- PID Controller Setup: Gain Scheduling ---
	// R6: Implement the Gain Scheduling strategy.
	// Calculate the PID acceleration gains based on the current plant dynamics.
	Kp_a, Ki_a, Kd_a := calculateScheduledAccelerationGains(omega_p, zeta_p)

	h.logger.Debug("Gain Scheduling: Calculated PID acceleration gains.",
		zap.Float64("omega_p", omega_p),
		zap.Float64("zeta_p", zeta_p),
		zap.Float64("Kp_a", Kp_a),
		zap.Float64("Ki_a", Ki_a),
		zap.Float64("Kd_a", Kd_a),
	)

	// PID State Variables initialization.
	var integralError Vector2D
	var previousError Vector2D

	// --- Simulation Loop ---
	// Integrates the equations of motion over time using Semi-implicit Euler method.
	for t < maxSimTime {
		// 1. Check for context cancellation.
		if ctx.Err() != nil {
			return velocity, ctx.Err()
		}

		// 2. Anti-Periodicity: Stochastic Time Step (dt).
		// Introduces realistic variability in timing.
		jitter := (rng.Float64()*2.0 - 1.0) * stochasticJitter.Seconds()
		dt := timeStepBase.Seconds() + jitter
		if dt <= 0.001 {
			dt = 0.001 // Enforce a minimum positive time step for numerical stability (prevents division by zero).
		}

		// 3. Check termination condition (proximity and low velocity).
		distanceToTarget := currentPos.Dist(end)
		currentVelocityMag := velocity.Mag()
		if distanceToTarget < terminalDistThresh && currentVelocityMag < terminalVelThresh {
			break
		}

		// 4. PID-Based Micro-Correction Acceleration (a_pid).
		var correctionAcceleration Vector2D // a_pid

		// Calculate the current progress along the ideal trajectory.
		currentProgress := currentPos.Sub(start)
		projectedMag := currentProgress.Dot(idealTrajectoryNorm)

		// Determine the remaining distance (clamped to handle potential overshoot or starting behind the line).
		// Use math.Max/Min for idiomatic clamping.
		clampedProjectedMag := math.Max(0, math.Min(projectedMag, initialDist))
		remainingDist := initialDist - clampedProjectedMag

		// Reset PID state if very close to the target to prevent windup or chatter (smooth landing).
		if remainingDist < terminalDistThresh {
			integralError = Vector2D{}
			previousError = Vector2D{}
		} else if microCorrectionThresh > 0 {
			// Calculate the error vector (perpendicular deviation from the ideal path).
			projectedProgress := idealTrajectoryNorm.Mul(projectedMag)
			errorVector := currentProgress.Sub(projectedProgress)

			// Apply correction only if the error exceeds the threshold.
			if errorVector.Mag() > microCorrectionThresh {
				// P-Term (Proportional): Acceleration directly opposing the current error.
				P_out := errorVector.Mul(-Kp_a)

				// I-Term (Integral): Accumulates error over time (discrete-time integration) to eliminate steady-state error.
				integralError = integralError.Add(errorVector.Mul(dt))
				I_out := integralError.Mul(-Ki_a)

				// D-Term (Derivative): Opposes the rate of change of error (adds damping).
				derivativeError := errorVector.Sub(previousError).Mul(1.0 / dt)
				D_out := derivativeError.Mul(-Kd_a)

				// Total PID Acceleration (a_pid).
				correctionAcceleration = P_out.Add(I_out).Add(D_out)

				previousError = errorVector
			} else {
				// Reset integral error if within the threshold to prevent drift.
				integralError = Vector2D{}
				previousError = errorVector
			}
		}

		// 5. Calculate Net Acceleration (a_total = a_spring + a_damping + a_external + a_pid).
		// All terms are accelerations (Force/mass).

		// Spring acceleration (a_spring = (k/m)x = omega_p^2 * displacement). Drives towards the target.
		displacement := end.Sub(currentPos)
		springAcceleration := displacement.Mul(omega_p * omega_p)

		// Damping acceleration (a_damping = (c/m)v = 2 * zeta_p * omega_p * velocity).
		// Opposes velocity.
		dampingAcceleration := velocity.Mul(-2.0 * zeta_p * omega_p)

		// External acceleration (a_external = F_ext / m). From potential fields (disturbances).
		// Assumes field.CalculateNetForce returns acceleration.
		externalAcceleration := field.CalculateNetForce(currentPos)

		// Net acceleration.
		acceleration := springAcceleration.Add(dampingAcceleration).Add(externalAcceleration).Add(correctionAcceleration)

		// 6. Update Velocity (Semi-implicit Euler integration).
		velocity = velocity.Add(acceleration.Mul(dt))

		// 7. Apply Signal-Dependent Noise (SDN).
		// Noise magnitude increases with velocity, modeling motor control inaccuracies.
		currentVelocityMag = velocity.Mag()
		if sdnFactor > 0 && currentVelocityMag > 0 {
			noiseMag := currentVelocityMag * sdnFactor
			// Noise is applied orthogonally to the direction of movement.
			orthogonalDir := Vector2D{X: -velocity.Y, Y: velocity.X}.Normalize()
			// Check for NaN in case velocity was somehow a zero vector (defensive check).
			if !math.IsNaN(orthogonalDir.X) && !math.IsNaN(orthogonalDir.Y) {
				sdnNoise := orthogonalDir.Mul(rng.NormFloat64() * noiseMag)
				velocity = velocity.Add(sdnNoise)
			}
		}

		// Clamp velocity to realistic physical maximums.
		if velocity.Mag() > maxVelocity {
			velocity = velocity.Normalize().Mul(maxVelocity)
		}

		// 8. Update Position (Semi-implicit Euler integration).
		currentPos = currentPos.Add(velocity.Mul(dt))

		// 9. Apply Low-Frequency Drift (Pink Noise) and High-Frequency Tremor (Gaussian Noise).
		// Models physiological noise sources.
		pinkNoiseDrift := Vector2D{
			X: h.noiseX.Next() * pinkNoiseMagnitude,
			Y: h.noiseY.Next() * pinkNoiseMagnitude,
		}
		driftAppliedPos := currentPos.Add(pinkNoiseDrift)
		finalPerturbedPoint := h.applyGaussianNoise(driftAppliedPos)

		// 10. Dispatch Event (with Anti-Periodicity Frame Dropping).
		// Simulates variability in the operating system's event handling rate.
		if rng.Float64() > frameDropProb {
			eventData := schemas.MouseEventData{
				Type:    schemas.MouseMove,
				X:       finalPerturbedPoint.X,
				Y:       finalPerturbedPoint.Y,
				Button:  schemas.ButtonNone, // Button field indicates the button that *changed* state (e.g., click), not held buttons.
				Buttons: buttonsBitfield,    // Buttons bitfield indicates which buttons are currently held down (for dragging).
			}
			if err := h.executor.DispatchMouseEvent(ctx, eventData); err != nil {
				// Log the error unless it was caused by context cancellation.
				if ctx.Err() == nil {
					h.logger.Warn("Humanoid: Failed to dispatch mouse event", zap.Error(err))
				}
				return velocity, err
			}
		}

		// 11. Update State and Timing.
		h.currentPos = finalPerturbedPoint
		t += time.Duration(dt * float64(time.Second))

		// 12. Sleep for the duration of the time step to maintain real-time simulation speed.
		sleepDuration := time.Duration(dt * float64(time.Second))
		if sleepDuration > 0 {
			if err := h.executor.Sleep(ctx, sleepDuration); err != nil {
				return velocity, err
			}
		}
	}

	// Log if the simulation timed out (this is not an error state, but indicates incomplete movement).
	if t >= maxSimTime {
		h.logger.Warn("Humanoid: Movement simulation timed out",
			zap.Duration("maxSimTime", maxSimTime),
			zap.Any("start", start),
			zap.Any("end", end),
			zap.Float64("distance_remaining", currentPos.Dist(end)))
	}

	// Return the final velocity achieved at the end of the movement.
	return velocity, nil
}
