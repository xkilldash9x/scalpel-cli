// File: internal/browser/humanoid/trajectory.go
package humanoid

import (
	"context"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// simulateTrajectory simulates mouse movement using a spring-damped system influenced by potential fields,
// incorporating advanced models like Signal-Dependent Noise and PID-controlled micro-corrections.
// It assumes the caller holds the lock.
func (h *Humanoid) simulateTrajectory(ctx context.Context, start, end Vector2D, field *PotentialField, buttonState schemas.MouseButton) (Vector2D, error) {
	// Initialize simulation state.
	currentPos := start
	velocity := Vector2D{X: 0, Y: 0} // Start with zero velocity.
	t := time.Duration(0)

	// Use dynamic configuration parameters (affected by fatigue/habituation).
	omega := h.dynamicConfig.Omega         // Natural frequency (speed)
	zeta := h.dynamicConfig.Zeta           // Damping ratio (smoothness/oscillation)
	sdnFactor := h.dynamicConfig.SDNFactor // Signal-Dependent Noise factor

	// Use base configuration for timing, limits, thresholds, and anti-periodicity.
	baseCfg := h.baseConfig
	timeStepBase := baseCfg.TimeStep
	maxSimTime := baseCfg.MaxSimTime
	maxVelocity := baseCfg.MaxVelocity
	terminalDistThresh := baseCfg.TerminalDistThreshold
	terminalVelThresh := baseCfg.TerminalVelocityThreshold
	microCorrectionThresh := h.dynamicConfig.MicroCorrectionThreshold // FIX: Read from dynamic config
	stochasticJitter := baseCfg.AntiPeriodicityTimeJitter
	frameDropProb := baseCfg.AntiPeriodicityFrameDropProb
	if field == nil {
		field = NewPotentialField()
	}

	buttonsBitfield := h.calculateButtonsBitfield(buttonState)
	rng := h.rng
	// Noise parameters also use dynamic config (affected by fatigue).
	// Updated to use PinkNoiseAmplitude.
	pinkNoiseMagnitude := h.dynamicConfig.PinkNoiseAmplitude

	// --- PID Controller Setup for Micro-Corrections ---
	// This implementation replaces the previous unstable sub-targeting mechanism
	// with a PID controller, as recommended by the diagnostic report (Section V.A).

	// PID Gains. Tuned for stabilization and aggressive correction.
	// FIX: The previous gains (Kp=600, Ki=50) improved the response but still allowed
	// excessive steady-state error, failing the test requirement.
	// We significantly increase Kp and Ki to ensure rapid correction of disturbances.
	// Kd_crit = 2 * sqrt(Kp). With Kp=1200, Kd_crit ≈ 69.28.
	const Kp = 1200.0 // Proportional Gain: Very strong reaction. (Was 600.0)
	const Ki = 200.0  // Integral Gain: Aggressively eliminates steady-state error. (Was 50.0)
	const Kd = 70.0   // Derivative Gain: Increased to maintain stability. (Was 50.0)

	// PID State Variables.
	var integralError Vector2D
	var previousError Vector2D

	// The MSD system now always drives towards 'end'.
	initialDist := start.Dist(end)

	// Handle zero distance movement gracefully.
	if initialDist == 0 {
		return velocity, nil
	}

	// Ideal trajectory vector (straight line from start to end).
	idealTrajectory := end.Sub(start)
	idealTrajectoryNorm := idealTrajectory.Normalize()

	// --- Simulation Loop ---
	for t < maxSimTime {
		if ctx.Err() != nil {
			return velocity, ctx.Err()
		}

		// 1. Anti-Periodicity: Stochastic Time Step (dt)
		// Jitter the time step for this iteration (e.g., +/- 2ms on a 5ms base).
		jitter := (rng.Float64()*2.0 - 1.0) * stochasticJitter.Seconds()
		dt := timeStepBase.Seconds() + jitter
		if dt <= 0.001 {
			dt = 0.001 // Ensure dt is positive and non-zero.
		}

		// 2. Check termination condition.
		distanceToTarget := currentPos.Dist(end)
		// Use velocity magnitude from the previous step for termination checks.
		currentVelocityMag := velocity.Mag()

		// Stop if we are very close to the current target AND moving slowly.
		if distanceToTarget < terminalDistThresh && currentVelocityMag < terminalVelThresh {
			break
		}

		// 3. PID-Based Micro-Correction Force Calculation.
		var correctionForce Vector2D // Initialize correction force to zero.

		// Calculate progress along the ideal trajectory.
		currentProgress := currentPos.Sub(start)
		projectedMag := currentProgress.Dot(idealTrajectoryNorm)

		// Calculate remaining distance. We clamp the projection magnitude for this calculation
		// to handle cases where the cursor hasn't yet passed the start point (projectedMag < 0).
		clampedProjectedMag := projectedMag
		if clampedProjectedMag < 0 {
			clampedProjectedMag = 0
		}
		remainingDist := initialDist - clampedProjectedMag

		// State-Dependent Triggering (Report Section V.B):
		// Disable corrections if the total movement is insignificant, or during the terminal phase
		// (close to target or overshot, where remainingDist < terminalDistThresh).
		// This prevents the controller from fighting the natural terminal oscillations of the MSD model.
		if initialDist < terminalDistThresh || remainingDist < terminalDistThresh {
			// In the terminal phase, reset PID state and apply no force.
			integralError = Vector2D{}
			previousError = Vector2D{}
		} else if microCorrectionThresh > 0 {
			// Calculate the error vector (deviation).
			// We must use the actual (unclamped) projectedMag here to calculate the true orthogonal
			// distance from the infinite ideal line.
			projectedProgress := idealTrajectoryNorm.Mul(projectedMag)
			// Error vector points from the ideal line towards the current position.
			errorVector := currentProgress.Sub(projectedProgress)

			// Dead Zone Implementation (Report Section V.B):
			// Only activate PID if the error exceeds the threshold.
			if errorVector.Mag() > microCorrectionThresh {

				// P-Term (Proportional): Force opposes the error.
				P_out := errorVector.Mul(-Kp)

				// I-Term (Integral): Accumulate error over time.
				integralError = integralError.Add(errorVector.Mul(dt))
				I_out := integralError.Mul(-Ki)

				// D-Term (Derivative): Rate of change of error (damping).
				derivativeError := errorVector.Sub(previousError).Mul(1.0 / dt)
				D_out := derivativeError.Mul(-Kd)

				// Total Correction Force.
				correctionForce = P_out.Add(I_out).Add(D_out)

				// Update state for next iteration.
				previousError = errorVector

			} else {
				// If within the dead zone, reset the integral term to prevent windup,
				// but continue tracking the error for the derivative term.
				integralError = Vector2D{}
				previousError = errorVector
			}
		}

		// 4. Calculate Forces (F = ma).
		// Spring force towards the final target (end).
		displacement := end.Sub(currentPos)
		springForce := displacement.Mul(omega * omega)

		// Damping force opposing velocity.
		dampingForce := velocity.Mul(-2.0 * zeta * omega)

		// External forces from the potential field.
		externalForce := field.CalculateNetForce(currentPos)

		// Net acceleration (a = F/m). Includes the PID correction force.
		acceleration := springForce.Add(dampingForce).Add(externalForce).Add(correctionForce)

		// 5. Update Velocity and Position (Semi-implicit Euler integration).
		velocity = velocity.Add(acceleration.Mul(dt))

		// 6. Apply Signal-Dependent Noise (SDN).
		// Noise that scales with the magnitude of the motor command (velocity).
		currentVelocityMag = velocity.Mag()
		if sdnFactor > 0 && currentVelocityMag > 0 {
			noiseMag := currentVelocityMag * sdnFactor
			// Apply noise orthogonal to the direction of movement (trajectory spreading).
			// Rotate velocity vector by 90 degrees.
			orthogonalDir := Vector2D{X: -velocity.Y, Y: velocity.X}.Normalize()
			sdnNoise := orthogonalDir.Mul(rng.NormFloat64() * noiseMag)
			velocity = velocity.Add(sdnNoise)
		}

		// Clamp velocity to realistic maximums.
		if velocity.Mag() > maxVelocity {
			velocity = velocity.Normalize().Mul(maxVelocity)
		}

		currentPos = currentPos.Add(velocity.Mul(dt))

		// 7. Apply Low-Frequency Drift and High-Frequency Tremor.
		// Apply Pink noise (1/f drift/waver). Pink noise generators are stateful.
		pinkNoiseDrift := Vector2D{
			X: h.noiseX.Next() * pinkNoiseMagnitude,
			Y: h.noiseY.Next() * pinkNoiseMagnitude,
		}
		driftAppliedPos := currentPos.Add(pinkNoiseDrift)

		// Apply Gaussian noise (high-frequency tremor).
		finalPerturbedPoint := h.applyGaussianNoise(driftAppliedPos)

		// 8. Dispatch Event (with Anti-Periodicity Frame Dropping)
		// Skip dispatching the event occasionally to break rhythmic patterns.
		if rng.Float64() > frameDropProb {
			eventData := schemas.MouseEventData{
				Type:    schemas.MouseMove,
				X:       finalPerturbedPoint.X,
				Y:       finalPerturbedPoint.Y,
				Button:  schemas.ButtonNone,
				Buttons: buttonsBitfield,
			}

			if err := h.executor.DispatchMouseEvent(ctx, eventData); err != nil {
				if ctx.Err() == nil {
					h.logger.Warn("Humanoid: Failed to dispatch mouse move event", zap.Error(err))
				}
				return velocity, err
			}
		}

		// 9. Update State and Timing.
		// Always update internal position even if frame was dropped.
		h.currentPos = finalPerturbedPoint
		// t is updated by the actual dt used in the simulation step.
		t += time.Duration(dt * float64(time.Second))

		// Sleep for the duration of the stochastic time step (dt) to maintain real-time simulation speed.
		sleepDuration := time.Duration(dt * float64(time.Second))
		if sleepDuration > 0 {
			if err := h.executor.Sleep(ctx, sleepDuration); err != nil {
				return velocity, err
			}
		}
	}

	if t >= maxSimTime {
		h.logger.Warn("Humanoid: Movement simulation timed out", zap.Any("start", start), zap.Any("end", end), zap.Float64("distance_remaining", currentPos.Dist(end)))
	}

	// Return the final velocity achieved at the end of the movement.
	return velocity, nil
}
