// File: internal/browser/humanoid/trajectory.go
package humanoid

import (
	"context"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// simulateTrajectory simulates mouse movement using a spring-damped system influenced by potential fields,
// incorporating advanced models like Signal-Dependent Noise and adaptive micro-corrections.
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
	microCorrectionThresh := baseCfg.MicroCorrectionThreshold
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

	// Variables for Adaptive Deviation-Based Micro-Correction Model.
	currentTarget := end
	initialDist := start.Dist(end)
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
		distanceToTarget := currentPos.Dist(currentTarget)
		currentVelocityMag := velocity.Mag()

		// Stop if we are very close to the current target AND moving slowly.
		if distanceToTarget < terminalDistThresh && currentVelocityMag < terminalVelThresh {
			// If we reached the final destination, we are done.
			if currentTarget == end {
				break
			}
			// If we reached a submovement target, switch focus to the final target.
			currentTarget = end
			continue // Re-evaluate forces immediately for the new target.
		}

		// 3. Adaptive Deviation-Based Micro-Corrections.
		// Only consider corrections if the initial distance was significant.
		if initialDist > microCorrectionThresh {
			// Calculate deviation from the ideal trajectory.
			currentProgress := currentPos.Sub(start)
			// Project current progress onto the ideal trajectory.
			projectedProgress := idealTrajectoryNorm.Mul(currentProgress.Dot(idealTrajectoryNorm))
			// Deviation vector is the orthogonal distance from the current position to the ideal line.
			deviation := currentProgress.Sub(projectedProgress)
			deviationMag := deviation.Mag()

			// If deviation exceeds a threshold (e.g., 5% of initial distance), initiate a correction.
			if deviationMag > initialDist*0.05 {
				// Define a new sub-target. The correction aims to bring the cursor back towards the ideal trajectory.
				// The new target is slightly ahead of the current projected position on the ideal line.
				lookAheadFactor := 0.3 + rng.Float64()*0.4 // Look ahead 30-70% of the remaining distance.
				remainingDist := initialDist - projectedProgress.Mag()
				if remainingDist > 0 {
					correctionTarget := start.Add(projectedProgress).Add(idealTrajectoryNorm.Mul(remainingDist * lookAheadFactor))

					// Only update if the new target is significantly different from the current one.
					if currentTarget.Dist(correctionTarget) > 5.0 {
						currentTarget = correctionTarget
						h.logger.Debug("Humanoid: Initiating deviation-based micro-correction",
							zap.Float64("deviation_mag", deviationMag),
							zap.Float64("remaining_dist", remainingDist))
					}
				}
			}
		}

		// 4. Calculate Forces (F = ma).
		// Spring force towards the current target.
		displacement := currentTarget.Sub(currentPos)
		springForce := displacement.Mul(omega * omega)

		// Damping force opposing velocity.
		dampingForce := velocity.Mul(-2.0 * zeta * omega)

		// External forces from the potential field.
		externalForce := field.CalculateNetForce(currentPos)

		// Net acceleration (a = F/m).
		acceleration := springForce.Add(dampingForce).Add(externalForce)

		// 5. Update Velocity and Position (Semi-implicit Euler integration).
		velocity = velocity.Add(acceleration.Mul(dt))

		// 6. Apply Signal-Dependent Noise (SDN).
		// Noise that scales with the magnitude of the motor command (velocity).
		if sdnFactor > 0 {
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
