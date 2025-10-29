// FILE: ./internal/browser/humanoid/keyboard.go
// ./internal/browser/humanoid/keyboard.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// -- keyboardNeighbors maps characters to their adjacent keys on a QWERTY layout --
var keyboardNeighbors = map[rune]string{
	'1': "2q`", '2': "13wq", '3': "24we", '4': "35er", '5': "46rt", '6': "57ty",
	'7': "68yu", '8': "79ui", '9': "80io", '0': "9-op",
	'q': "wa1s", 'w': "qase23", 'e': "wsdr34", 'r': "edft45", 't': "rfgy56",
	'y': "tghu67", 'u': "yhji78", 'i': "ujko89", 'o': "iklp90", 'p': "ol;0-",
	'a': "qwsz", 's': "awedxz", 'd': "serfcx", 'f': "drtgvc", 'g': "ftyhbv",
	'h': "gyujnb", 'j': "huikmn", 'k': "jiol,m", 'l': "kop;.",
	'z': "asx", 'x': "zsdc", 'c': "xdfv", 'v': "cfgb", 'b': "vghn", 'n': "bhjm", 'm': "njk,",
}

// -- homoglyphs maps characters to visually similar characters --
var homoglyphs = map[rune][]rune{
	'o': {'0'}, 'O': {'0'},
	'l': {'1', 'I'}, 'I': {'1', 'l'},
	'i': {'1', 'l'},
	's': {'5'}, 'S': {'5'},
	'z': {'2'}, 'Z': {'2'},
	'a': {'@'},
	'b': {'8'}, 'B': {'8'},
	';': {':'}, ':': {';'},
	',': {'.'}, '.': {','},
}

// -- commonNgrams contains common letter combinations to simulate rhythmic typing --
var commonNgrams = map[string]bool{
	"th": true, "he": true, "in": true, "er": true, "an": true, "re": true,
	"es": true, "on": true, "st": true, "nt": true,
	"the": true, "and": true, "ing": true, "ion": true, "tio": true,
}

// -- Advanced IKD Structures --

// KeyInfo stores metadata about keys for IKD calculation.
type KeyInfo struct {
	Hand   int     // 0: Left, 1: Right, 2: Either (Spacebar)
	Finger int     // 0: Pinky, 1: Ring, 2: Middle, 3: Index, 4: Thumb
	Row    int     // 0: Numbers, 1: Top, 2: Home, 3: Bottom
	Col    float64 // Column position, staggered for realism
}

// QWERTYLayout maps characters to their physical properties on a standard keyboard.
var QWERTYLayout = map[rune]KeyInfo{
	// Numbers Row
	'1': {0, 0, 0, 1}, '2': {0, 1, 0, 2}, '3': {0, 2, 0, 3}, '4': {0, 3, 0, 4}, '5': {0, 3, 0, 5},
	'6': {1, 3, 0, 6}, '7': {1, 3, 0, 7}, '8': {1, 2, 0, 8}, '9': {1, 1, 0, 9}, '0': {1, 0, 0, 10},
	// Top Row
	'q': {0, 0, 1, 1.5}, 'w': {0, 1, 1, 2.5}, 'e': {0, 2, 1, 3.5}, 'r': {0, 3, 1, 4.5}, 't': {0, 3, 1, 5.5},
	'y': {1, 3, 1, 6.5}, 'u': {1, 3, 1, 7.5}, 'i': {1, 2, 1, 8.5}, 'o': {1, 1, 1, 9.5}, 'p': {1, 0, 1, 10.5},
	// Home Row
	'a': {0, 0, 2, 1.75}, 's': {0, 1, 2, 2.75}, 'd': {0, 2, 2, 3.75}, 'f': {0, 3, 2, 4.75}, 'g': {0, 3, 2, 5.75},
	'h': {1, 3, 2, 6.75}, 'j': {1, 3, 2, 7.75}, 'k': {1, 2, 2, 8.75}, 'l': {1, 1, 2, 9.75}, ';': {1, 0, 2, 10.75},
	// Bottom Row
	'z': {0, 0, 3, 2}, 'x': {0, 1, 3, 3}, 'c': {0, 2, 3, 4}, 'v': {0, 3, 3, 5}, 'b': {0, 3, 3, 6},
	'n': {1, 3, 3, 7}, 'm': {1, 3, 3, 8}, ',': {1, 2, 3, 9}, '.': {1, 1, 3, 10}, '/': {1, 0, 3, 11},
	// Spacebar
	' ': {2, 4, 4, 6},
}

// getKeyInfo retrieves the KeyInfo for a given rune, handling case and fallbacks.
func getKeyInfo(r rune) KeyInfo {
	info, ok := QWERTYLayout[unicode.ToLower(r)]
	if !ok {
		// Default fallback for unknown characters.
		return KeyInfo{Hand: 1, Finger: 3, Row: 1, Col: 11}
	}
	return info
}

// parseKeyExpression parses a string like "ctrl+shift+a" into KeyEventData.
func parseKeyExpression(expression string) (schemas.KeyEventData, error) {
	parts := strings.Split(expression, "+")
	var data schemas.KeyEventData
	var keyPart string

	// Track the original string representation of the key for case sensitivity
	var originalKeyString string

	for _, part := range parts {
		p := strings.TrimSpace(part)
		pLower := strings.ToLower(p)

		if pLower == "" {
			// Handles cases like "ctrl++a" or empty input if split results in empty strings
			if strings.TrimSpace(expression) == "" || strings.Contains(expression, "++") {
				return schemas.KeyEventData{}, fmt.Errorf("invalid or empty expression: '%s'", expression)
			}
			continue
		}

		switch pLower {
		case "ctrl", "control":
			data.Modifiers |= schemas.ModCtrl
		case "alt", "option":
			data.Modifiers |= schemas.ModAlt
		case "shift":
			data.Modifiers |= schemas.ModShift
		case "meta", "cmd", "command", "win", "windows":
			data.Modifiers |= schemas.ModMeta
		default:
			if keyPart != "" {
				return schemas.KeyEventData{}, fmt.Errorf("multiple keys specified in expression: '%s' and '%s'", keyPart, p)
			}
			keyPart = pLower
			originalKeyString = p
		}
	}

	if keyPart == "" {
		return schemas.KeyEventData{}, fmt.Errorf("no key specified in expression: '%s'", expression)
	}

	// Determine the final key string.
	if len(keyPart) == 1 {
		// Use the original casing if it was a single character.
		data.Key = originalKeyString
	} else {
		// Use the normalized lowercase name for special keys (e.g., "enter", "tab").
		data.Key = keyPart
	}

	// Handle implicit Shift modifier and ensure capitalization consistency.
	isUppercase := false
	isLetter := false
	if len(data.Key) == 1 {
		r := rune(data.Key[0])
		if unicode.IsLetter(r) {
			isLetter = true
			if unicode.IsUpper(r) {
				isUppercase = true
			}
		}
	}

	// If it's uppercase (e.g., input "Ctrl+A"), ensure Shift modifier is set.
	if isUppercase {
		data.Modifiers |= schemas.ModShift
	}

	// If Shift modifier is set (explicitly or implicitly), ensure the key representation is uppercase if it's a letter.
	if (data.Modifiers&schemas.ModShift != 0) && isLetter {
		data.Key = strings.ToUpper(data.Key)
	}

	return data, nil
}

// Shortcut parses a key expression (e.g., "ctrl+a", "meta+c") and dispatches it.
func (h *Humanoid) Shortcut(ctx context.Context, keysExpression string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 1. Parse the expression
	keyData, err := parseKeyExpression(keysExpression)
	if err != nil {
		return fmt.Errorf("humanoid: failed to parse shortcut expression '%s': %w", keysExpression, err)
	}

	h.logger.Debug("Humanoid: Executing shortcut",
		zap.String("expression", keysExpression),
		zap.String("key", keyData.Key),
		zap.Int("modifiers", int(keyData.Modifiers)),
	)

	// Update fatigue/habituation. Shortcuts are low intensity (e.g., 0.1).
	h.updateFatigueAndHabituation(0.1)

	// 2. Cognitive pause before executing a shortcut.
	// Shortcuts are often reflexive (Mean Scale 1.0, StdDev Scale 0.8). ActionType switches to TYPE.
	if err := h.cognitivePause(ctx, 1.0, 0.8, ActionTypeType); err != nil {
		return err
	}

	// 3. Dispatch the structured key event
	// The executor handles the precise timings of KeyDown/KeyUp.
	if err := h.executor.DispatchStructuredKey(ctx, keyData); err != nil {
		return fmt.Errorf("humanoid: failed to dispatch shortcut '%s': %w", keysExpression, err)
	}

	// 4. Simulate the time the combination is held down (post-dispatch sleep).
	// This adds realism to the overall action duration and ensures the browser processes the shortcut.
	// The executor dispatches KeyDown/KeyUp quickly; this sleep represents the user's hold time.
	holdDuration := h.keyHoldDuration()
	// Use Sleep as we don't need mouse hesitation during a keyboard shortcut.
	if err := h.executor.Sleep(ctx, holdDuration); err != nil {
		return err
	}

	// Recover fatigue during the hold.
	h.recoverFatigue(holdDuration)

	return nil
}

// Type is the public entry point for typing and acquires the lock for the entire operation.
func (h *Humanoid) Type(ctx context.Context, selector string, text string, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update fatigue/habituation based on the typing effort (length of text). Intensity factor 0.05 per character.
	h.updateFatigueAndHabituation(float64(len(text)) * 0.05)

	// 1. Preparation: Use an internal helper to focus the element.
	// ActionType is handled within clickToFocus (MOVE then CLICK).
	if err := h.clickToFocus(ctx, selector, opts); err != nil {
		return fmt.Errorf("humanoid: failed to click/focus selector '%s': %w", selector, err)
	}

	// Pause after focusing to simulate cognitive planning (Mean Scale 2.0, StdDev Scale 1.5).
	// cognitivePause handles the ActionType switch (from CLICK to TYPE).
	if err := h.cognitivePause(ctx, 2.0, 1.5, ActionTypeType); err != nil {
		return err
	}

	// Convert the entire text to runes for processing.
	runes := []rune(text)
	cfg := h.dynamicConfig
	burstPauseProb := cfg.KeyBurstPauseProbability

	// 2. Execution Loop: Type character by character.
	for i := 0; i < len(runes); i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Introduce Burst Pause (Cognitive delay during typing).
		// Check against burstPauseProb. Go's RNG returns [0.0, 1.0).
		if h.rng.Float64() < burstPauseProb {
			// Burst pauses are longer than standard IKD (Mean Scale 3.0, StdDev Scale 2.0).
			// ActionType remains TYPE.
			if err := h.cognitivePause(ctx, 3.0, 2.0, ActionTypeType); err != nil {
				return err
			}
		}

		// Speed factor is generally 1.0, relying on IKD for timing.
		const speedFactor = 1.0

		advanced, err := h.typeCharacter(ctx, runes, i, speedFactor)
		if err != nil {
			return err
		}
		if advanced {
			i++ // Skip next character if handled by typo (e.g., transposition).
		}
	}

	return nil
}

// clickToFocus is an internal helper that performs a click without acquiring a lock.
func (h *Humanoid) clickToFocus(ctx context.Context, selector string, opts *InteractionOptions) error {
	// ensureVisible and moveToSelector are handled within the internal click logic.
	// We call moveToSelector here which handles ensureVisible internally.
	// ActionType is set to MOVE within moveToSelector.
	if err := h.moveToSelector(ctx, selector, opts); err != nil {
		return err
	}

	// Cognitive pause before the click (Mean Scale 0.5, StdDev Scale 0.5).
	// cognitivePause handles the ActionType switch (from MOVE to CLICK).
	if err := h.cognitivePause(ctx, 0.5, 0.5, ActionTypeClick); err != nil {
		return err
	}

	// Simplified click logic using applyClickNoise and hesitate for realism.
	// Apply click noise before press.
	clickPos := h.applyClickNoise(h.currentPos)

	mouseDownData := schemas.MouseEventData{
		Type:       schemas.MousePress,
		X:          clickPos.X,
		Y:          clickPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    1,
	}
	if err := h.executor.DispatchMouseEvent(ctx, mouseDownData); err != nil {
		return err
	}
	h.currentPos = clickPos
	h.currentButtonState = schemas.ButtonLeft

	// Short hold with hesitation (slippage).
	holdDuration := h.keyHoldDuration()
	if err := h.hesitate(ctx, holdDuration); err != nil {
		// Attempt cleanup if interrupted.
		h.releaseMouse(context.Background())
		return err
	}

	// Apply click noise before release.
	releasePos := h.applyClickNoise(h.currentPos)
	h.currentPos = releasePos

	// Use centralized release function.
	return h.releaseMouse(ctx)
}

// typeCharacter handles the logic for typing a single character. Assumes lock is held.
func (h *Humanoid) typeCharacter(ctx context.Context, runes []rune, i int, speedFactor float64) (advanced bool, err error) {
	// Calculate and execute the Inter-Key Delay (IKD).
	if err := h.keyPause(ctx, speedFactor, speedFactor, runes, i); err != nil {
		return false, err
	}

	cfg := h.dynamicConfig
	// Check against TypoRate. Go's RNG returns [0.0, 1.0).
	shouldTypo := h.rng.Float64() < cfg.TypoRate

	if shouldTypo {
		// FIX: typoHandled indicates if the character at index i (and potentially i+1) was fully processed by the typo logic.
		typoHandled, advanced, err := h.introduceTypo(ctx, cfg, runes, i)
		if err != nil {
			return false, fmt.Errorf("humanoid: error during typo simulation: %w", err)
		}
		if typoHandled {
			return advanced, nil
		}
		// If shouldTypo was true but typoHandled is false, it means a typo attempt failed (e.g., no neighbors found).
		// We proceed to type the intended character.
	}

	// No typo or typo attempt failed: Send the intended character.
	if err := h.sendString(ctx, string(runes[i])); err != nil {
		return false, fmt.Errorf("humanoid: failed to send key '%c': %w", runes[i], err)
	}

	return false, nil
}

// sendString is a unified, private helper for dispatching key events. Assumes lock is held.
func (h *Humanoid) sendString(ctx context.Context, keys string) error {
	if err := h.executor.SendKeys(ctx, keys); err != nil {
		return err
	}
	// Simulate the time the key is held down.
	return h.executor.Sleep(ctx, h.keyHoldDuration())
}

// keyHoldDuration calculates key hold time using Ex-Gaussian distribution. Assumes lock is held.
func (h *Humanoid) keyHoldDuration() time.Duration {
	cfg := h.dynamicConfig
	// Use the specific KeyHold parameters (Mu, Sigma, Tau).
	mu := cfg.KeyHoldMu
	sigma := cfg.KeyHoldSigma
	tau := cfg.KeyHoldTau

	delay := h.randExGaussian(mu, sigma, tau)

	// Apply fatigue (longer holds when tired, factor 0.2). Habituation is already factored into dynamic config.
	delay *= (1.0 + h.fatigueLevel*0.2)

	// Ensure a minimum realistic hold time (20ms).
	if delay < 20.0 {
		delay = 20.0 + h.rng.Float64()*5.0
	}
	// FIX: Ensure accurate time conversion.
	return time.Duration(delay * float64(time.Millisecond))
}

// keyPause introduces a human-like inter-key delay (IKD) using Ex-Gaussian modeling and physical factors.
// Assumes lock is held.
func (h *Humanoid) keyPause(ctx context.Context, meanScale, stdDevScale float64, runes []rune, index int) error {
	// If it's the first character (index 0), there is no IKD.
	if index == 0 {
		// If runes is nil (e.g. during typo correction) and index is 0, we still need a pause if scales are set.
		if runes != nil || (meanScale == 1.0 && stdDevScale == 1.0) {
			return nil
		}
	}

	cfg := h.dynamicConfig
	fatigueLevel := h.fatigueLevel

	// 1. Calculate Base IKD Distribution Parameters (Ex-Gaussian)
	// Use specific IKD parameters (Mu, Sigma, Tau).
	mu := cfg.IKDMu * meanScale
	sigma := cfg.IKDSigma * stdDevScale
	tau := cfg.IKDTau * stdDevScale
	minDelay := cfg.KeyPauseMin * meanScale

	// -- Advanced IKD Modeling: Applying Modifiers --
	ikdFactor := 1.0

	// Apply factors only if we have the context (runes) and it's not the start of the sequence.
	if runes != nil && index > 0 && index < len(runes) {
		// 2. N-gram (Rhythm) Factor
		ngramFactor := 1.0
		if index > 1 {
			trigraph := strings.ToLower(string(runes[index-2 : index+1]))
			if commonNgrams[trigraph] {
				ngramFactor = cfg.KeyPauseNgramFactor3
			}
		}
		// Check for digraph only if trigraph wasn't found.
		if ngramFactor == 1.0 {
			digraph := strings.ToLower(string(runes[index-1 : index+1]))
			if commonNgrams[digraph] {
				ngramFactor = cfg.KeyPauseNgramFactor2
			}
		}
		ikdFactor *= ngramFactor

		// 3. Physical Effort Factor (Hand/Finger switching, Distance)
		prevKey := getKeyInfo(runes[index-1])
		currentKey := getKeyInfo(runes[index])

		physicalFactor := 1.0

		// Determine hand usage, handling the spacebar (Hand 2).
		prevHand := prevKey.Hand
		currentHand := currentKey.Hand

		// Simple model: if either is spacebar, treat it as the opposite hand of the other key.
		if prevHand == 2 && currentHand != 2 {
			prevHand = 1 - currentHand
		} else if currentHand == 2 && prevHand != 2 {
			currentHand = 1 - prevHand
		}

		if prevHand != currentHand {
			// Hand alternation (faster)
			physicalFactor = cfg.IKDHandAlternationBonus
		} else if prevKey.Finger != currentKey.Finger {
			// Different finger, same hand (neutral speed)
			physicalFactor = 1.0
		} else {
			// Same finger repetition (slowest)
			physicalFactor = cfg.IKDSameFingerPenalty
		}

		// Distance calculation (Euclidean distance on the layout)
		dist := math.Sqrt(math.Pow(prevKey.Col-currentKey.Col, 2) + math.Pow(float64(prevKey.Row-currentKey.Row), 2))
		// Longer distances take more time.
		distanceFactor := 1.0 + dist*cfg.IKDDistanceFactor

		ikdFactor *= physicalFactor * distanceFactor
	}

	// Apply the combined IKD factor to the distribution parameters.
	mu *= ikdFactor
	sigma *= ikdFactor
	tau *= ikdFactor
	minDelay *= ikdFactor

	// 4. Fatigue Factor
	fatigueFactor := 1.0 + fatigueLevel*cfg.KeyPauseFatigueFactor
	mu *= fatigueFactor
	tau *= fatigueFactor // Fatigue disproportionately increases Tau (long delays).

	// Calculate final delay using the modified Ex-Gaussian parameters.
	delay := h.randExGaussian(mu, sigma, tau)
	finalDelay := math.Max(minDelay, delay)
	// FIX: Convert float64 milliseconds (finalDelay) to time.Duration (int64 nanoseconds) accurately to prevent truncation.
	duration := time.Duration(finalDelay * float64(time.Millisecond))

	// Recover fatigue during the pause.
	h.recoverFatigue(duration)

	return h.executor.Sleep(ctx, duration)
}

// introduceTypo decides which kind of typo to simulate. Assumes lock is held.
// FIX: Renamed return variables to (handled bool, advanced bool, err error) for clarity.
// 'handled' means the character(s) were processed and the main loop should not process the current index again.
func (h *Humanoid) introduceTypo(ctx context.Context, cfg config.HumanoidConfig, runes []rune, i int) (handled bool, advanced bool, err error) {
	char := runes[i]
	p := h.rng.Float64()

	if p < cfg.TypoHomoglyphRate {
		// Homoglyph typos attempt to handle the character.
		return h.introduceHomoglyphTypo(ctx, char)
	}
	p -= cfg.TypoHomoglyphRate

	if p < cfg.TypoNeighborRate {
		// Neighbor typos attempt to handle the character.
		return h.introduceNeighborTypo(ctx, char)
	}
	p -= cfg.TypoNeighborRate

	if p < cfg.TypoTransposeRate {
		var nextChar rune
		if i+1 < len(runes) {
			nextChar = runes[i+1]
		}
		// Transposition attempts to handle the character (and the next one).
		return h.introduceTransposition(ctx, char, nextChar)
	}
	p -= cfg.TypoTransposeRate

	if p < cfg.TypoOmissionRate {
		// Omission attempts to handle the character.
		return h.introduceOmission(ctx, char)
	}

	// Any remaining probability falls through to an insertion typo.
	// Insertion attempts to handle the character.
	return h.introduceInsertion(ctx, char)
}

// -- Typo Implementations (all assume lock is held) --
// FIX: Updated return signatures to (handled bool, advanced bool, err error)

func (h *Humanoid) introduceHomoglyphTypo(ctx context.Context, char rune) (bool, bool, error) {
	if candidates, ok := homoglyphs[char]; ok && len(candidates) > 0 {
		cfg := h.dynamicConfig
		typoChar := candidates[h.rng.Intn(len(candidates))]

		if err := h.sendString(ctx, string(typoChar)); err != nil {
			return true, false, err
		}

		shouldCorrect := h.rng.Float64() < cfg.TypoCorrectionProbability
		if shouldCorrect {
			// Pause to notice typo (Cognitive pause, not IKD).
			if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
				return true, false, err
			}
			if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
				return true, false, err
			}
			// Pause after correction.
			if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil {
				return true, false, err
			}
			if err := h.sendString(ctx, string(char)); err != nil {
				return true, false, err
			}
		}
		// Character handled (either substituted or corrected).
		return true, false, nil
	}
	// No homoglyph found for this char, so typo was not handled by this function.
	return false, false, nil
}

func (h *Humanoid) introduceNeighborTypo(ctx context.Context, char rune) (bool, bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		cfg := h.dynamicConfig
		typoChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		if unicode.IsUpper(char) && h.rng.Float64() < cfg.TypoShiftCorrectionProbability {
			typoChar = unicode.ToUpper(typoChar)
		}

		if err := h.sendString(ctx, string(typoChar)); err != nil {
			return true, false, err
		}

		// FIX: Check probability before correcting.
		shouldCorrect := h.rng.Float64() < cfg.TypoCorrectionProbability
		if shouldCorrect {
			// Pause to notice typo (Cognitive pause, not IKD).
			if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
				return true, false, err
			}
			if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
				return true, false, err
			}
			// Pause after correction.
			if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil {
				return true, false, err
			}
			if err := h.sendString(ctx, string(char)); err != nil {
				return true, false, err
			}
		}
		// Character handled.
		return true, false, nil
	}
	// Typo not handled by this function.
	return false, false, nil
}

func (h *Humanoid) introduceTransposition(ctx context.Context, char, nextChar rune) (handled, advanced bool, err error) {
	if nextChar == 0 || unicode.IsSpace(nextChar) || unicode.IsSpace(char) {
		return false, false, nil
	}
	// Typo occurs: Type nextChar then char.
	if err := h.sendString(ctx, string(nextChar)); err != nil {
		return true, true, err
	}
	// Short pause between transposed keys.
	if err := h.keyPause(ctx, 0.8, 0.3, nil, 0); err != nil {
		return true, true, err
	}
	if err := h.sendString(ctx, string(char)); err != nil {
		return true, true, err
	}
	advanced = true
	handled = true

	cfg := h.dynamicConfig
	// Check probability before correcting.
	shouldCorrect := h.rng.Float64() < cfg.TypoCorrectionProbability

	if shouldCorrect {
		// Pause to notice transposition.
		if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
			return handled, advanced, err
		}
		if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
			return handled, advanced, err
		}
		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil {
			return handled, advanced, err
		}
		if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
			return handled, advanced, err
		}
		// Pause before retyping.
		if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil {
			return handled, advanced, err
		}
		if err := h.sendString(ctx, string(char)); err != nil {
			return handled, advanced, err
		}
		if err := h.keyPause(ctx, 1.0, 0.4, nil, 0); err != nil {
			return handled, advanced, err
		}
		if err := h.sendString(ctx, string(nextChar)); err != nil {
			return handled, advanced, err
		}
	}
	return handled, advanced, nil
}

func (h *Humanoid) introduceOmission(ctx context.Context, char rune) (bool, bool, error) {
	if unicode.IsSpace(char) {
		return false, false, nil
	}

	cfg := h.dynamicConfig
	shouldNotice := h.rng.Float64() < cfg.TypoOmissionNoticeProbability

	if shouldNotice {
		// Pause to notice the omission, then type the character.
		if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
			return true, false, err
		}
		if err := h.sendString(ctx, string(char)); err != nil {
			return true, false, err
		}
	}
	// Character handled (either omitted or noticed and typed).
	return true, false, nil
}

func (h *Humanoid) introduceInsertion(ctx context.Context, char rune) (bool, bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		cfg := h.dynamicConfig
		insertionChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		shouldNotice := h.rng.Float64() < cfg.TypoInsertionNoticeProbability

		// Type the inserted character.
		if err := h.sendString(ctx, string(insertionChar)); err != nil {
			return true, false, err
		}

		if shouldNotice {
			// Pause to notice the insertion, then delete it.
			if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
				return true, false, err
			}
			if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
				return true, false, err
			}
		}

		// Pause before typing the intended character.
		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil {
			return true, false, err
		}
		if err := h.sendString(ctx, string(char)); err != nil {
			return true, false, err
		}
		// Character handled.
		return true, false, nil
	}
	// Typo not handled by this function.
	return false, false, nil
}
