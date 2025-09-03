// pkg/humanoid/keyboard.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// -- keyboardNeighbors --
// Maps characters to adjacent keys on a standard QWERTY layout for "fat-finger" typos.
var keyboardNeighbors = map[rune]string{
	'1': "2q`", '2': "13wq", '3': "24we", '4': "35er", '5': "46rt", '6': "57ty",
	'7': "68yu", '8': "79ui", '9': "80io", '0': "9-op",
	'q': "wa1s", 'w': "qase23", 'e': "wsdr34", 'r': "edft45", 't': "rfgy56",
	'y': "tghu67", 'u': "yhji78", 'i': "ujko89", 'o': "iklp90", 'p': "ol;0-",
	'a': "qwsz", 's': "awedxz", 'd': "serfcx", 'f': "drtgvc", 'g': "ftyhbv",
	'h': "gyujnb", 'j': "huikmn", 'k': "jiol,m", 'l': "kop;.",
	'z': "asx", 'x': "zsdc", 'c': "xdfv", 'v': "cfgb", 'b': "vghn", 'n': "bhjm", 'm': "njk,",
}

// -- commonNgrams --
// Stores common English digraphs/trigraphs for faster typing simulation (muscle memory).
var commonNgrams = map[string]bool{
	"th": true, "he": true, "in": true, "er": true, "an": true, "re": true,
	"es": true, "on": true, "st": true, "nt": true,
	"the": true, "and": true, "ing": true, "ion": true, "tio": true,
}

// Basic mapping for US QWERTY layout Virtual Key codes (required for raw events).
var keyToVK = map[rune]int64{
	'a': 0x41, 'b': 0x42, 'c': 0x43, 'd': 0x44, 'e': 0x45, 'f': 0x46,
	'g': 0x47, 'h': 0x48, 'i': 0x49, 'j': 0x4A, 'k': 0x4B, 'l': 0x4C,
	'm': 0x4D, 'n': 0x4E, 'o': 0x4F, 'p': 0x50, 'q': 0x51, 'r': 0x52,
	's': 0x53, 't': 0x54, 'u': 0x55, 'v': 0x56, 'w': 0x57, 'x': 0x58,
	'y': 0x59, 'z': 0x5A,
	'0': 0x30, '1': 0x31, '2': 0x32, '3': 0x33, '4': 0x34,
	'5': 0x35, '6': 0x36, '7': 0x37, '8': 0x38, '9': 0x39,
	' ': 0x20, '\b': 0x08, '\r': 0x0D, '\n': 0x0D, // Space, Backspace, Enter
	// Punctuation (Standard US Layout)
	';': 0xBA, '=': 0xBB, ',': 0xBC, '-': 0xBD, '.': 0xBE, '/': 0xBF,
	'`': 0xC0, '[': 0xDB, '\\': 0xDC, ']': 0xDD, '\'': 0xDE,
}

// Characters that require the Shift key on a standard US QWERTY layout.
func needsShift(key rune) bool {
	if unicode.IsLetter(key) && unicode.IsUpper(key) {
		return true
	}
	switch key {
	case '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+',
		'{', '}', '|', ':', '"', '<', '>', '?','~':
		return true
	default:
		return false
	}
}

// Type simulates realistic human typing behavior, including typos, N-gram adjustments,
// key hold dynamics, fatigue, and input synchronization.
func (h *Humanoid) Type(selector string, text string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Update fatigue based on the intensity of the typing action.
		h.updateFatigue(float64(len(text)) * 0.1)

		// 1. Preparation: Realistically find and focus the element.
		if err := chromedp.WaitVisible(selector).Do(ctx); err != nil {
			return fmt.Errorf("humanoid: element '%s' not visible: %w", selector, err)
		}

		// Use IntelligentClick to focus the input field.
		if err := h.IntelligentClick(selector, nil).Do(ctx); err != nil {
			return fmt.Errorf("humanoid: failed to click/focus selector '%s': %w", selector, err)
		}

		// Pause after focusing (Cognitive planning). Uses CognitivePause for input synchronization.
		if err := h.CognitivePause(ctx, 200, 80); err != nil {
			return err
		}

		runes := []rune(text)

		// 2. Execution Loop: Type each character one by one.
		for i := 0; i < len(runes); i++ {
			// Inter-key pause (IKD), adjusted for N-grams. May trigger mouse movement if long enough.
			if err := h.keyPause(ctx, 1.0, 1.0, text, i); err != nil {
				return err
			}

			// Determine if a typo should occur.
			h.mu.Lock()
			// Use dynamic config (affected by fatigue).
			cfg := h.dynamicConfig
			shouldTypo := h.rng.Float64() < cfg.TypoRate
			h.mu.Unlock()

			if shouldTypo {
				// Attempt to introduce and correct a typo.
				typoIntroduced, advanced, err := h.introduceTypo(ctx, cfg, runes, i)
				if err != nil {
					return fmt.Errorf("humanoid: error during typo simulation: %w", err)
				}

				if advanced {
					i++
				}
				if typoIntroduced {
					continue
				}
			}

			// No typo: Send the intended character using the realistic sendKey method.
			if err := h.sendKey(ctx, runes[i]); err != nil {
				return fmt.Errorf("humanoid: failed to send key '%c': %w", runes[i], err)
			}
		}
		return nil
	})
}

// sendKey dispatches a single key with realistic hold time (KeyDown -> Pause -> KeyUp).
func (h *Humanoid) sendKey(ctx context.Context, key rune) error {
	text := string(key)
	var modifiers int64
	// Basic shift detection.
	if needsShift(key) {
		modifiers = 2 // Shift modifier bit.
	}

	// Attempt to find VK code, fallback if not found.
	keyCode, ok := keyToVK[unicode.ToLower(key)]
	if !ok {
		// If VK code isn't mapped, we rely on the browser interpreting the 'Key' field.
		h.logger.Debug("Humanoid: Virtual Key code not mapped for rune", zap.String("rune", string(key)))
	}

	// 1. KeyDown
	// Determine the event type. Use input.KeyDown for characters which generates input events.
	downType := input.RawKeyDown
	// Check if it's a standard printable character.
	if unicode.IsPrint(key) {
		downType = input.KeyDown
	}

	downEvent := input.DispatchKeyEvent(downType).
		WithModifiers(modifiers).
		WithWindowsVirtualKeyCode(keyCode).
		WithKey(text)

	// Only include 'Text' if it's a character input event (KeyDown/Char).
	if downType == input.KeyDown {
		downEvent = downEvent.WithText(text)
	}

	if err := downEvent.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: keydown failed for '%c': %w", key, err)
	}

	// 2. Hold Time (Biometric timing)
	if err := h.keyHoldPause(ctx); err != nil {
		// Ensure KeyUp happens even if pause is interrupted.
		input.DispatchKeyEvent(input.KeyUp).WithModifiers(modifiers).WithWindowsVirtualKeyCode(keyCode).WithKey(text).Do(context.Background())
		return err
	}

	// 3. KeyUp
	upEvent := input.DispatchKeyEvent(input.KeyUp).
		WithModifiers(modifiers).
		WithWindowsVirtualKeyCode(keyCode).
		WithKey(text)

	if err := upEvent.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: keyup failed for '%c': %w", key, err)
	}

	return nil
}

// sendControlKey handles keys like Backspace, Enter, etc.
func (h *Humanoid) sendControlKey(ctx context.Context, key string) error {
	var keyCode int64
	// Handle common control characters passed as strings (e.g., "\b").
	if len(key) == 1 {
		keyCode, _ = keyToVK[rune(key[0])]
	}

	// 1. KeyDown
	// Control keys typically use input.KeyDown.
	downEvent := input.DispatchKeyEvent(input.KeyDown).
		WithKey(key).
		WithWindowsVirtualKeyCode(keyCode)

	if err := downEvent.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: control keydown failed for '%s': %w", key, err)
	}

	// 2. Hold Time
	if err := h.keyHoldPause(ctx); err != nil {
		// Ensure KeyUp happens.
		input.DispatchKeyEvent(input.KeyUp).WithKey(key).WithWindowsVirtualKeyCode(keyCode).Do(context.Background())
		return err
	}

	// 3. KeyUp
	upEvent := input.DispatchKeyEvent(input.KeyUp).
		WithKey(key).
		WithWindowsVirtualKeyCode(keyCode)

	if err := upEvent.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: control keyup failed for '%s': %w", key, err)
	}
	return nil
}

// keyHoldPause simulates the duration a key is held down (Dwell Time).
func (h *Humanoid) keyHoldPause(ctx context.Context) error {
	h.mu.Lock()
	// Use dynamic config (affected by fatigue).
	cfg := h.dynamicConfig
	mean := cfg.KeyHoldMean
	stdDev := cfg.KeyHoldStdDev
	randNorm := h.rng.NormFloat64()
	h.mu.Unlock()

	delay := randNorm*stdDev + mean
	// Minimum physiological hold time (e.g., 20ms).
	duration := time.Duration(math.Max(20.0, delay)) * time.Millisecond

	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// keyPause introduces a human-like inter-key delay (IKD or Flight Time).
// If the delay is long enough, it simulates synchronized mouse micro-movements (Input Synchronization).
func (h *Humanoid) keyPause(ctx context.Context, meanScale, stdDevScale float64, ngramInfo ...interface{}) error {
	// Base IKD parameters.
	mean := 70.0 * meanScale
	stdDev := 28.0 * stdDevScale
	minDelay := 35.0 * meanScale
	ngramFactor := 1.0

	// Adjust for N-grams (Rhythmic typing).
	if len(ngramInfo) == 2 {
		if text, ok := ngramInfo[0].(string); ok {
			if index, ok := ngramInfo[1].(int); ok && index > 0 && index < len(text) {
				// Check for trigraph (faster)
				if index > 1 {
					trigraph := strings.ToLower(text[index-2 : index+1])
					if commonNgrams[trigraph] {
						ngramFactor = 0.55 // 45% faster
					}
				}
				// Check for digraph
				if ngramFactor == 1.0 {
					digraph := strings.ToLower(text[index-1 : index+1])
					if commonNgrams[digraph] {
						ngramFactor = 0.7 // 30% faster
					}
				}
			}
		}
	}

	mean *= ngramFactor
	minDelay *= ngramFactor

	// Generate delay.
	h.mu.Lock()
	randNorm := h.rng.NormFloat64()
	// Fatigue also slightly increases inter-key delays.
	fatigueFactor := 1.0 + h.fatigueLevel*0.3 // Up to 30% longer IKD when fatigued.
	h.mu.Unlock()

	mean *= fatigueFactor

	delay := randNorm*stdDev + mean
	finalDelay := math.Max(minDelay, delay)
	duration := time.Duration(finalDelay) * time.Millisecond

	// Input Synchronization: If the pause is long (> 120ms), use Hesitate to move the mouse slightly.
	// This prevents the "frozen cursor" anomaly during typing.
	if finalDelay > 120.0 {
		return h.Hesitate(duration).Do(ctx)
	}

	// Use a simple select block for short pauses.
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// (The introduceTypo functions follow, utilizing sendKey/sendControlKey and keyPause)

// introduceTypo selects and executes a specific typo based on normalized conditional probabilities.
func (h *Humanoid) introduceTypo(ctx context.Context, cfg Config, runes []rune, i int) (introduced bool, advanced bool, err error) {
	char := runes[i]

	h.mu.Lock()
	p := h.rng.Float64()
	h.mu.Unlock()

	// 1. Neighbor Typo
	if p < cfg.TypoNeighborRate {
		introduced, err = h.introduceNeighborTypo(ctx, char)
		return introduced, false, err
	}
	p -= cfg.TypoNeighborRate

	// 2. Transposition Typo
	if p < cfg.TypoTransposeRate {
		var nextChar rune
		if i+1 < len(runes) {
			nextChar = runes[i+1]
		}
		corrected, didAdvance, err := h.introduceTransposition(ctx, char, nextChar)
		// Return true for introduced if the sequence started (corrected or not).
		return corrected || didAdvance, didAdvance, err
	}
	p -= cfg.TypoTransposeRate

	// 3. Omission Typo
	if p < cfg.TypoOmissionRate {
		introduced, err = h.introduceOmission(ctx, char)
		return introduced, false, err
	}

	// 4. Insertion Typo (fallback)
	introduced, err = h.introduceInsertion(ctx, char)
	return introduced, false, err
}

func (h *Humanoid) introduceNeighborTypo(ctx context.Context, char rune) (bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		h.mu.Lock()
		// Select a random neighboring key.
		typoChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		// High chance (80%) to preserve the original character's case.
		if unicode.IsUpper(char) && h.rng.Float64() < 0.8 {
			typoChar = unicode.ToUpper(typoChar)
		}
		h.mu.Unlock()

		// Type the wrong character.
		if err := h.sendKey(ctx, typoChar); err != nil {
			return true, err // Return true because a key was sent.
		}
		// Pause to realize mistake (Long pause triggers input synchronization).
		if err := h.keyPause(ctx, 1.8, 0.6); err != nil {
			return true, err
		}
		// Send Backspace.
		if err := h.sendControlKey(ctx, "\b"); err != nil {
			return true, err
		}
		// Pause briefly after backspacing.
		if err := h.keyPause(ctx, 1.2, 0.5); err != nil {
			return true, err
		}
		// Type the correct character.
		if err := h.sendKey(ctx, char); err != nil {
			return true, err
		}
		return true, nil // Typo introduced and corrected successfully.
	}
	return false, nil // No valid neighbor.
}

func (h *Humanoid) introduceTransposition(ctx context.Context, char, nextChar rune) (corrected, advanced bool, err error) {
	// Can't transpose if there's no next character or if either is a space.
	if nextChar == 0 || unicode.IsSpace(nextChar) || unicode.IsSpace(char) {
		return false, false, nil
	}

	// Send the transposed characters rapidly.
	if err := h.sendKey(ctx, nextChar); err != nil {
		return false, true, err // Advanced past two conceptual characters.
	}
	// Short pause (transpositions happen quickly).
	if err := h.keyPause(ctx, 0.8, 0.3); err != nil {
		return false, true, err
	}
	if err := h.sendKey(ctx, char); err != nil {
		return false, true, err
	}
	advanced = true

	h.mu.Lock()
	shouldCorrect := h.rng.Float64() < 0.85 // 85% chance to notice and correct.
	h.mu.Unlock()

	if shouldCorrect {
		// Pause to realize mistake.
		if err := h.keyPause(ctx, 1.5, 0.7); err != nil {
			return false, advanced, err
		}
		// Send two backspaces sequentially.
		if err := h.sendControlKey(ctx, "\b"); err != nil {
			return false, advanced, err
		}
		if err := h.keyPause(ctx, 1.1, 0.4); err != nil { // Pause between backspaces
			return false, advanced, err
		}
		if err := h.sendControlKey(ctx, "\b"); err != nil {
			return false, advanced, err
		}

		// Pause again before retyping.
		if err := h.keyPause(ctx, 1.2, 0.5); err != nil {
			return false, advanced, err
		}
		// Send the correct sequence.
		if err := h.sendKey(ctx, char); err != nil {
			return false, advanced, err
		}
		if err := h.keyPause(ctx, 1.0, 0.4); err != nil { // Normal IKD
			return false, advanced, err
		}
		if err := h.sendKey(ctx, nextChar); err != nil {
			return false, advanced, err
		}
		return true, advanced, nil // Corrected and advanced.
	}

	// Did not correct, but still advanced.
	return false, advanced, nil
}

func (h *Humanoid) introduceOmission(ctx context.Context, char rune) (bool, error) {
	// Omitting spaces is often intended, so we don't simulate it as a mistake.
	if unicode.IsSpace(char) {
		return false, nil
	}

	// The character is skipped initially.

	h.mu.Lock()
	shouldNotice := h.rng.Float64() < 0.70 // 70% chance to notice the omission.
	h.mu.Unlock()

	if shouldNotice {
		// Pause slightly longer, simulating the realization of the mistake.
		if err := h.keyPause(ctx, 2.0, 0.8); err != nil {
			return true, err
		}
		// Now type the character that was missed.
		if err := h.sendKey(ctx, char); err != nil {
			return true, err
		}
		return true, nil // Omission occurred but was corrected.
	}
	// Character was omitted and not noticed.
	return true, nil
}

func (h *Humanoid) introduceInsertion(ctx context.Context, char rune) (bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		h.mu.Lock()
		// Pick a random neighbor to insert.
		insertionChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		shouldNotice := h.rng.Float64() < 0.80 // 80% chance to notice.
		h.mu.Unlock()

		// Send the inserted (wrong) character first.
		if err := h.sendKey(ctx, insertionChar); err != nil {
			return true, err
		}

		if shouldNotice {
			// Pause to notice the extra character.
			if err := h.keyPause(ctx, 1.5, 0.6); err != nil {
				return true, err
			}
			// Send Backspace to correct.
			if err := h.sendControlKey(ctx, "\b"); err != nil {
				return true, err
			}
		}

		// Pause before the intended character.
		if err := h.keyPause(ctx, 1.1, 0.4); err != nil {
			return true, err
		}

		// Finally, send the intended character.
		if err := h.sendKey(ctx, char); err != nil {
			return true, err
		}
		return true, nil // Insertion sequence complete.
	}
	return false, nil // No neighbor found.
}
