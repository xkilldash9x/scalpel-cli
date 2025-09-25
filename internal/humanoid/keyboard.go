package humanoid

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	// "github.com/chromedp/chromedp"       // Removed
	// "github.com/chromedp/chromedp/kb" // Removed
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

// -- commonNgrams contains common letter combinations to simulate rhythmic typing --
var commonNgrams = map[string]bool{
	"th": true, "he": true, "in": true, "er": true, "an": true, "re": true,
	"es": true, "on": true, "st": true, "nt": true,
	"the": true, "and": true, "ing": true, "ion": true, "tio": true,
}

// Type simulates realistic human typing behavior, including pauses, fatigue, and typos.
// It executes immediately using the provided context.
func (h *Humanoid) Type(ctx context.Context, selector string, text string) error {
	// Update fatigue based on the typing effort (length of text).
	h.updateFatigue(float64(len(text)) * 0.05)

	// 1. Preparation: Focus the element before typing.
	if err := h.IntelligentClick(ctx, selector, nil); err != nil {
		return fmt.Errorf("humanoid: failed to click/focus selector '%s': %w", selector, err)
	}

	// Pause after focusing to simulate cognitive planning.
	if err := h.CognitivePause(ctx, 200, 80); err != nil {
		return err
	}

	runes := []rune(text)

	// 2. Execution Loop: Type each character one by one.
	for i := 0; i < len(runes); i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Simulate the pause between keystrokes.
		if err := h.keyPause(ctx, 1.0, 1.0, runes, i); err != nil {
			return err
		}

		// Determine if a typo should occur based on fatigue and configuration.
		h.mu.Lock()
		cfg := h.dynamicConfig
		shouldTypo := h.rng.Float64() < cfg.TypoRate
		h.mu.Unlock()

		if shouldTypo {
			typoIntroduced, advanced, err := h.introduceTypo(ctx, cfg, runes, i)
			if err != nil {
				return fmt.Errorf("humanoid: error during typo simulation: %w", err)
			}
			if advanced {
				i++ // Skip the next character if the typo (e.g., transposition) handled it.
			}
			if typoIntroduced {
				continue // Move to the next iteration.
			}
		}

		// No typo: Send the intended character.
		if err := h.sendKey(ctx, runes[i]); err != nil {
			return fmt.Errorf("humanoid: failed to send key '%c': %w", runes[i], err)
		}
	}
	return nil
}

// sendKey dispatches a single key with a realistic hold time via the executor.
func (h *Humanoid) sendKey(ctx context.Context, key rune) error {
	// REFACTORED: We now call the executor's SendKeys method directly.
	// This relies on the contract that the element was already focused by IntelligentClick.
	if err := h.executor.SendKeys(ctx, string(key)); err != nil {
		return err
	}
	// Simulate the key "dwell" time after the key press.
	return h.executor.Sleep(ctx, h.keyHoldDuration())
}

// sendControlKey dispatches control characters (like Backspace) via the executor.
func (h *Humanoid) sendControlKey(ctx context.Context, key string) error {
	// REFACTORED: This is now unified with sendKey, using the executor's SendKeys method.
	if err := h.executor.SendKeys(ctx, key); err != nil {
		return err
	}
	// Simulate the key "dwell" time.
	return h.executor.Sleep(ctx, h.keyHoldDuration())
}

// keyHoldDuration calculates how long a key should be held down.
func (h *Humanoid) keyHoldDuration() time.Duration {
	h.mu.Lock()
	cfg := h.dynamicConfig
	mean := cfg.KeyHoldMean
	stdDev := cfg.KeyHoldStdDev
	randNorm := h.rng.NormFloat64()
	h.mu.Unlock()

	delay := randNorm*stdDev + mean
	if delay < 20.0 { // Ensure a minimum realistic hold time.
		delay = 20.0
	}
	return time.Duration(delay) * time.Millisecond
}

// keyPause introduces a human-like inter-key delay (IKD).
func (h *Humanoid) keyPause(ctx context.Context, meanScale, stdDevScale float64, runes []rune, index int) error {
	mean := 70.0 * meanScale
	stdDev := 28.0 * stdDevScale
	minDelay := 35.0 * meanScale
	ngramFactor := 1.0

	// Adjust for common N-grams to simulate rhythmic typing.
	if runes != nil && index > 1 {
		trigraph := strings.ToLower(string(runes[index-2 : index+1]))
		if commonNgrams[trigraph] {
			ngramFactor = 0.55 // Type faster
		} else {
			digraph := strings.ToLower(string(runes[index-1 : index+1]))
			if commonNgrams[digraph] {
				ngramFactor = 0.7 // Type a bit faster
			}
		}
	}

	mean *= ngramFactor
	minDelay *= ngramFactor

	h.mu.Lock()
	randNorm := h.rng.NormFloat64()
	fatigueFactor := 1.0 + h.fatigueLevel*0.3 // Fatigue increases delays.
	h.mu.Unlock()

	mean *= fatigueFactor

	delay := randNorm*stdDev + mean
	finalDelay := math.Max(minDelay, delay)
	duration := time.Duration(finalDelay) * time.Millisecond

	h.recoverFatigue(duration)

	return h.executor.Sleep(ctx, duration)
}

// introduceTypo decides which kind of typo to simulate.
func (h *Humanoid) introduceTypo(ctx context.Context, cfg Config, runes []rune, i int) (introduced bool, advanced bool, err error) {
	// This function's logic is unchanged as it calls the now-refactored helper methods.
	char := runes[i]
	h.mu.Lock()
	p := h.rng.Float64()
	h.mu.Unlock()

	if p < cfg.TypoNeighborRate {
		introduced, err = h.introduceNeighborTypo(ctx, char)
		return introduced, false, err
	}
	p -= cfg.TypoNeighborRate

	if p < cfg.TypoTransposeRate {
		var nextChar rune
		if i+1 < len(runes) {
			nextChar = runes[i+1]
		}
		corrected, didAdvance, err := h.introduceTransposition(ctx, char, nextChar)
		return corrected || didAdvance, didAdvance, err
	}
	p -= cfg.TypoTransposeRate

	if p < cfg.TypoOmissionRate {
		introduced, err = h.introduceOmission(ctx, char)
		return introduced, false, err
	}

	return h.introduceInsertion(ctx, char)
}

// --- Typo Implementations ---

func (h *Humanoid) introduceNeighborTypo(ctx context.Context, char rune) (bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		h.mu.Lock()
		typoChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		if unicode.IsUpper(char) && h.rng.Float64() < 0.8 {
			typoChar = unicode.ToUpper(typoChar)
		}
		h.mu.Unlock()

		if err := h.sendKey(ctx, typoChar); err != nil { return true, err }
		if err := h.keyPause(ctx, 1.8, 0.6, nil, 0); err != nil { return true, err }

		// REFACTORED: Use the internal 'KeyBackspace' constant.
		if err := h.sendControlKey(ctx, string(KeyBackspace)); err != nil { return true, err }

		if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil { return true, err }
		if err := h.sendKey(ctx, char); err != nil { return true, err }
		return true, nil
	}
	return false, nil
}

func (h *Humanoid) introduceTransposition(ctx context.Context, char, nextChar rune) (corrected, advanced bool, err error) {
	if nextChar == 0 || unicode.IsSpace(nextChar) || unicode.IsSpace(char) {
		return false, false, nil
	}
	if err := h.sendKey(ctx, nextChar); err != nil { return false, true, err }
	if err := h.keyPause(ctx, 0.8, 0.3, nil, 0); err != nil { return false, true, err }
	if err := h.sendKey(ctx, char); err != nil { return false, true, err }
	advanced = true

	h.mu.Lock()
	shouldCorrect := h.rng.Float64() < 0.85
	h.mu.Unlock()

	if shouldCorrect {
		if err := h.keyPause(ctx, 1.5, 0.7, nil, 0); err != nil { return false, advanced, err }

		// REFACTORED: Use the internal 'KeyBackspace' constant.
		if err := h.sendControlKey(ctx, string(KeyBackspace)); err != nil { return false, advanced, err }
		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil { return false, advanced, err }
		if err := h.sendControlKey(ctx, string(KeyBackspace)); err != nil { return false, advanced, err }
		
		if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil { return false, advanced, err }
		if err := h.sendKey(ctx, char); err != nil { return false, advanced, err }
		if err := h.keyPause(ctx, 1.0, 0.4, nil, 0); err != nil { return false, advanced, err }
		if err := h.sendKey(ctx, nextChar); err != nil { return false, advanced, err }
		return true, advanced, nil
	}
	return false, advanced, nil
}

func (h *Humanoid) introduceOmission(ctx context.Context, char rune) (bool, error) {
	if unicode.IsSpace(char) { return false, nil }
	
	h.mu.Lock()
	shouldNotice := h.rng.Float64() < 0.70
	h.mu.Unlock()

	if shouldNotice {
		if err := h.keyPause(ctx, 2.0, 0.8, nil, 0); err != nil { return true, err }
		if err := h.sendKey(ctx, char); err != nil { return true, err }
		return true, nil
	}
	// Omission remains uncorrected.
	return true, nil
}

func (h *Humanoid) introduceInsertion(ctx context.Context, char rune) (bool, bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		h.mu.Lock()
		insertionChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		shouldNotice := h.rng.Float64() < 0.80
		h.mu.Unlock()

		if err := h.sendKey(ctx, insertionChar); err != nil { return true, false, err }

		if shouldNotice {
			if err := h.keyPause(ctx, 1.5, 0.6, nil, 0); err != nil { return true, false, err }

			// REFACTORED: Use the internal 'KeyBackspace' constant.
			if err := h.sendControlKey(ctx, string(KeyBackspace)); err != nil { return true, false, err }
		}

		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil { return true, false, err }
		if err := h.sendKey(ctx, char); err != nil { return true, false, err }
		return true, false, nil
	}
	return false, false, nil
}
