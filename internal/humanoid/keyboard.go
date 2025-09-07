// -- pkg/humanoid/keyboard.go --
package humanoid

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

// -- keyboardNeighbors --
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
// Stored as strings for easy lookup.
var commonNgrams = map[string]bool{
	"th": true, "he": true, "in": true, "er": true, "an": true, "re": true,
	"es": true, "on": true, "st": true, "nt": true,
	"the": true, "and": true, "ing": true, "ion": true, "tio": true,
}

// Type simulates realistic human typing behavior.
func (h *Humanoid) Type(selector string, text string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Update fatigue based on the intensity (length).
		h.updateFatigue(float64(len(text)) * 0.05)

		// 1. Preparation: Focus the element.
		if err := h.IntelligentClick(selector, nil).Do(ctx); err != nil {
			return fmt.Errorf("humanoid: failed to click/focus selector '%s': %w", selector, err)
		}

		// Pause after focusing (Cognitive planning).
		if err := h.CognitivePause(200, 80).Do(ctx); err != nil {
			return err
		}

		// Convert string to rune slice for correct iteration and safe N-gram analysis.
		runes := []rune(text)

		// 2. Execution Loop.
		for i := 0; i < len(runes); i++ {
			// Inter-key pause (IKD).
			if err := h.keyPause(ctx, 1.0, 1.0, runes, i); err != nil {
				return err
			}

			// Determine if a typo should occur.
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
					i++
				}
				if typoIntroduced {
					continue
				}
			}

			// No typo: Send the intended character.
			if err := h.sendKey(ctx, runes[i]); err != nil {
				return fmt.Errorf("humanoid: failed to send key '%c': %w", runes[i], err)
			}
		}
		return nil
	})
}

// sendKey dispatches a single key with realistic hold time using high-level actions.
func (h *Humanoid) sendKey(ctx context.Context, key rune) error {
	// We simulate the "hold" duration by sleeping for a tiny bit *after* the key is sent.
	action := chromedp.SendKeys(
		// Target the active element using JS path.
		"document.activeElement",
		string(key),
		chromedp.ByJSPath,
	)

	if err := action.Do(ctx); err != nil {
		return err
	}
	// This simulates the dwell/hold time.
	return chromedp.Sleep(h.keyHoldDuration()).Do(ctx)
}

// sendControlKey dispatches control characters (like Backspace).
// FIXED: Updated signature to accept string as requested to resolve type mismatch.
func (h *Humanoid) sendControlKey(ctx context.Context, key string) error {
	// Use SendKeys targeted at the active element.
	action := chromedp.SendKeys(
		"document.activeElement",
		key,
		chromedp.ByJSPath,
	)

	if err := action.Do(ctx); err != nil {
		return err
	}
	// This simulates the dwell/hold time.
	return chromedp.Sleep(h.keyHoldDuration()).Do(ctx)
}

// keyHoldDuration calculates the duration a key should be held down.
func (h *Humanoid) keyHoldDuration() time.Duration {
	h.mu.Lock()
	cfg := h.dynamicConfig
	mean := cfg.KeyHoldMean
	stdDev := cfg.KeyHoldStdDev
	randNorm := h.rng.NormFloat64()
	h.mu.Unlock()

	delay := randNorm*stdDev + mean
	// Ensure a minimum realistic hold time.
	if delay < 20.0 {
		delay = 20.0
	}
	return time.Duration(delay) * time.Millisecond
}

// keyPause introduces a human-like inter-key delay (IKD or Flight Time).
func (h *Humanoid) keyPause(ctx context.Context, meanScale, stdDevScale float64, runes []rune, index int) error {
	mean := 70.0 * meanScale
	stdDev := 28.0 * stdDevScale
	minDelay := 35.0 * meanScale
	ngramFactor := 1.0

	// Adjust for N-grams (Rhythmic typing).
	if runes != nil && index > 0 && index < len(runes) {
		// Check Trigram (Previous 2 + Current)
		if index >= 2 {
			trigraph := strings.ToLower(string(runes[index-2 : index+1]))
			if commonNgrams[trigraph] {
				ngramFactor = 0.55
			}
		}

		// Check Digram (Previous 1 + Current)
		if ngramFactor == 1.0 && index >= 1 {
			digraph := strings.ToLower(string(runes[index-1 : index+1]))
			if commonNgrams[digraph] {
				ngramFactor = 0.7
			}
		}
	}

	mean *= ngramFactor
	minDelay *= ngramFactor

	h.mu.Lock()
	randNorm := h.rng.NormFloat64()
	// Fatigue increases inter-key delays.
	fatigueFactor := 1.0 + h.fatigueLevel*0.3
	h.mu.Unlock()

	mean *= fatigueFactor

	delay := randNorm*stdDev + mean
	finalDelay := math.Max(minDelay, delay) // Ensure delay is at least the minimum.
	duration := time.Duration(finalDelay) * time.Millisecond

	// Recover fatigue during the pause.
	h.recoverFatigue(duration)

	// Use the standard, context-aware chromedp.Sleep.
	return chromedp.Sleep(duration).Do(ctx)
}

// introduceTypo attempts to simulate a realistic typo based on configuration probabilities.
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
		return corrected || didAdvance, didAdvance, err
	}
	p -= cfg.TypoTransposeRate

	// 3. Omission Typo
	if p < cfg.TypoOmissionRate {
		introduced, err = h.introduceOmission(ctx, char)
		return introduced, false, err
	}

	// 4. Insertion Typo
	return h.introduceInsertion(ctx, char)
}

// --- Typo Implementations ---

func (h *Humanoid) introduceNeighborTypo(ctx context.Context, char rune) (bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		h.mu.Lock()
		typoChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		// Preserve case probabilistically
		if unicode.IsUpper(char) && h.rng.Float64() < 0.8 {
			typoChar = unicode.ToUpper(typoChar)
		}
		h.mu.Unlock()

		// Send typo
		if err := h.sendKey(ctx, typoChar); err != nil {
			return true, err
		}
		// Pause (Recognition)
		if err := h.keyPause(ctx, 1.8, 0.6, nil, 0); err != nil {
			return true, err
		}
		// Backspace
		// kb.Backspace is compatible with the string signature (type Key string).
		if err := h.sendControlKey(ctx, kb.Backspace); err != nil {
			return true, err
		}
		// Pause (Repositioning)
		if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil {
			return true, err
		}
		// Send correct key
		if err := h.sendKey(ctx, char); err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func (h *Humanoid) introduceTransposition(ctx context.Context, char, nextChar rune) (corrected, advanced bool, err error) {
	if nextChar == 0 || unicode.IsSpace(nextChar) || unicode.IsSpace(char) {
		return false, false, nil
	}
	// Send keys in wrong order
	if err := h.sendKey(ctx, nextChar); err != nil {
		return false, true, err
	}
	// Short pause (Rhythm continuation)
	if err := h.keyPause(ctx, 0.8, 0.3, nil, 0); err != nil {
		return false, true, err
	}
	if err := h.sendKey(ctx, char); err != nil {
		return false, true, err
	}
	advanced = true

	h.mu.Lock()
	shouldCorrect := h.rng.Float64() < 0.85
	h.mu.Unlock()

	if shouldCorrect {
		// Pause (Recognition)
		if err := h.keyPause(ctx, 1.5, 0.7, nil, 0); err != nil {
			return false, advanced, err
		}
		// Backspace x2
		if err := h.sendControlKey(ctx, kb.Backspace); err != nil {
			return false, advanced, err
		}
		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil {
			return false, advanced, err
		}
		if err := h.sendControlKey(ctx, kb.Backspace); err != nil {
			return false, advanced, err
		}
		// Pause (Repositioning)
		if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil {
			return false, advanced, err
		}
		// Send keys in correct order
		if err := h.sendKey(ctx, char); err != nil {
			return false, advanced, err
		}
		if err := h.keyPause(ctx, 1.0, 0.4, nil, 0); err != nil {
			return false, advanced, err
		}
		if err := h.sendKey(ctx, nextChar); err != nil {
			return false, advanced, err
		}
		return true, advanced, nil
	}
	return false, advanced, nil
}

func (h *Humanoid) introduceOmission(ctx context.Context, char rune) (bool, error) {
	if unicode.IsSpace(char) {
		return false, nil
	}
	// Key is skipped entirely.

	h.mu.Lock()
	shouldNotice := h.rng.Float64() < 0.70
	h.mu.Unlock()

	if shouldNotice {
		// Pause (Recognition of missing character)
		if err := h.keyPause(ctx, 2.0, 0.8, nil, 0); err != nil {
			return true, err
		}
		// Send the missing character
		if err := h.sendKey(ctx, char); err != nil {
			return true, err
		}
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

		// Send extra character
		if err := h.sendKey(ctx, insertionChar); err != nil {
			return true, false, err
		}

		if shouldNotice {
			// Pause (Recognition)
			if err := h.keyPause(ctx, 1.5, 0.6, nil, 0); err != nil {
				return true, false, err
			}
			// Backspace
			if err := h.sendControlKey(ctx, kb.Backspace); err != nil {
				return true, false, err
			}
		}

		// Pause before intended character
		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil {
			return true, false, err
		}
		// Send intended character
		if err := h.sendKey(ctx, char); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}