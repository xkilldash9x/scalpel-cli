package humanoid

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
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

// Type is the public entry point for typing and acquires the lock for the entire operation.
func (h *Humanoid) Type(ctx context.Context, selector string, text string, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update fatigue based on the typing effort (length of text).
	h.updateFatigue(float64(len(text)) * 0.05)

	// 1. Preparation: Use an internal helper to focus the element, avoiding a deadlock.
	if err := h.clickToFocus(ctx, selector, opts); err != nil {
		return fmt.Errorf("humanoid: failed to click/focus selector '%s': %w", selector, err)
	}

	// Pause after focusing to simulate cognitive planning.
	if err := h.cognitivePause(ctx, 200, 80); err != nil {
		return err
	}

	words := strings.Fields(text)

	// 2. Execution Loop: Type word by word to simulate burst-and-pause rhythm.
	for i, word := range words {
		// Type the characters of the word in a rapid burst.
		runes := []rune(word)
		for j := 0; j < len(runes); j++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Use a speed factor to make intra-word typing faster.
			const burstSpeedFactor = 0.7
			advanced, err := h.typeCharacter(ctx, runes, j, burstSpeedFactor)
			if err != nil {
				return err
			}
			if advanced {
				j++ // Skip next character if handled by typo (e.g., transposition).
			}
		}

		// If it's not the last word, add a space and a longer pause.
		if i < len(words)-1 {
			nextWordLen := len(words[i+1])
			rng := h.rng
			pauseMs := 100 + (float64(nextWordLen) * 5) + rng.Float64()*80
			if err := h.cognitivePause(ctx, pauseMs, pauseMs*0.4); err != nil {
				return err
			}

			// Type the space between words.
			if err := h.sendString(ctx, " "); err != nil {
				return err
			}
		}
	}
	return nil
}

// clickToFocus is a new internal helper that performs a click without acquiring a lock.
func (h *Humanoid) clickToFocus(ctx context.Context, selector string, opts *InteractionOptions) error {
	if err := h.moveToSelector(ctx, selector, opts); err != nil {
		return err
	}
	// Simplified click logic for focus.
	mouseDownData := schemas.MouseEventData{
		Type:       schemas.MousePress,
		X:          h.currentPos.X,
		Y:          h.currentPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    1,
	}
	if err := h.executor.DispatchMouseEvent(ctx, mouseDownData); err != nil {
		return err
	}

	// Short hold for focus.
	if err := h.executor.Sleep(ctx, h.keyHoldDuration()); err != nil {
		return err
	}

	mouseUpData := schemas.MouseEventData{
		Type:       schemas.MouseRelease,
		X:          h.currentPos.X,
		Y:          h.currentPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    0,
	}
	return h.executor.DispatchMouseEvent(ctx, mouseUpData)
}

// typeCharacter handles the logic for typing a single character. Assumes lock is held.
func (h *Humanoid) typeCharacter(ctx context.Context, runes []rune, i int, speedFactor float64) (advanced bool, err error) {
	if err := h.keyPause(ctx, speedFactor, speedFactor, runes, i); err != nil {
		return false, err
	}

	cfg := h.dynamicConfig
	shouldTypo := h.rng.Float64() < cfg.TypoRate

	if shouldTypo {
		typoIntroduced, advanced, err := h.introduceTypo(ctx, cfg, runes, i)
		if err != nil {
			return false, fmt.Errorf("humanoid: error during typo simulation: %w", err)
		}
		if typoIntroduced {
			return advanced, nil
		}
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
	return h.executor.Sleep(ctx, h.keyHoldDuration())
}

// keyHoldDuration calculates key hold time. Assumes lock is held.
func (h *Humanoid) keyHoldDuration() time.Duration {
	cfg := h.dynamicConfig
	mean := cfg.KeyHoldMean
	stdDev := cfg.KeyHoldStdDev
	randNorm := h.rng.NormFloat64()

	delay := randNorm*stdDev + mean
	if delay < 20.0 { // Ensure a minimum realistic hold time.
		delay = 20.0
	}
	return time.Duration(delay) * time.Millisecond
}

// keyPause introduces a human-like inter-key delay (IKD). Assumes lock is held.
func (h *Humanoid) keyPause(ctx context.Context, meanScale, stdDevScale float64, runes []rune, index int) error {
	cfg := h.dynamicConfig
	randNorm := h.rng.NormFloat64()
	fatigueLevel := h.fatigueLevel

	mean := cfg.KeyPauseMean * meanScale
	stdDev := cfg.KeyPauseStdDev * stdDevScale
	minDelay := cfg.KeyPauseMin * meanScale
	ngramFactor := 1.0

	// Adjust for common N-grams to simulate rhythmic typing.
	if runes != nil && index > 1 {
		trigraph := strings.ToLower(string(runes[index-2 : index+1]))
		if commonNgrams[trigraph] {
			ngramFactor = cfg.KeyPauseNgramFactor3
		} else {
			digraph := strings.ToLower(string(runes[index-1 : index+1]))
			if commonNgrams[digraph] {
				ngramFactor = cfg.KeyPauseNgramFactor2
			}
		}
	}

	mean *= ngramFactor
	minDelay *= ngramFactor

	fatigueFactor := 1.0 + fatigueLevel*cfg.KeyPauseFatigueFactor
	mean *= fatigueFactor

	delay := randNorm*stdDev + mean
	finalDelay := math.Max(minDelay, delay)
	duration := time.Duration(finalDelay) * time.Millisecond

	h.recoverFatigue(duration)

	return h.executor.Sleep(ctx, duration)
}

// introduceTypo decides which kind of typo to simulate. Assumes lock is held.
func (h *Humanoid) introduceTypo(ctx context.Context, cfg Config, runes []rune, i int) (introduced bool, advanced bool, err error) {
	char := runes[i]
	p := h.rng.Float64()

	if p < cfg.TypoNeighborRate {
		return h.introduceNeighborTypo(ctx, char)
	}
	p -= cfg.TypoNeighborRate

	if p < cfg.TypoTransposeRate {
		var nextChar rune
		if i+1 < len(runes) {
			nextChar = runes[i+1]
		}
		return h.introduceTransposition(ctx, char, nextChar)
	}
	p -= cfg.TypoTransposeRate

	if p < cfg.TypoOmissionRate {
		return h.introduceOmission(ctx, char)
	}

	return h.introduceInsertion(ctx, char)
}

// --- Typo Implementations (all assume lock is held) ---

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
		if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
			return true, false, err
		}
		if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
			return true, false, err
		}
		if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil {
			return true, false, err
		}
		if err := h.sendString(ctx, string(char)); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}

func (h *Humanoid) introduceTransposition(ctx context.Context, char, nextChar rune) (corrected, advanced bool, err error) {
	if nextChar == 0 || unicode.IsSpace(nextChar) || unicode.IsSpace(char) {
		return false, false, nil
	}
	if err := h.sendString(ctx, string(nextChar)); err != nil {
		return false, true, err
	}
	if err := h.keyPause(ctx, 0.8, 0.3, nil, 0); err != nil {
		return false, true, err
	}
	if err := h.sendString(ctx, string(char)); err != nil {
		return false, true, err
	}
	advanced = true

	cfg := h.dynamicConfig
	shouldCorrect := h.rng.Float64() < cfg.TypoCorrectionProbability

	if shouldCorrect {
		if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
			return false, advanced, err
		}
		if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
			return false, advanced, err
		}
		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil {
			return false, advanced, err
		}
		if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
			return false, advanced, err
		}
		if err := h.keyPause(ctx, 1.2, 0.5, nil, 0); err != nil {
			return false, advanced, err
		}
		if err := h.sendString(ctx, string(char)); err != nil {
			return false, advanced, err
		}
		if err := h.keyPause(ctx, 1.0, 0.4, nil, 0); err != nil {
			return false, advanced, err
		}
		if err := h.sendString(ctx, string(nextChar)); err != nil {
			return false, advanced, err
		}
		return true, advanced, nil
	}
	return false, advanced, nil
}

func (h *Humanoid) introduceOmission(ctx context.Context, char rune) (bool, bool, error) {
	if unicode.IsSpace(char) {
		return false, false, nil
	}

	cfg := h.dynamicConfig
	shouldNotice := h.rng.Float64() < cfg.TypoOmissionNoticeProbability

	if shouldNotice {
		if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
			return true, false, err
		}
		if err := h.sendString(ctx, string(char)); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	// Omission remains uncorrected.
	return true, false, nil
}

func (h *Humanoid) introduceInsertion(ctx context.Context, char rune) (bool, bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		cfg := h.dynamicConfig
		insertionChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		shouldNotice := h.rng.Float64() < cfg.TypoInsertionNoticeProbability

		if err := h.sendString(ctx, string(insertionChar)); err != nil {
			return true, false, err
		}

		if shouldNotice {
			if err := h.keyPause(ctx, cfg.TypoCorrectionPauseMeanScale, cfg.TypoCorrectionPauseStdDevScale, nil, 0); err != nil {
				return true, false, err
			}
			if err := h.sendString(ctx, string(KeyBackspace)); err != nil {
				return true, false, err
			}
		}

		if err := h.keyPause(ctx, 1.1, 0.4, nil, 0); err != nil {
			return true, false, err
		}
		if err := h.sendString(ctx, string(char)); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}