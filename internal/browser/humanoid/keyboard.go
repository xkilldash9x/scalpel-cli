package humanoid

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
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
// It now models "burst" typing for words with longer cognitive pauses between them.
func (h *Humanoid) Type(ctx context.Context, selector string, text string, opts *InteractionOptions) error {
	// Update fatigue based on the typing effort (length of text).
	h.updateFatigue(float64(len(text)) * 0.05)

	// 1. Preparation: Focus the element before typing. This will implicitly handle scrolling.
	if err := h.IntelligentClick(ctx, selector, opts); err != nil {
		return fmt.Errorf("humanoid: failed to click/focus selector '%s': %w", selector, err)
	}

	// Pause after focusing to simulate cognitive planning.
	if err := h.CognitivePause(ctx, 200, 80); err != nil {
		return err
	}

	// Use strings.Fields to handle multiple spaces between words gracefully.
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
			// Inter-word pause, simulates locating the next word.
			// The pause can be slightly longer if the next word is long.
			nextWordLen := len(words[i+1])
			h.mu.Lock()
			rng := h.rng
			h.mu.Unlock()
			pauseMs := 100 + (float64(nextWordLen) * 5) + rng.Float64()*80
			if err := h.CognitivePause(ctx, pauseMs, pauseMs*0.4); err != nil {
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

// typeCharacter handles the logic for typing a single character, including pauses and typos.
// It returns true if it processed more than one character (e.g., for transposition).
func (h *Humanoid) typeCharacter(ctx context.Context, runes []rune, i int, speedFactor float64) (advanced bool, err error) {
	// Simulate the pause between keystrokes, adjusted by the speedFactor.
	if err := h.keyPause(ctx, speedFactor, speedFactor, runes, i); err != nil {
		return false, err
	}

	// Determine if a typo should occur based on fatigue and configuration.
	h.mu.Lock()
	cfg := h.dynamicConfig
	shouldTypo := h.rng.Float64() < cfg.TypoRate
	h.mu.Unlock()

	if shouldTypo {
		typoIntroduced, advanced, err := h.introduceTypo(ctx, cfg, runes, i)
		if err != nil {
			return false, fmt.Errorf("humanoid: error during typo simulation: %w", err)
		}
		// If a typo was introduced (e.g., typing and backspacing), we don't need to send the original key.
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

// sendString is a unified, private helper for dispatching key events.
func (h *Humanoid) sendString(ctx context.Context, keys string) error {
	if err := h.executor.SendKeys(ctx, keys); err != nil {
		return err
	}
	// Simulate the key "dwell" time after the key press.
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
	h.mu.Lock()
	cfg := h.dynamicConfig
	randNorm := h.rng.NormFloat64()
	fatigueLevel := h.fatigueLevel
	h.mu.Unlock()

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

// introduceTypo decides which kind of typo to simulate.
func (h *Humanoid) introduceTypo(ctx context.Context, cfg Config, runes []rune, i int) (introduced bool, advanced bool, err error) {
	char := runes[i]
	h.mu.Lock()
	p := h.rng.Float64()
	h.mu.Unlock()

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

// --- Typo Implementations ---

func (h *Humanoid) introduceNeighborTypo(ctx context.Context, char rune) (bool, bool, error) {
	lowerChar := unicode.ToLower(char)
	if neighbors, ok := keyboardNeighbors[lowerChar]; ok && len(neighbors) > 0 {
		h.mu.Lock()
		cfg := h.dynamicConfig
		typoChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		if unicode.IsUpper(char) && h.rng.Float64() < cfg.TypoShiftCorrectionProbability {
			typoChar = unicode.ToUpper(typoChar)
		}
		h.mu.Unlock()

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

	h.mu.Lock()
	cfg := h.dynamicConfig
	shouldCorrect := h.rng.Float64() < cfg.TypoCorrectionProbability
	h.mu.Unlock()

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

	h.mu.Lock()
	cfg := h.dynamicConfig
	shouldNotice := h.rng.Float64() < cfg.TypoOmissionNoticeProbability
	h.mu.Unlock()

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
		h.mu.Lock()
		cfg := h.dynamicConfig
		insertionChar := rune(neighbors[h.rng.Intn(len(neighbors))])
		shouldNotice := h.rng.Float64() < cfg.TypoInsertionNoticeProbability
		h.mu.Unlock()

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
