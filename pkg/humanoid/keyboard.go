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
	var modifiers input.Modifier // CORRECTED: Use the correct type
	// Basic shift detection.
	if needsShift(key) {
		modifiers = input.ModifierShift // CORRECTED: Use the correct constant
	}

	// Attempt to find VK code, fallback if not found.
	keyCode, ok := keyToVK[unicode.ToLower(key)]
	if !ok {
		// If VK code isn't mapped, we rely on the browser interpreting the 'Key' field.
		h.logger.Debug("Humanoid: Virtual Key code not mapped for rune", zap.String("rune", string(key)))
	}

	// 1. KeyDown
	// Determine the event type. Use input.KeyDown for characters which generates input events.
	downType := input.KeyEventTypeRawKeyDown 
	// Check if it's a standard printable character.
	if unicode.IsPrint(key) {
		downType = input.KeyEventTypeKeyDown 
	}

	downEvent := input.DispatchKeyEvent(downType).
		WithModifiers(modifiers).
		WithWindowsVirtualKeyCode(keyCode).
		WithKey(text)

	//   if it's a character input event like up or down then this
	if downType == input.KeyEventTypeKeyDown { // CORRECTED: Use correct constant name
		downEvent = downEvent.WithText(text)
	}

	if err := downEvent.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: keydown failed for '%c': %w", key, err)
	}

	// 2. biometric timing   
	if err := h.keyHoldPause(ctx); err != nil {
		// Ensure KeyUp happens even if pause is interrupted.
		input.DispatchKeyEvent(input.KeyEventTypeKeyUp).WithModifiers(modifiers).WithWindowsVirtualKeyCode(keyCode).WithKey(text).Do(context.Background())
		return err
	}

	// 3. key'd up
	upEvent := input.DispatchKeyEvent(input.KeyEventTypeKeyUp). 
								WithModifiers(modifiers).
								WithWindowsVirtualKeyCode(keyCode).
								WithKey(text)

	if err := upEvent.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: keyup failed for '%c': %w", key, err)
	}

	return nil
}
// (The rest of the file remains the same)
// ...
