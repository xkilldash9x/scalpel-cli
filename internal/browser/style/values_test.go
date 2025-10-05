package style

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseColor(t *testing.T) {
	tests := []struct {
		input    string
		expected Color
		ok       bool
	}{
		// Keywords
		{"red", Color{R: 255, G: 0, B: 0, A: 255}, true},
		{"transparent", Color{R: 0, G: 0, B: 0, A: 0}, true},
		// Hex
		{"#ff0099", Color{R: 0xff, G: 0x00, B: 0x99, A: 255}, true},
		{"#f09", Color{R: 0xff, G: 0x00, B: 0x99, A: 255}, true},
		{"#ff009988", Color{R: 0xff, G: 0x00, B: 0x99, A: 0x88}, true},
		// RGB/RGBA
		{"rgb(255, 0, 153)", Color{R: 255, G: 0, B: 153, A: 255}, true},
		// 0.5 * 255 = 127.5. The implementation uses strconv.ParseFloat and clamps/rounds (+0.5), resulting in 128.
		{"rgba(0, 0, 0, 0.5)", Color{R: 0, G: 0, B: 0, A: 128}, true},
		{"rgb(100%, 50%, 0%)", Color{R: 255, G: 128, B: 0, A: 255}, true}, // 50% rounds up
		// Invalid
		{"invalidcolor", Color{A: 255}, false},
		{"#12345", Color{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			actual, ok := ParseColor(tt.input)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}

func TestParseLengthWithUnits(t *testing.T) {
	parentFontSize, rootFontSize, refDim, vw, vh := 20.0, 16.0, 100.0, 1000.0, 800.0

	tests := []struct {
		input    string
		expected float64
	}{
		{"10px", 10.0},
		{"1.5em", 30.0},  // 1.5 * 20
		{"2rem", 32.0},   // 2 * 16
		{"50%", 50.0},    // 0.5 * 100
		{"10vw", 100.0},  // 0.1 * 1000
		{"5vh", 40.0},    // 0.05 * 800
		{"5vmin", 40.0},  // min(1000, 800) * 0.05
		{"10vmax", 100.0}, // max(1000, 800) * 0.1
		{"auto", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			actual := ParseLengthWithUnits(tt.input, parentFontSize, rootFontSize, refDim, vw, vh)
			assert.InDelta(t, tt.expected, actual, 0.001)
		})
	}
}

// Test internal parseFloat (White-box testing)
func TestInternalParseFloat(t *testing.T) {
	tests := []struct {
		input string
		expected float64
		isErr bool
	}{
		{"10.5", 10.5, false},
		{"-5", -5.0, false},
		{"+2.5e", 2.5, false}, // Stops parsing at 'e'
		{"", 0.0, true},
		{"abc", 0.0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			actual, err := parseFloat(tt.input)
			if tt.isErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}