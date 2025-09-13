// internal/network/parser_test.go
package network

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// -- Test Cases: Parsing Logic --

// TestParseResponseHeaders verifies that headers are correctly extracted and mapped.
func TestParseResponseHeaders(t *testing.T) {
	// A table of test cases for our parsing function.
	testCases := []struct {
		name string
		headers http.Header
		expected map[string]string
	}{
		{
			name: "single header",
			headers: http.Header{
				"Content-Type": {"application/json"},
			},
			expected: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name: "multiple headers",
			headers: http.Header{
				"Content-Type": {"text/html"},
				"Cache-Control": {"no-cache"},
				"X-Custom-Header": {"some-value"},
			},
			expected: map[string]string{
				"Content-Type": "text/html",
				"Cache-Control": "no-cache",
				"X-Custom-Header": "some-value",
			},
		},
		{
			name: "header with multiple values",
			headers: http.Header{
				"Set-Cookie": {"session=abc", "locale=en-US"},
			},
			// In our parsing function, we'll assume we only care about the first value.
			expected: map[string]string{
				"Set-Cookie": "session=abc",
			},
		},
		{
			name: "empty headers",
			headers: http.Header{},
			expected: map[string]string{},
		},
		{
			name: "nil headers",
			headers: nil,
			expected: map[string]string{},
		},
		{
			name: "header key case insensitivity",
			headers: http.Header{
				"content-type": {"application/xml"},
			},
			expected: map[string]string{
				"content-type": "application/xml",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// A hypothetical parsing function that you would implement.
			// This function would take http.Header and return a simplified map.
			// Let's assume it looks something like this:
			// func ParseHeaders(headers http.Header) map[string]string { ... }
			// For this example, we'll implement it inline to demonstrate the logic.
			
			parsedHeaders := make(map[string]string)
			if tc.headers != nil {
				for key, values := range tc.headers {
					if len(values) > 0 {
						parsedHeaders[key] = values[0]
					}
				}
			}

			assert.Equal(t, tc.expected, parsedHeaders, "Parsed headers should match expected output")
		})
	}
}

// TestParseStatusCode verifies that the HTTP status code is correctly identified.
func TestParseStatusCode(t *testing.T) {
	// This test would check a function that extracts the status code.
	t.Run("valid status code", func(t *testing.T) {
		// Hypothetical function: ParseStatusCode(resp *http.Response) int
		// Let's create a mock response.
		resp := &http.Response{StatusCode: http.StatusOK}
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("client error status code", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusNotFound}
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
	
	t.Run("redirect status code", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusFound}
		assert.Equal(t, http.StatusFound, resp.StatusCode)
	})
}