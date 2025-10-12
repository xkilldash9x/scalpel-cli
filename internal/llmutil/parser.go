// internal/llmutil/parser.go
package llmutil

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	// Regex definitions use \x60 (hex representation) for backticks because Go raw strings cannot contain backticks.

	// jsonObjectRegex extracts a JSON object if the response is wrapped in markdown.
	jsonObjectRegex = regexp.MustCompile("(?s)\x60\x60\x60(?:json)?\\s*({.*})\\s*\x60\x60\x60")
	// jsonArrayRegex extracts a JSON array if the response is wrapped in markdown.
	jsonArrayRegex = regexp.MustCompile("(?s)\x60\x60\x60(?:json)?\\s*(\\[.*\\])\\s*\x60\x60\x60")

	// codeBlockRegex extracts content wrapped in markdown, supporting various language tags (diff, patch, go, etc.).
	codeBlockRegex = regexp.MustCompile("(?s)\x60\x60\x60[a-zA-Z]*\\s*(.*?)\\s*\x60\x60\x60")
)

// ParseJSONResponse attempts to parse an LLM response string into a target Go type using generics.
// It handles common LLM formatting issues, such as wrapping the JSON in markdown code blocks.
func ParseJSONResponse[T any](response string) (*T, error) {
	response = strings.TrimSpace(response)
	jsonStringToParse := response

	// Heuristically determine if the content is likely an object or array.
	isObject := strings.Contains(response, "{")
	isArray := strings.Contains(response, "[")

	// 1. Handle markdown wrapping (most common case).
	if strings.HasPrefix(response, "```") {
		var matches []string
		// Prioritize object regex if it looks like an object.
		if isObject {
			matches = jsonObjectRegex.FindStringSubmatch(response)
		}
		// If object regex didn't match or it's clearly an array, try array regex.
		if len(matches) <= 1 && isArray {
			matches = jsonArrayRegex.FindStringSubmatch(response)
		}

		if len(matches) > 1 {
			jsonStringToParse = matches[1]
		}
	} else if (isObject || isArray) && (!strings.HasPrefix(response, "{") && !strings.HasPrefix(response, "[")) {
		// 2. Attempt to find the structure within conversational text.
		firstBracket := -1
		lastBracket := -1

		// Try finding object boundaries.
		if isObject {
			fb := strings.Index(response, "{")
			lb := strings.LastIndex(response, "}")
			if fb != -1 && lb != -1 && lb > fb {
				firstBracket = fb
				lastBracket = lb + 1
			}
		}

		// If object detection failed or it's primarily an array, try array boundaries.
		if (firstBracket == -1 || lastBracket == -1) && isArray {
			fb := strings.Index(response, "[")
			lb := strings.LastIndex(response, "]")
			if fb != -1 && lb != -1 && lb > fb {
				firstBracket = fb
				lastBracket = lb + 1
			}
		}

		if firstBracket != -1 && lastBracket != -1 {
			jsonStringToParse = response[firstBracket:lastBracket]
		}
	}

	// 3. Unmarshal
	var result T
	if err := json.Unmarshal([]byte(jsonStringToParse), &result); err != nil {
		// Provide a detailed error message including the extracted JSON snippet.
		return nil, fmt.Errorf("failed to unmarshal LLM JSON response: %w. Extracted JSON (truncated): %s", err, truncateString(jsonStringToParse, 500))
	}

	return &result, nil
}

// CleanCodeOutput removes common markdown artifacts (like ```go or ```diff) from a code or patch string.
func CleanCodeOutput(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		matches := codeBlockRegex.FindStringSubmatch(content)
		if len(matches) > 1 {
			// Normalize the content: trim whitespace.
			cleaned := strings.TrimSpace(matches[1])

			// Specific handling for patches: ensure one trailing newline, required by 'git apply'.
			if strings.Contains(cleaned, "--- a/") && strings.Contains(cleaned, "+++ b/") {
				return cleaned + "\n"
			}
			return cleaned
		}
	}
	return content
}

// truncateString truncates a string to a maximum length.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 0 {
		return ""
	}
	if len(s) > maxLen {
		// Simple truncation; does not account for rune boundaries but sufficient for error logging.
		return s[:maxLen] + "..."
	}
	return s
}
