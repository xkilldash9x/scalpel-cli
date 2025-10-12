// internal/jsoncompare/heuristics.go
package jsoncompare

import (
	"regexp"
	"time"
)

// Placeholders for normalized data.
const (
	PlaceholderDynamicKey   = "__DYNAMIC_KEY__"
	PlaceholderDynamicValue = "__DYNAMIC_VALUE__"
)

// HeuristicRules defines the configurable set of rules for identifying dynamic data.
type HeuristicRules struct {
	// KeyPatterns identifies map keys that are likely dynamic (e.g., "session_id").
	KeyPatterns []*regexp.Regexp
	// CheckValueForUUID enables detection of UUIDs in string values.
	CheckValueForUUID bool
	// CheckValueForTimestamp enables detection of timestamps (strings or numbers).
	CheckValueForTimestamp bool
	// TimestampFormats defines the layouts to try when parsing string timestamps.
	TimestampFormats []string
	// CheckValueForHighEntropy enables detection of high-entropy strings (e.g., tokens).
	CheckValueForHighEntropy bool
	// EntropyThreshold defines the minimum Shannon entropy to classify a string as dynamic.
	EntropyThreshold float64
}

// DefaultRules provides a sensible default configuration for common dynamic data.
func DefaultRules() HeuristicRules {
	keyPatterns := []*regexp.Regexp{
		// Common session/token patterns
		regexp.MustCompile(`(?i)sess(ion)?_?(id|key|token)?`),
		regexp.MustCompile(`(?i)(api|access|refresh|auth)_?token$`),
		regexp.MustCompile(`(?i)^(csrf|xsrf)`),
		regexp.MustCompile(`(?i)nonce`),
		// Correlation/Request IDs
		regexp.MustCompile(`(?i)(correlation|request|trace|tracking)_?id`),
		// Pattern to catch keys with dynamic suffixes/prefixes (e.g., "session_abc").
		regexp.MustCompile(`(?i)^session_[a-zA-Z0-9_-]+$`),
	}

	return HeuristicRules{
		KeyPatterns:            keyPatterns,
		CheckValueForUUID:      true,
		CheckValueForTimestamp: true,
		// Common formats including ISO 8601 variants.
		TimestampFormats:         []string{time.RFC3339, time.RFC3339Nano, time.RFC822, "2006-01-02T15:04:05.000Z"},
		CheckValueForHighEntropy: true,
		EntropyThreshold:         4.5, // Recommended threshold for high-entropy tokens.
	}
}
