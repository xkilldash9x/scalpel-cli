// types.go
package idor

import (
	"fmt"
	"net/http"
	"regexp"
)

// Severity levels for findings.
type Severity string

const (
	SeverityHigh   Severity = "High"
	SeverityMedium Severity = "Medium"
	// Other levels (Low, Info, Critical) can be added as needed.
)

// Session defines the interface for an authenticated user session.
// This allows the analyzer to apply session details (like cookies or headers) to a request.
type Session interface {
	// IsAuthenticated should return true if the session represents a logged-in user.
	IsAuthenticated() bool
	// ApplyToRequest modifies an *http.Request to use the session's authentication credentials.
	ApplyToRequest(req *http.Request)
}

// RequestResponsePair holds a matched HTTP request and its response, including raw bodies.
// Storing bodies as []byte is essential for repeatable analysis and comparison.
type RequestResponsePair struct {
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
}

// HeuristicRules defines the set of rules for identifying dynamic data in responses.
type HeuristicRules struct {
	KeyPatterns              []*regexp.Regexp
	CheckValueForUUID        bool
	CheckValueForTimestamp   bool
	CheckValueForHighEntropy bool
	// EntropyThreshold defines the minimum Shannon entropy (bits per character) to be considered dynamic.
	EntropyThreshold float64
	// IgnoreArrayOrder determines if the order of elements in arrays should matter during comparison.
	IgnoreArrayOrder bool

	// SpecificValuesToIgnore is used internally during Manipulation tests to normalize the tested identifiers.
	// It allows structural comparison even when the resource data differs.
	SpecificValuesToIgnore map[string]struct{}
	// NormalizeAllValuesForStructure indicates that all primitive values (leaf nodes) should be normalized
	// to focus purely on the structure (keys, nesting) of the JSON. Used for Manipulation tests.
	NormalizeAllValuesForStructure bool
}

// DeepCopy creates a concurrency-safe copy of the HeuristicRules.
func (h HeuristicRules) DeepCopy() HeuristicRules {
	copy := h
	// Copy slices/maps to ensure isolation between concurrent comparisons.
	copy.KeyPatterns = append([]*regexp.Regexp(nil), h.KeyPatterns...)
	copy.SpecificValuesToIgnore = make(map[string]struct{})
	// Although the map is usually empty in the base config, we copy it defensively.
	for k, v := range h.SpecificValuesToIgnore {
		copy.SpecificValuesToIgnore[k] = v
	}
	return copy
}

// Config holds the configuration for the IDOR analysis.
type Config struct {
	// Session (User A) used for baseline requests and manipulation checks.
	Session Session
	// SecondSession (User B) used for horizontal bypass checks.
	SecondSession Session
	// ComparisonRules defines how to normalize and compare responses for equivalence.
	ComparisonRules HeuristicRules
	// ConcurrencyLevel defines the number of concurrent workers for replaying requests.
	ConcurrencyLevel int
	// HttpClient is the client used to replay requests. Should be configured externally or defaults will be applied.
	HttpClient *http.Client
}

// Finding represents a potential IDOR vulnerability that has been identified.
type Finding struct {
	URL        string
	Method     string
	Evidence   string
	Severity   Severity
	TestType   string // "Horizontal" or "Manipulation"
	StatusCode int
	// Details specific to Manipulation checks
	Identifier  *ObservedIdentifier
	TestedValue string
	// Details regarding the comparison result (useful for debugging normalization)
	ComparisonDetails *ResponseComparisonResult
}

// --- Types related to Identifier Extraction (for Manipulation strategy) ---

// IdentifierType distinguishes between different kinds of identifiers.
type IdentifierType string

const (
	TypeNumericID IdentifierType = "NumericID"
	TypeUUID      IdentifierType = "UUID"
)

// IdentifierLocation specifies where in the request the identifier was found.
type IdentifierLocation string

const (
	LocationURLPath    IdentifierLocation = "URLPath"
	LocationQueryParam IdentifierLocation = "QueryParam"
	LocationJSONBody   IdentifierLocation = "JSONBody"
	LocationHeader     IdentifierLocation = "Header"
)

// ObservedIdentifier represents a potential ID that was observed in the traffic.
type ObservedIdentifier struct {
	Value    string
	Type     IdentifierType
	Location IdentifierLocation
	// Key is the parameter name (Query/Header) or JSON path (JSONBody, e.g., data.items[0].id).
	Key string
	// PathIndex is the index in the URL path (e.g., /users/123 -> index 1).
	PathIndex int
}

func (o ObservedIdentifier) String() string {
	switch o.Location {
	case LocationURLPath:
		return fmt.Sprintf("Path[%d] (%s)", o.PathIndex, o.Type)
	default:
		return fmt.Sprintf("%s: %s (%s)", o.Location, o.Key, o.Type)
	}
}
