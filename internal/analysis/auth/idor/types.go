// File: internal/analysis/auth/idor/types.go
package idor

import (
	"fmt"
	"net/http"

	// Import the centralized jsoncompare package.
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
)

// Severity levels for findings.
type Severity string

const (
	SeverityHigh   Severity = "High"
	SeverityMedium Severity = "Medium"
	// Other levels (Low, Info, Critical) can be added as needed.
)

// Session defines the interface for an authenticated user session.
type Session interface {
	IsAuthenticated() bool
	ApplyToRequest(req *http.Request)
}

// RequestResponsePair holds a matched HTTP request and its response, including raw bodies.
type RequestResponsePair struct {
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
}

// Config holds the configuration for the IDOR analysis.
type Config struct {
	// Session (User A) used for baseline requests and manipulation checks.
	Session Session
	// SecondSession (User B) used for horizontal bypass checks.
	SecondSession Session
	// ComparisonOptions defines how to normalize and compare responses.
	// This allows the IDOR analyzer to specify preferences to the jsoncompare service.
	// Renamed from ComparisonRules/HeuristicRules.
	ComparisonOptions jsoncompare.Options
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
	// Details regarding the comparison result.
	// Renamed from ComparisonDetails/ResponseComparisonResult.
	ComparisonDetails *jsoncompare.ComparisonResult
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
