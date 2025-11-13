// File: internal/analysis/auth/idor/types.go
package idor

import (
	"fmt"
	"net/http"

	// Import the centralized jsoncompare package.
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
)

// Severity defines the severity level of an IDOR finding.
type Severity string

const (
	SeverityCritical Severity = "Critical" // Used when resources are accessible without authentication.
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
)

// Session defines a generic interface for an authenticated user session. It
// provides a way to check if the session is authenticated and to apply the
// session's authentication details (e.g., cookies, headers) to an HTTP request.
type Session interface {
	IsAuthenticated() bool
	ApplyToRequest(req *http.Request)
}

// NilSession implements the Session interface but represents an unauthenticated state.
type NilSession struct{}

// IsAuthenticated always returns false for a NilSession.
func (n *NilSession) IsAuthenticated() bool {
	return false
}

// ApplyToRequest does nothing. The request preparation logic ensures existing auth tokens are removed.
func (n *NilSession) ApplyToRequest(req *http.Request) {}

// RequestResponsePair is a data structure that holds a single, complete HTTP
// transaction, including the raw request and response bodies.
type RequestResponsePair struct {
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
}

// Config encapsulates all the necessary configuration for running an IDOR
// analysis, including authenticated sessions, comparison options, and concurrency settings.
type Config struct {
	Session       Session // The primary authenticated session (User A).
	SecondSession Session // The secondary authenticated session for horizontal checks (User B).

	// Strategy configuration
	SkipHorizontal      bool // Option to skip horizontal checks.
	SkipManipulation    bool // Option to skip manipulation checks.
	SkipUnauthenticated bool // Option to skip unauthenticated checks.

	ComparisonOptions jsoncompare.Options // Defines how JSON responses are normalized and compared.
	ConcurrencyLevel  int                 // The number of concurrent workers for replaying requests.
	HttpClient        *http.Client        // The HTTP client to use for replaying requests.
}

// Finding represents a single, potential IDOR vulnerability discovered by the
// analyzer.
type Finding struct {
	URL               string
	Method            string
	Evidence          string
	Severity          Severity
	TestType          string // e.g., "Horizontal", "Manipulation", "Unauthenticated"
	StatusCode        int
	Identifier        *ObservedIdentifier           // Details about the identifier that was manipulated.
	TestedValue       string                        // The value used to replace the original identifier.
	ComparisonDetails *jsoncompare.ComparisonResult // The detailed result from the JSON comparison.
}

// --- Types related to Identifier Extraction (for Manipulation strategy) ---

// IdentifierType enumerates the kinds of resource identifiers that the analyzer
// can detect.
type IdentifierType string

const (
	TypeNumericID IdentifierType = "NumericID"
	TypeUUID      IdentifierType = "UUID"
	TypeHash      IdentifierType = "Hash" // MD5, SHA1, SHA256
)

// IdentifierLocation specifies the part of an HTTP request where an identifier
// was discovered.
type IdentifierLocation string

const (
	LocationURLPath    IdentifierLocation = "URLPath"
	LocationQueryParam IdentifierLocation = "QueryParam"
	LocationJSONBody   IdentifierLocation = "JSONBody"
	LocationXMLBody    IdentifierLocation = "XMLBody"
	LocationFormBody   IdentifierLocation = "FormBody" // URL-encoded or Multipart
	LocationHeader     IdentifierLocation = "Header"
	LocationCookie     IdentifierLocation = "Cookie"
)

// ObservedIdentifier is a detailed record of a potential resource identifier
// found within an HTTP request.
type ObservedIdentifier struct {
	Value     string
	Type      IdentifierType
	Location  IdentifierLocation
	Key       string // The parameter name (Query/Header/Form/Cookie), JSON path (e.g., "data.items[0].id"), or XPath.
	PathIndex int    // The index in the URL path (e.g., for "/users/123", the index is 1).
}

func (o ObservedIdentifier) String() string {
	switch o.Location {
	case LocationURLPath:
		return fmt.Sprintf("Path[%d] (%s)", o.PathIndex, o.Type)
	default:
		return fmt.Sprintf("%s: %s (%s)", o.Location, o.Key, o.Type)
	}
}
