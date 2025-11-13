// File: internal/analysis/auth/idor/types.go
package idor

import (
	"fmt"
	"net/http"
	"sync" // Added for IdentifierPool

	// Import the centralized jsoncompare package.
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
)

// Severity defines the severity level of an IDOR finding.
type Severity string

const (
	SeverityCritical Severity = "Critical" // e.g., Unauthenticated access or Horizontal Manipulation.
	SeverityHigh     Severity = "High"     // e.g., Standard Horizontal access.
	SeverityMedium   Severity = "Medium"   // e.g., Vertical Manipulation.
	SeverityLow      Severity = "Low"      // e.g., Resource Enumeration (Oracle) (Strategic 5.6)
)

// AuthArtifacts details the specific headers and cookies used for authentication by a session.
// (Fix 3.1: Dynamic Request Sanitization)
type AuthArtifacts struct {
	// Map keys are the names of the headers (e.g., "Authorization")
	HeaderNames map[string]struct{}
	// Map keys are the names of the cookies (e.g., "session_id")
	CookieNames map[string]struct{}
}

// Session defines a generic interface for an authenticated user session.
type Session interface {
	IsAuthenticated() bool
	ApplyToRequest(req *http.Request)
	// GetAuthArtifacts returns the names of headers and cookies that this session manages.
	GetAuthArtifacts() AuthArtifacts
}

// NilSession implements the Session interface but represents an unauthenticated state.
type NilSession struct{}

// IsAuthenticated always returns false for a NilSession.
func (n *NilSession) IsAuthenticated() bool {
	return false
}

// ApplyToRequest does nothing.
func (n *NilSession) ApplyToRequest(req *http.Request) {}

// GetAuthArtifacts returns empty artifacts.
func (n *NilSession) GetAuthArtifacts() AuthArtifacts {
	return AuthArtifacts{
		HeaderNames: make(map[string]struct{}),
		CookieNames: make(map[string]struct{}),
	}
}

// RequestResponsePair is a data structure that holds a single, complete HTTP transaction.
type RequestResponsePair struct {
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
}

// Config encapsulates all the necessary configuration for running an IDOR analysis.
type Config struct {
	Session       Session // The primary authenticated session (User A).
	SecondSession Session // The secondary authenticated session for horizontal checks (User B).

	// Strategy configuration
	SkipHorizontal      bool // Option to skip standard horizontal checks.
	SkipManipulation    bool // Option to skip manipulation checks.
	SkipUnauthenticated bool // Option to skip unauthenticated checks.
	// (Strategic 5.1: Horizontal Manipulation)
	SkipHorizontalManipulation bool // Option to skip horizontal manipulation checks (Pita test).

	// (Fix 3.2: Safety Configuration)
	AllowUnsafeMethods bool // If true, allows testing of POST, PUT, DELETE, PATCH. Default is false.

	ComparisonOptions jsoncompare.Options // Defines how JSON responses are normalized and compared.
	ConcurrencyLevel  int                 // The number of concurrent workers for replaying requests.
	HttpClient        *http.Client        // The HTTP client to use for replaying requests.
}

// Finding represents a single, potential IDOR vulnerability discovered by the analyzer.
type Finding struct {
	URL               string
	Method            string
	Evidence          string
	Severity          Severity
	TestType          string // e.g., "Horizontal", "Manipulation", "Unauthenticated", "HorizontalManipulation", "ResourceEnumeration"
	StatusCode        int
	Identifier        *ObservedIdentifier           // Details about the identifier that was manipulated.
	TestedValue       string                        // The value used to replace the original identifier.
	ComparisonDetails *jsoncompare.ComparisonResult // The detailed result from the JSON comparison.
}

// --- Types related to Identifier Extraction (for Manipulation strategy) ---

// IdentifierType enumerates the kinds of resource identifiers that the analyzer can detect.
type IdentifierType string

const (
	TypeNumericID IdentifierType = "NumericID"
	TypeUUID      IdentifierType = "UUID"
	TypeHash      IdentifierType = "Hash" // MD5, SHA1, SHA256
	// (Strategic 5.3: Expanded Identifier Types)
	TypeEmail    IdentifierType = "Email"
	TypeUsername IdentifierType = "Username"
	TypeULID     IdentifierType = "ULID"
)

// IdentifierLocation specifies the part of an HTTP request where an identifier was discovered.
type IdentifierLocation string

const (
	LocationURLPath    IdentifierLocation = "URLPath"
	LocationQueryParam IdentifierLocation = "QueryParam"
	LocationJSONBody   IdentifierLocation = "JSONBody"
	LocationXMLBody    IdentifierLocation = "XMLBody"
	LocationFormBody   IdentifierLocation = "FormBody" // URL-encoded or Multipart
	LocationHeader     IdentifierLocation = "Header"
	LocationCookie     IdentifierLocation = "Cookie"
	// (Strategic 5.3: Added location for encoded payloads)
	LocationEncodedPayload IdentifierLocation = "EncodedPayload"
)

// ObservedIdentifier is a detailed record of a potential resource identifier found within an HTTP request.
type ObservedIdentifier struct {
	Value     string
	Type      IdentifierType
	Location  IdentifierLocation
	Key       string // The parameter name, JSON path, XPath, or encoded payload locator.
	PathIndex int    // The index in the URL path.

	// (Strategic 5.3) Fields for encoded payloads
	IsEncoded      bool               // Flag indicating if this ID was found within an encoded structure.
	EncodingType   string             // e.g., "Base64JSON", "JWT"
	ParentLocation IdentifierLocation // Where the encoded payload itself was located (e.g., Header)
	ParentKey      string             // The key of the encoded payload
}

func (o ObservedIdentifier) String() string {
	// Enhanced string representation for encoded identifiers
	if o.IsEncoded {
		return fmt.Sprintf("%s in %s[%s] at %s (%s)", o.EncodingType, o.ParentLocation, o.ParentKey, o.Key, o.Type)
	}
	switch o.Location {
	case LocationURLPath:
		return fmt.Sprintf("Path[%d] (%s)", o.PathIndex, o.Type)
	default:
		return fmt.Sprintf("%s: %s (%s)", o.Location, o.Key, o.Type)
	}
}

// --- Identifier Pool Implementation (Strategic 5.2) ---

// IdentifierPool stores unique observed identifiers categorized by type for realistic manipulation tests.
type IdentifierPool struct {
	pool map[IdentifierType]map[string]struct{}
	mu   sync.RWMutex
}

func NewIdentifierPool() *IdentifierPool {
	return &IdentifierPool{
		pool: make(map[IdentifierType]map[string]struct{}),
	}
}

// Add inserts a new identifier into the pool.
func (p *IdentifierPool) Add(ident ObservedIdentifier) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.pool[ident.Type]; !ok {
		p.pool[ident.Type] = make(map[string]struct{})
	}
	p.pool[ident.Type][ident.Value] = struct{}{}
}

// GetDifferent returns a known-valid identifier of the same type that is different from the provided value.
func (p *IdentifierPool) GetDifferent(idType IdentifierType, currentValue string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if values, ok := p.pool[idType]; ok {
		// Iterate (non-deterministically) until a different value is found.
		for value := range values {
			if value != currentValue {
				return value, true
			}
		}
	}
	return "", false
}

// Count returns the total number of unique identifiers in the pool.
func (p *IdentifierPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, values := range p.pool {
		count += len(values)
	}
	return count
}
