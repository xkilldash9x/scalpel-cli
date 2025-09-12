package core

import (
	"net/http"
	// Removed imports time and github.com/google/uuid as they are no longer used.

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Identifier Definitions --
// These types can be shared across multiple analyzers. Just makes sense.

// IdentifierType represents the classified type of an observed identifier.
type IdentifierType string

// IdentifierLocation specifies where in the HTTP request an identifier was found.
type IdentifierLocation string

const (
	TypeUnknown   IdentifierType = "Unknown"
	TypeNumericID IdentifierType = "NumericID"
	TypeUUID      IdentifierType = "UUID"
	TypeObjectID  IdentifierType = "ObjectID"
	TypeBase64    IdentifierType = "Base64"
)

const (
	LocationURLPath    IdentifierLocation = "URLPath"
	LocationQueryParam IdentifierLocation = "QueryParam"
	LocationJSONBody   IdentifierLocation = "JSONBody"
	LocationHeader     IdentifierLocation = "Header"
)

// ObservedIdentifier holds detailed information about a single identifier extracted from a request.
type ObservedIdentifier struct {
	Value     string
	Type      IdentifierType
	Location  IdentifierLocation
	Key       string // Used for headers, query params, and JSON keys.
	PathIndex int    // Used for URL path segments.
}

// -- General Analysis Definitions --

// Removed deprecated types: SeverityLevel, Status, AnalysisResult, Evidence.
// Analyzers should use the canonical schemas defined in api/schemas.

// SerializedResponse is a structure used for embedding HTTP responses in findings evidence.
// It ensures the body is a string (potentially truncated) for safe JSON serialization.
type SerializedResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
}

// Reporter is the interface for publishing analysis results.
// Implementations MUST be safe for concurrent use by multiple goroutines.
type Reporter interface {
	// Write accepts a ResultEnvelope containing Findings and/or KGUpdates.
	Write(envelope *schemas.ResultEnvelope) error
}