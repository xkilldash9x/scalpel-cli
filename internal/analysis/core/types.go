package core

import (
	"net/http"
	// Removed imports time and github.com/google/uuid as they are no longer used.

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Identifier Definitions --

// IdentifierType provides a classification for different kinds of resource
// identifiers found in HTTP requests, such as numeric IDs or UUIDs.
type IdentifierType string

// IdentifierLocation specifies the exact part of an HTTP request where an
// identifier was discovered.
type IdentifierLocation string

const (
	TypeUnknown   IdentifierType = "Unknown"
	TypeNumericID IdentifierType = "NumericID"
	TypeUUID      IdentifierType = "UUID"
	TypeObjectID  IdentifierType = "ObjectID" // e.g., MongoDB ObjectID
	TypeBase64    IdentifierType = "Base64"
)

const (
	LocationURLPath    IdentifierLocation = "URLPath"
	LocationQueryParam IdentifierLocation = "QueryParam"
	LocationJSONBody   IdentifierLocation = "JSONBody"
	LocationHeader     IdentifierLocation = "Header"
)

// ObservedIdentifier provides a structured representation of a potential
// resource identifier discovered within an HTTP request, detailing its value,
// type, and precise location.
type ObservedIdentifier struct {
	Value     string
	Type      IdentifierType
	Location  IdentifierLocation
	Key       string // The key for headers, query params, or the JSON path.
	PathIndex int    // The index for URL path segments.
}

// -- General Analysis Definitions --

// Removed deprecated types: SeverityLevel, Status, AnalysisResult, Evidence.
// Analyzers should use the canonical schemas defined in api/schemas.

// SerializedResponse provides a JSON-safe representation of an HTTP response,
// intended for embedding within the `Evidence` field of a finding. It ensures
// the response body is stored as a string.
type SerializedResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
}

// Reporter defines a standard, thread-safe interface for components that can
// publish the results of an analysis, such as writing them to a database or a file.
type Reporter interface {
	// Write takes a `ResultEnvelope`, which can contain findings and/or
	// knowledge graph updates, and persists it.
	Write(envelope *schemas.ResultEnvelope) error
}