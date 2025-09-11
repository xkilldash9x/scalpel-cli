package core

import (
	"time"

	"github.com/google/uuid"
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

// SeverityLevel defines the severity of a finding.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "Critical"
	SeverityHigh     SeverityLevel = "High"
	SeverityMedium   SeverityLevel = "Medium"
	SeverityLow      SeverityLevel = "Low"
	SeverityInfo     SeverityLevel = "Info"
)

// Status defines the status of a finding.
type Status string

const (
	StatusOpen   Status = "Open"
	StatusClosed Status = "Closed"
)

// AnalysisResult represents a finding discovered during active analysis.
type AnalysisResult struct {
	ScanID            uuid.UUID
	AnalyzerName      string
	Timestamp         time.Time
	VulnerabilityType string
	Title             string
	Description       string
	Severity          SeverityLevel
	Status            Status
	Confidence        float64
	TargetURL         string
	Evidence          *Evidence
	CWE               string
}

// Evidence struct (required by ato/models.go provided in the prompt)
type Evidence struct {
	Details  string
	Request  string
	Response string
}

// Reporter is the interface for publishing analysis results.
// Implementations MUST be safe for concurrent use by multiple goroutines.
type Reporter interface {
	Publish(finding AnalysisResult) error
}
