package sarif

// This file defines the Go structs for the SARIF 2.1.0 standard.
// Pointers are used for optional fields. Required fields use value types.

type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []*Run `json:"runs"`
}

type Run struct {
	Tool    *Tool     `json:"tool"`
	Results []*Result `json:"results"`
}

type Tool struct {
	Driver *ToolComponent `json:"driver"`
}

// ToolComponent describes the tool that produced the results. Pointers are used for optional bits.
type ToolComponent struct {
	Name           string                 `json:"name"`
	Version        *string                `json:"version,omitempty"`
	InformationURI *string                `json:"informationUri,omitempty"`
	Rules          []*ReportingDescriptor `json:"rules,omitempty"`
}

type ReportingDescriptor struct {
	ID               string                    `json:"id"` // Required
	Name             *string                   `json:"name,omitempty"`
	ShortDescription *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
	Help             *MultiformatMessageString `json:"help,omitempty"`
	Properties       *PropertyBag              `json:"properties,omitempty"`
}

type Result struct {
	RuleID    string      `json:"ruleId"` // Required
	Message   *Message    `json:"message"`
	Level     Level       `json:"level,omitempty"`
	Locations []*Location `json:"locations,omitempty"`
}

type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *Message          `json:"message,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
}

type ArtifactLocation struct {
	URI *string `json:"uri,omitempty"`
}

type Message struct {
	Text *string `json:"text,omitempty"`
}

type MultiformatMessageString struct {
	Text     *string `json:"text"`
	Markdown *string `json:"markdown,omitempty"`
}

type PropertyBag map[string]interface{}

type Level string

const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelNote    Level = "note"
)
