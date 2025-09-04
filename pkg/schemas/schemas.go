package schemas

import "time"

// Node represents a fundamental entity in the knowledge graph, such as a web page,
// a JavaScript function, or a piece of infrastructure. It's the core building block
// for representing the system under analysis.
type Node struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Label      string                 `json:"label"`
	Status     string                 `json:"status"`
	CreatedAt  time.Time              `json:"created_at"`
	LastSeen   time.Time              `json:"last_seen"`
	Properties map[string]interface{} `json:"properties"`
}

// Edge represents a relationship or connection between two Nodes in the knowledge graph.
// It could signify anything from a hyperlink between pages to a data flow relationship
// between a source and a sink.
type Edge struct {
	ID         string                 `json:"id"`
	From       string                 `json:"from"`
	To         string                 `json:"to"`
	Type       string                 `json:"type"`
	Label      string                 `json:"label"`
	CreatedAt  time.Time              `json:"created_at"`
	LastSeen   time.Time              `json:"last_seen"`
	Properties map[string]interface{} `json:"properties"`
}

// Finding represents a security finding or a result from a scan. I've reconstructed
// this struct based on its usage in the results package. You may need to adjust
// its fields to match your original definition perfectly.
type Finding struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Confidence  string                 `json:"confidence"`
	Location    string                 `json:"location"`
	Properties  map[string]interface{} `json:"properties"`
	CreatedAt   time.Time              `json:"created_at"`
}
