// interface.go
package idor

import "context"

// Analyzer defines the standard interface for an IDOR (Insecure Direct Object
// Reference) vulnerability scanner. It abstracts the underlying implementation of
// the analysis logic.
type Analyzer interface {
	// AnalyzeTraffic orchestrates the IDOR detection process. It takes a context
	// for cancellation, a slice of captured HTTP request-response pairs, and a
	// configuration object. It returns a slice of any discovered findings and an
	// error if the analysis could not be completed.
	AnalyzeTraffic(ctx context.Context, traffic []RequestResponsePair, config Config) ([]Finding, error)
}
