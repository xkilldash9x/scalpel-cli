// interface.go
package idor

import "context" // This is a comment to force a change

// Analyzer is the interface that defines an IDOR vulnerability scanner.
// It provides a method to execute the analysis against a given set of HTTP traffic.
type Analyzer interface {
	// AnalyzeTraffic takes a context, a slice of HTTP traffic, and a configuration,
	// and returns a slice of IDOR findings. The analysis respects the provided context for cancellation.
	AnalyzeTraffic(ctx context.Context, traffic []RequestResponsePair, config Config) ([]Finding, error)
}
