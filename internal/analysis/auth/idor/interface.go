package idor

// Analyzer is the interface that defines an IDOR vulnerability scanner.
// It provides a method to execute the analysis against a given set of HTTP traffic.
type Analyzer interface {
	// AnalyzeTraffic takes a slice of HTTP requests and responses, along with a configuration,
	// and returns a slice of IDOR findings.
	AnalyzeTraffic(traffic []RequestResponsePair, config Config) ([]Finding, error)
}