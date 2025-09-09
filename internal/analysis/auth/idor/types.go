package idor

import "net/http"

// Session defines the interface for an authenticated user session.
// This allows the analyzer to apply session details (like cookies or headers) to a request.
type Session interface {
	// IsAuthenticated should return true if the session represents a logged-in user.
	IsAuthenticated() bool
	// ApplyToRequest modifies an *http.Request to use the session's authentication credentials.
	ApplyToRequest(req *http.Request)
}

// RequestResponsePair holds a matched HTTP request and its corresponding response.
type RequestResponsePair struct {
	Request  *http.Request
	Response *http.Response
}

// Config holds the configuration for the IDOR analysis.
type Config struct {
	// ParametersToTest specifies a list of request parameters to specifically target for IDOR checks.
	ParametersToTest []string
	// Session represents the authenticated user session to use for baseline requests.
	Session Session
	// SecondSession represents a different authenticated user session to test for authorization bypass.
	SecondSession Session
}

// Finding represents a potential IDOR vulnerability that has been identified.
type Finding struct {
	// URL is the endpoint where the vulnerability was found.
	URL string
	// Parameter is the specific parameter that appears to be vulnerable.
	Parameter string
	// OriginalValue is the parameter value from the original authenticated request.
	OriginalValue string
	// TestedValue is the parameter value from the second session that illicitly accessed the resource.
	TestedValue string
	// Method is the HTTP method used (e.g., "GET", "POST").
	Method string
	// Evidence provides a brief description of why this is considered a finding.
	Evidence string
}