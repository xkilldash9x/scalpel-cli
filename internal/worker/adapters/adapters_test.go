package adapters_test

import (
	"bytes"
	"io"
	"net/http"
)

// MockTransport is a shared mock for simulating network behavior in adapter tests.
type MockTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

// RoundTrip implements the http.RoundTripper interface.
func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the body before reading, as http.Request.Body can only be read once.
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body
	}
	return m.RoundTripFunc(req)
}

// newMockClient is a helper to create an http.Client with a mock transport.
func newMockClient(fn func(req *http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{Transport: &MockTransport{RoundTripFunc: fn}}
}
