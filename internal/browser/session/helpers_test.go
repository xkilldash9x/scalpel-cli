package session

import (
    "io"
    "net/http"
)

// -- Mock HTTP Transport --

// mockTransport is a simple http.RoundTripper implementation for testing.
type mockTransport struct {
    handler func(*http.Request) (*http.Response, error)
}

// RoundTrip satisfies the http.RoundTripper interface.
func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    return m.handler(req)
}

// -- Delayed Body Closer --

// delayCloseBody is a test helper that implements io.ReadCloser.
// Its Close method blocks until a signal is sent on its closeSignal channel.
type delayCloseBody struct {
    io.Reader
    closeSignal <-chan struct{}
}

// Close waits for the closeSignal before returning nil.
func (d *delayCloseBody) Close() error {
    <-d.closeSignal
    return nil
}