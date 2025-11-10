// internal/browser/network/customhttp/mock_server_test.go
package customhttp

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"time"
)

// MockServerHandler is a configurable http.Handler for testing.
type MockServerHandler struct {
	StatusCode   int
	Headers      map[string]string
	Body         []byte
	Redirects    int
	RedirectURL  string
	Delay        time.Duration
	AuthRequired bool
	AuthUser     string
	AuthPass     string
}

// ServeHTTP implements the http.Handler interface.
func (h *MockServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Delay > 0 {
		time.Sleep(h.Delay)
	}

	if h.AuthRequired {
		user, pass, ok := r.BasicAuth()
		if !ok || user != h.AuthUser || pass != h.AuthPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// This is for the max redirect test which uses Redirects as a counter
	if h.Redirects > 0 {
		h.Redirects--
		w.Header().Set("Location", h.RedirectURL)
		w.WriteHeader(h.StatusCode) // StatusCode is set to 302 in the test
		return
	}

	// This is for other redirect tests
	if h.RedirectURL != "" {
		w.Header().Set("Location", h.RedirectURL)

		statusCode := h.StatusCode
		switch statusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			// Use the valid redirect code
		default:
			// Default to 302 if not a valid redirect code
			statusCode = http.StatusFound
		}
		w.WriteHeader(statusCode)
		return
	}

	for key, value := range h.Headers {
		w.Header().Set(key, value)
	}

	if h.StatusCode == 0 {
		// Prevent panic from WriteHeader(0) if no status is set and it's not a redirect
		h.StatusCode = http.StatusOK
	}
	w.WriteHeader(h.StatusCode)
	if h.Body != nil {
		w.Write(h.Body)
	}
}

// NewMockServer creates a new httptest.Server with a MockServerHandler.
func NewMockServer(handler *MockServerHandler) *httptest.Server {
	return httptest.NewServer(handler)
}

// NewMockTLSServer creates a new httptest.Server with a MockServerHandler and TLS.
func NewMockTLSServer(handler *MockServerHandler) *httptest.Server {
	// Use NewUnstartedServer to allow configuration before starting.
	server := httptest.NewUnstartedServer(handler)

	// Explicitly configure TLS to support H2, mirroring the logic
	// from the H2 fallback test. The standard httptest.Server.StartTLS()
	// should do this, but we are forcing it to resolve the test failures.
	server.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}

	// Start the server with TLS enabled (uses the configuration updated by ConfigureServer).
	server.StartTLS()
	return server
}
