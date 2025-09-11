package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultClientConfig_Optimizations(t *testing.T) {
	config := NewDefaultClientConfig()

	// Verifies that key performance optimizations are enabled by default.
	assert.True(t, config.Dialer.EnableKeepAlives, "Keep-Alives should be enabled for performance")
	assert.True(t, config.HTTP2.Enabled, "HTTP/2 should be enabled by default")
	assert.False(t, config.DisableConnectionPooling, "Connection pooling should be enabled by default")
}

func TestConfigureTLS_Defaults(t *testing.T) {
	var cfg ClientConfig
	tlsConfig := ConfigureTLS(&cfg)

	// Verifies that default TLS settings are sane.
	assert.NotNil(t, tlsConfig, "TLS config should never be nil")
	assert.False(t, tlsConfig.InsecureSkipVerify, "InsecureSkipVerify should be false by default")
	assert.Equal(t, tls.VersionTLS12, int(tlsConfig.MinVersion), "Minimum TLS version should be 1.2")
}

func TestConfigureTLS_CustomConfigClone(t *testing.T) {
	customCipher := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	cfg := ClientConfig{
		TLS: &tls.Config{
			CipherSuites: customCipher,
		},
	}

	tlsConfig := ConfigureTLS(&cfg)

	// Verifies that a user-provided TLS config is cloned and used.
	assert.NotSame(t, cfg.TLS, tlsConfig, "The returned TLS config should be a clone, not the same pointer")
	assert.Equal(t, customCipher, tlsConfig.CipherSuites, "Custom cipher suites should be preserved")

	// Modifying the returned config should not affect the original.
	tlsConfig.InsecureSkipVerify = true
	assert.False(t, cfg.TLS.InsecureSkipVerify, "Modifying the clone should not affect the original config")
}

func TestNewHTTPTransport_ConfigurationMapping(t *testing.T) {
	cfg := &ClientConfig{
		Dialer: DialerConfig{
			Timeout:             15 * time.Second,
			KeepAlive:           45 * time.Second,
			DualStack:           true,
			EnableKeepAlives:    true,
			ResponseHeaderLimit: 2048,
		},
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   5,
		IdleConnTimeout:       120 * time.Second,
		DisableConnectionPooling: true,
	}

	transport := NewHTTPTransport(cfg)
	require.NotNil(t, transport)

	// Verifies that all config fields correctly map to the http.Transport struct.
	assert.Equal(t, cfg.ResponseHeaderTimeout, transport.ResponseHeaderTimeout)
	assert.Equal(t, cfg.ExpectContinueTimeout, transport.ExpectContinueTimeout)
	assert.Equal(t, cfg.MaxIdleConns, transport.MaxIdleConns)
	assert.Equal(t, cfg.MaxIdleConnsPerHost, transport.MaxIdleConnsPerHost)
	assert.Equal(t, cfg.IdleConnTimeout, transport.IdleConnTimeout)
	assert.True(t, transport.DisableKeepAlives, "DisableConnectionPooling should translate to DisableKeepAlives")
	assert.Equal(t, cfg.Dialer.ResponseHeaderLimit, transport.MaxResponseHeaderBytes)
}

func TestNewHTTPTransport_Robustness_NilConfig(t *testing.T) {
	// Verifies the function doesn't panic with a nil config.
	assert.NotPanics(t, func() {
		transport := NewHTTPTransport(nil)
		assert.NotNil(t, transport, "Transport should not be nil even with a nil config")
		assert.NotNil(t, transport.DialContext, "DialContext should be configured with default dialer")
	})
}

func TestNewHTTPTransport_ProxyConfiguration(t *testing.T) {
	proxyURL, _ := url.Parse("http://user:pass@localhost:8080")
	cfg := &ClientConfig{
		ProxyURL: proxyURL,
	}
	transport := NewHTTPTransport(cfg)
	require.NotNil(t, transport.Proxy)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	p, err := transport.Proxy(req)

	// Verifies that the proxy setting is correctly configured.
	assert.NoError(t, err)
	assert.Equal(t, proxyURL, p)
}

func TestNewHTTPTransport_HTTP2_Enabled(t *testing.T) {
	cfg := &ClientConfig{
		HTTP2: HTTP2Config{Enabled: true},
	}
	transport := NewHTTPTransport(cfg)
	// In Go's http.Transport, enabling HTTP/2 is implicit. The real check
	// is ensuring that the TLSNextProto map is NOT explicitly cleared.
	// An empty map disables HTTP/2. A nil map uses the default, which includes "h2".
	assert.Nil(t, transport.TLSNextProto, "TLSNextProto should be nil to allow default HTTP/2 negotiation")
}

func TestNewHTTPTransport_HTTP2_Disabled(t *testing.T) {
	cfg := &ClientConfig{
		HTTP2: HTTP2Config{Enabled: false},
	}
	transport := NewHTTPTransport(cfg)
	// Disabling HTTP/2 is done by providing a non-nil, empty map for TLSNextProto.
	assert.NotNil(t, transport.TLSNextProto, "TLSNextProto should not be nil when disabling HTTP/2")
	assert.Empty(t, transport.TLSNextProto, "TLSNextProto map should be empty to disable HTTP/2")
}

func TestNewClient_RedirectPolicy(t *testing.T) {
	var redirectCount int
	// A test server that redirects exactly twice.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirectCount < 2 {
			redirectCount++
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Test case 1: Follow up to 5 redirects (default behavior).
	redirectCount = 0
	clientDefault := NewClient(nil) // Use default config.
	resp, err := clientDefault.Get(server.URL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, redirectCount, "Should have followed 2 redirects")

	// Test case 2: Do not follow any redirects.
	redirectCount = 0
	clientNoRedirect := NewClient(&ClientConfig{FollowRedirects: false})
	resp, err = clientNoRedirect.Get(server.URL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, 1, redirectCount, "Should have stopped after the first redirect response")

	// Test case 3: Custom redirect limit.
	redirectCount = 0
	clientCustomRedirect := NewClient(&ClientConfig{
		MaxRedirects: 1, // Only allow one redirect.
	})
	// We expect an error here because the client will try to follow the second redirect,
	// exceed its limit, and return an error.
	_, err = clientCustomRedirect.Get(server.URL)
	assert.Error(t, err, "Should return an error after exceeding max redirects")
	assert.Contains(t, err.Error(), "stopped after 1 redirects", "Error message should indicate why it stopped")
	assert.Equal(t, 2, redirectCount, "The server would still see 2 requests before the client gives up")
}

func TestClient_TimeoutBehavior(t *testing.T) {
	// A server that waits for 200ms before responding.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Client with a 500ms total timeout, should succeed.
	clientSucceed := NewClient(&ClientConfig{
		TotalTimeout: 500 * time.Millisecond,
	})
	_, err := clientSucceed.Get(server.URL)
	assert.NoError(t, err, "Request should succeed with a 500ms timeout")

	// Client with a 100ms total timeout, should fail.
	clientFail := NewClient(&ClientConfig{
		TotalTimeout: 100 * time.Millisecond,
	})
	_, err = clientFail.Get(server.URL)
	assert.Error(t, err, "Request should fail with a 100ms timeout")
	// Check if the error is a timeout error.
	netErr, ok := err.(net.Error)
	assert.True(t, ok && netErr.Timeout(), "Error should be a network timeout error")
}

func TestClient_Behavior_ResponseHeaderTimeout(t *testing.T) {
	// A server that accepts the connection but never sends a response header.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection to prevent the server from automatically sending headers.
		hijacker, ok := w.(http.Hijacker)
		require.True(t, ok, "Server must support hijacking")
		conn, _, err := hijacker.Hijack()
		require.NoError(t, err)
		// Just keep the connection open without writing anything.
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		ResponseHeaderTimeout: 100 * time.Millisecond,
		Dialer: DialerConfig{
			Timeout: 50 * time.Millisecond,
		},
	})

	_, err := client.Get(server.URL)
	assert.Error(t, err, "Request should fail due to response header timeout")
	assert.Contains(t, err.Error(), "timeout awaiting response headers", "Error message should be specific to header timeout")
}

func TestClient_HTTPS_Integration(t *testing.T) {
	// A handler for our test server.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	})

	// -- Correction for TestClient_HTTPS_Integration --
	// The default httptest.NewTLSServer does not enable HTTP/2. To test HTTP/2,
	// we must create an unstarted server, explicitly enable HTTP/2, and then start it.
	// This ensures the server can negotiate "h2" during the TLS handshake.
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	// Create a client that trusts the test server's certificate.
	client := NewClient(&ClientConfig{
		// We can use the server's client to get a pre-configured http.Client
		// that trusts the server's self-signed certificate.
		TLS: server.Client().Transport.(*http.Transport).TLSClientConfig,
	})

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// This is the core assertion that was failing. It now passes because the server is H2-enabled.
	assert.Equal(t, "HTTP/2.0", resp.Proto, "The protocol should be HTTP/2.0")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello, client\n", string(body))
}

func TestClient_InsecureSkipVerify_Integration(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// A client that does NOT trust the server's CA. This should fail.
	clientFail := NewClient(nil) // Default config
	_, err := clientFail.Get(server.URL)
	assert.Error(t, err, "Request should fail without trusting the server's certificate")

	// A client configured to skip certificate verification. This should succeed.
	clientSucceed := NewClient(&ClientConfig{
		TLS: &tls.Config{InsecureSkipVerify: true},
	})
	resp, err := clientSucceed.Get(server.URL)
	assert.NoError(t, err, "Request should succeed when InsecureSkipVerify is true")
	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
}

func TestClient_Behavior_ConnectionPooling(t *testing.T) {
	var connCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connCount++
		}
	}
	defer server.Close()

	// Client with pooling enabled.
	client := NewClient(nil)
	for i := 0; i < 3; i++ {
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// With connection pooling, only one connection should have been made for 3 requests.
	assert.Equal(t, 1, connCount, "Should reuse the same connection for multiple requests")

	// Client with pooling disabled.
	connCount = 0
	clientNoPool := NewClient(&ClientConfig{DisableConnectionPooling: true})
	for i := 0; i < 3; i++ {
		resp, err := clientNoPool.Get(server.URL)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// Without pooling, a new connection should be made for each request.
	assert.Equal(t, 3, connCount, "Should create a new connection for each request when pooling is disabled")
}

