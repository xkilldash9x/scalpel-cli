// internal/network/httpclient_test.go
package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- Test Cases: Configuration and Defaults (ClientConfig) --

// TestNewDefaultClientConfig_Optimizations verifies the defaults are optimized for scanning.
func TestNewDefaultClientConfig_Optimizations(t *testing.T) {
	config := NewDefaultClientConfig()

	// Verify Timeouts
	assert.Equal(t, DefaultRequestTimeout, config.RequestTimeout)
	assert.Equal(t, DefaultResponseHeaderTimeout, config.ResponseHeaderTimeout)

	// Verify Connection Pool
	assert.Equal(t, DefaultMaxIdleConns, config.MaxIdleConns)
	assert.Equal(t, DefaultMaxIdleConnsPerHost, config.MaxIdleConnsPerHost)

	// Verify Protocol Settings
	assert.True(t, config.ForceHTTP2, "HTTP/2 should be preferred by default")

	// Verify Dialer Configuration (Crucial Integration Point)
	require.NotNil(t, config.DialerConfig)
	// TCP_NODELAY (ForceNoDelay) must be true for optimized HTTP clients.
	assert.True(t, config.DialerConfig.ForceNoDelay, "TCP_NODELAY should be enabled for HTTP clients")

	// Verify Logger
	assert.NotNil(t, config.Logger)
}

// TestConfigureTLS_Defaults verifies the strong security defaults of the TLS configuration helper.
func TestConfigureTLS_Defaults(t *testing.T) {
	// Using a nil config to ensure the helper applies defaults correctly.
	tlsConfig := configureTLS(nil)

	// Verify Security Parameters
	require.NotNil(t, tlsConfig, "TLS config should never be nil")
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.False(t, tlsConfig.InsecureSkipVerify)

	// Verify Cipher Suites (Strong AEAD prioritized)
	expectedCiphers := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	assert.Equal(t, expectedCiphers, tlsConfig.CipherSuites)

	// Verify Optimizations (Session Resumption Cache)
	assert.NotNil(t, tlsConfig.ClientSessionCache, "TLS session cache should be enabled")
}

// TestConfigureTLS_CustomConfigClone verifies that a provided custom TLSConfig is cloned and used, and overrides apply.
func TestConfigureTLS_CustomConfigClone(t *testing.T) {
	customTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "custom.sni",
	}
	config := NewDefaultClientConfig()
	config.TLSConfig = customTLS
	config.IgnoreTLSErrors = true // Test override

	tlsConfig := configureTLS(config)

	// Verify custom settings are preserved
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	assert.Equal(t, "custom.sni", tlsConfig.ServerName)

	// Verify override is applied
	assert.True(t, tlsConfig.InsecureSkipVerify)

	// Verify it's a clone, not the original object
	assert.NotSame(t, customTLS, tlsConfig)
	assert.False(t, customTLS.InsecureSkipVerify, "Original object should not be modified")
}

// -- Test Cases: Transport Creation (NewHTTPTransport) --

// TestNewHTTPTransport_ConfigurationMapping verifies ClientConfig maps correctly to http.Transport.
func TestNewHTTPTransport_ConfigurationMapping(t *testing.T) {
	config := NewDefaultClientConfig()
	// Modify defaults to ensure custom values are propagated
	config.MaxIdleConns = 55
	config.IdleConnTimeout = 99 * time.Second
	config.DisableCompression = true
	config.ResponseHeaderTimeout = 5 * time.Second
	config.DisableKeepAlives = true

	transport := NewHTTPTransport(config)

	// Verify mapping
	assert.Equal(t, 55, transport.MaxIdleConns)
	assert.Equal(t, 99*time.Second, transport.IdleConnTimeout)
	assert.True(t, transport.DisableCompression)
	assert.Equal(t, 5*time.Second, transport.ResponseHeaderTimeout)
	assert.True(t, transport.DisableKeepAlives, "DisableKeepAlives should be propagated")
}

// TestNewHTTPTransport_Robustness_NilConfig verifies handling of nil configuration.
func TestNewHTTPTransport_Robustness_NilConfig(t *testing.T) {
	// Should use defaults if config is nil
	transport := NewHTTPTransport(nil)

	// Verify defaults are applied
	assert.Equal(t, DefaultMaxIdleConns, transport.MaxIdleConns)
	assert.NotNil(t, transport.DialContext)
	assert.NotNil(t, transport.TLSClientConfig)
}

// TestNewHTTPTransport_ProxyConfiguration verifies proxy settings are applied.
func TestNewHTTPTransport_ProxyConfiguration(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	config := NewDefaultClientConfig()
	config.ProxyURL = proxyURL

	transport := NewHTTPTransport(config)

	// Verify Proxy function is set
	require.NotNil(t, transport.Proxy)

	// Test the proxy function behavior
	req, _ := http.NewRequest("GET", "http://target.com", nil)
	resultURL, err := transport.Proxy(req)

	require.NoError(t, err)
	assert.Equal(t, proxyURL, resultURL)
}

// TestNewHTTPTransport_HTTP2_Enabled verifies H2 configuration and ALPN negotiation.
func TestNewHTTPTransport_HTTP2_Enabled(t *testing.T) {
	config := NewDefaultClientConfig()
	config.ForceHTTP2 = true

	transport := NewHTTPTransport(config)

	// Verify http.Transport settings
	assert.True(t, transport.ForceAttemptHTTP2)

	// Verify ALPN negotiation protocols. http2.ConfigureTransport ensures "h2" is present.
	require.NotNil(t, transport.TLSClientConfig)
	assert.Contains(t, transport.TLSClientConfig.NextProtos, "h2")
	assert.Contains(t, transport.TLSClientConfig.NextProtos, "http/1.1")
}

// TestNewHTTPTransport_HTTP2_Disabled verifies H1-only configuration and ALPN restriction.
func TestNewHTTPTransport_HTTP2_Disabled(t *testing.T) {
	config := NewDefaultClientConfig()
	config.ForceHTTP2 = false

	transport := NewHTTPTransport(config)

	// Verify http.Transport settings
	assert.False(t, transport.ForceAttemptHTTP2)

	// Verify ALPN negotiation protocols: Should only advertise "http/1.1".
	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, []string{"http/1.1"}, transport.TLSClientConfig.NextProtos)
}

// -- Test Cases: Client Behavior (NewClient and Integration) --

// TestNewClient_RedirectPolicy verifies the client does not automatically follow redirects (Security requirement).
func TestNewClient_RedirectPolicy(t *testing.T) {
	// Setup a server that issues a redirect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/redirected", http.StatusFound) // 302
		}
	}))
	defer server.Close()

	client := NewClient(nil) // Use default config

	resp, err := client.Get(server.URL)
	// The error should be nil as the client successfully retrieved the 302 response.
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify the response is the redirect itself (302), not the destination (200)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/redirected", resp.Header.Get("Location"))
}

// TestClient_TimeoutBehavior verifies the overall client timeout (RequestTimeout).
func TestClient_TimeoutBehavior(t *testing.T) {
	// Setup server that delays the response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Configure client with a short timeout
	config := NewDefaultClientConfig()
	config.RequestTimeout = 100 * time.Millisecond
	client := NewClient(config)

	startTime := time.Now()
	resp, err := client.Get(server.URL)
	duration := time.Since(startTime)

	// Verify timeout error
	assert.Error(t, err)
	assert.Nil(t, resp)

	// Check error type (should be context deadline exceeded)
	urlErr, ok := err.(*url.Error)
	require.True(t, ok)
	assert.ErrorIs(t, urlErr.Err, context.DeadlineExceeded)

	// Verify duration
	assert.Less(t, duration, 500*time.Millisecond, "Timeout took significantly longer than expected")
}

// TestClient_Behavior_ResponseHeaderTimeout verifies the specific timeout for waiting on headers.
func TestClient_Behavior_ResponseHeaderTimeout(t *testing.T) {
	// Setup a raw TCP server that accepts a connection but slowly sends headers
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the request headers
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)

		// Wait before sending response headers
		time.Sleep(500 * time.Millisecond)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()

	// Configure client with a short ResponseHeaderTimeout
	config := NewDefaultClientConfig()
	config.RequestTimeout = 5 * time.Second // Long overall timeout
	config.ResponseHeaderTimeout = 100 * time.Millisecond
	client := NewClient(config)

	// Execute request
	req, _ := http.NewRequest("GET", "http://"+listener.Addr().String(), nil)
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	// Verify timeout error
	assert.Error(t, err)
	assert.Nil(t, resp)

	// The specific error message for ResponseHeaderTimeout
	assert.Contains(t, err.Error(), "timeout awaiting response headers")

	// Verify duration
	assert.Less(t, duration, 500*time.Millisecond)
}

// TestClient_HTTPS_Integration verifies end-to-end HTTPS communication and protocol negotiation.
func TestClient_HTTPS_Integration(t *testing.T) {
	// A handler for our test server.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	})

	// Setup a standard HTTPS server with a self-signed certificate (httptest default)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{}
	server.StartTLS()
	defer server.Close()

    // Get the CA cert from the server's TLS config
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(server.TLS.Certificates[0].Leaf)

	// Configure the client to trust the server's CA
	config := NewDefaultClientConfig()
	config.TLSConfig = &tls.Config{
		RootCAs: caCertPool,
	}
	// Ensure ForceHTTP2 is true (default)
	config.ForceHTTP2 = true
	client := NewClient(config)

	// Execute request
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Hello, client\n", string(body))

	// Verify protocol negotiation (Should be H2)
	assert.Equal(t, "HTTP/2.0", resp.Proto)
}

// TestClient_InsecureSkipVerify_Integration verifies the client can connect to servers with invalid certs if configured.
func TestClient_InsecureSkipVerify_Integration(t *testing.T) {
	// Start a standard HTTPS server with a self-signed certificate (httptest default)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK Insecure"))
	}))
	defer server.Close()

	// 1. Test with default config (should fail)
	clientDefault := NewClient(nil)
	_, err := clientDefault.Get(server.URL)
	assert.Error(t, err, "Default client should fail on untrusted certificate")

	// 2. Test with IgnoreTLSErrors enabled
	config := NewDefaultClientConfig()
	config.IgnoreTLSErrors = true
	clientInsecure := NewClient(config)

	resp, err := clientInsecure.Get(server.URL)
	require.NoError(t, err, "Client with IgnoreTLSErrors should succeed")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "OK Insecure", string(body))
}

// TestClient_Behavior_ConnectionPooling verifies that connections are reused (Keep-Alive).
func TestClient_Behavior_ConnectionPooling(t *testing.T) {
	// Use a map to track the unique remote addresses seen by the server
	remoteAddrs := make(map[string]bool)
	var mutex sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		remoteAddrs[r.RemoteAddr] = true
		mutex.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := NewDefaultClientConfig()
	config.DisableKeepAlives = false // Ensure KeepAlives are enabled (default)
	client := NewClient(config)

	// Make multiple requests sequentially
	iterations := 5
	for i := 0; i < iterations; i++ {
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		io.ReadAll(resp.Body) // Must read and close body to reuse connection
		resp.Body.Close()
	}

	// Verify that fewer connections were used than requests made
	assert.Less(t, len(remoteAddrs), iterations, "Connections should have been reused")
	assert.Greater(t, len(remoteAddrs), 0)
}