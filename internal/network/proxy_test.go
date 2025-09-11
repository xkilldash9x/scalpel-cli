// internal/network/proxy_test.go
package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/security"
	// Assuming observability is initialized elsewhere or we use zap.NewNop()
	// "github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// setupTestCA initializes a dummy Certificate Authority for testing purposes.
func setupTestCA(t *testing.T) (*security.CA, func()) {
	t.Helper()
	// Assuming security.NewCA() exists and works based on imports.
	ca, err := security.NewCA()
	require.NoError(t, err, "Failed to create test CA")
	cleanup := func() {
		// No explicit cleanup needed for the in-memory CA.
	}
	return ca, cleanup
}

// setupTestProxy initializes a proxy instance for testing.
func setupTestProxy(t *testing.T, ca *security.CA, hooks *ProxyHooks) (*Proxy, func()) {
	t.Helper()
	// Use zap.NewNop() for clean test output
	logger := zap.NewNop()

	cfg := &ProxyConfig{
		Addr:   "127.0.0.1:0", // Use port 0 to let the OS pick an available port.
		Logger: logger,
	}
	proxy := NewProxy(cfg)

	if ca != nil {
		err := proxy.ConfigureMITM(ca.Cert, ca.PrivateKey)
		require.NoError(t, err, "Failed to configure MITM on proxy")
	}

	if hooks != nil {
		proxy.SetHooks(*hooks)
	}

	// Assuming Proxy has Start/Stop methods
	err := proxy.Start()
	require.NoError(t, err, "Failed to start proxy")

	// Allow a brief moment for the server to bind
	time.Sleep(10 * time.Millisecond)

	cleanup := func() {
		err := proxy.Stop()
		assert.NoError(t, err, "Failed to stop proxy cleanly")
	}

	return proxy, cleanup
}

// --- Configuration and Lifecycle Tests ---

func TestConfigureMITM_ValidCA(t *testing.T) {
	ca, cleanup := setupTestCA(t)
	defer cleanup()

	proxy := NewProxy(&ProxyConfig{Logger: zap.NewNop()})
	err := proxy.ConfigureMITM(ca.Cert, ca.PrivateKey)

	assert.NoError(t, err, "Should successfully configure MITM with a valid CA")
	assert.True(t, proxy.IsMITMEnabled(), "MITM should be reported as enabled")
}

func TestConfigureMITM_InvalidCA(t *testing.T) {
	proxy := NewProxy(&ProxyConfig{Logger: zap.NewNop()})
	err := proxy.ConfigureMITM(nil, nil)
	assert.Error(t, err, "Should return an error for nil certificate or key")
	assert.False(t, proxy.IsMITMEnabled(), "MITM should be disabled with invalid config")
}

func TestProxy_Lifecycle(t *testing.T) {
	proxy, cleanup := setupTestProxy(t, nil, nil)

	// Test starting an already running proxy
	err := proxy.Start()
	assert.Error(t, err, "Starting an already running proxy should return an error")

	// Stop the proxy
	cleanup()

	// Test stopping a non-running proxy
	err = proxy.Stop()
	assert.NoError(t, err, "Stopping a non-running proxy should be a no-op and not return an error")
}

// --- Integration Tests: Traffic Flow ---

// TestProxy_HTTP_Forwarding verifies basic HTTP request forwarding.
func TestProxy_HTTP_Forwarding(t *testing.T) {
	// Setup a simple target HTTP server.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Header") == "value" {
			fmt.Fprint(w, "hello http")
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer targetServer.Close()

	// Setup a proxy without MITM capabilities.
	proxy, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	client := createTestClient(t, proxy, nil)

	req, _ := http.NewRequest("GET", targetServer.URL, nil)
	req.Header.Set("X-Test-Header", "value")

	// Make a request to the target server through the proxy.
	resp, err := client.Do(req)
	require.NoError(t, err, "Request through HTTP proxy failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello http", string(body))
}

// TestProxy_HTTPS_TunnelingMode verifies HTTPS CONNECT tunneling when MITM is disabled.
func TestProxy_HTTPS_TunnelingMode(t *testing.T) {
	// Setup a simple target HTTPS server.
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello https tunnel")
	}))
	defer targetServer.Close()

	// Setup a proxy without MITM capabilities. It will use CONNECT for HTTPS.
	proxy, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	// Client configured to use proxy, skipping verification for the self-signed target server.
	client := createTestClient(t, proxy, nil)

	// Make a request to the HTTPS server *through* the proxy tunnel.
	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err, "Client.Get through proxy tunnel returned an error")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello https tunnel", string(body), "Response body did not match expected")
}

// TestProxy_HTTPS_MITMMode verifies interception when MITM is enabled.
func TestProxy_HTTPS_MITMMode(t *testing.T) {
	// Setup a target HTTPS server.
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello mitm")
	}))
	defer targetServer.Close()

	// Setup a proxy WITH MITM capabilities.
	ca, caCleanup := setupTestCA(t)
	defer caCleanup()

	// Use hooks to verify interception occurred
	var requestIntercepted, responseIntercepted bool
	done := make(chan struct{})
	hookCount := 0

	hooks := &ProxyHooks{
		OnRequest: func(req *http.Request, ctx *ProxyContext) (*http.Request, *http.Response) {
			requestIntercepted = true
			assert.True(t, ctx.IsMITM, "Context should indicate MITM")
			return req, nil
		},
		OnResponse: func(resp *http.Response, ctx *ProxyContext) *http.Response {
			responseIntercepted = true
			hookCount++
			if hookCount == 1 {
				close(done)
			}
			return resp
		},
	}

	proxy, proxyCleanup := setupTestProxy(t, ca, hooks)
	defer proxyCleanup()

	// Client must trust the proxy's CA.
	client := createTestClient(t, proxy, ca)

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err, "Request through MITM proxy failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello mitm", string(body))

	// Wait for hooks to complete
	select {
	case <-done:
		// Hooks finished
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for MITM proxy hooks to complete")
	}

	assert.True(t, requestIntercepted, "OnRequest hook (MITM) should have been called")
	assert.True(t, responseIntercepted, "OnResponse hook (MITM) should have been called")
}

// --- Integration Tests: Hooks Functionality ---

func TestProxy_Hooks_RequestModification(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This test succeeds if this header is present.
		if r.Header.Get("X-Request-Modified") == "true" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "request was modified")
		} else {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "request was not modified")
		}
	}))
	defer targetServer.Close()

	hooks := &ProxyHooks{
		OnRequest: func(req *http.Request, ctx *ProxyContext) (*http.Request, *http.Response) {
			req.Header.Set("X-Request-Modified", "true")
			req.Method = "POST" // Change method
			return req, nil
		},
	}

	proxy, cleanup := setupTestProxy(t, nil, hooks)
	defer cleanup()

	client := createTestClient(t, proxy, nil)

	// Send GET, expect hook to change to POST
	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "request was modified", string(body))
}

func TestProxy_Hooks_ResponseModification(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Original-Response", "true")
		fmt.Fprint(w, "original body")
	}))
	defer targetServer.Close()

	hooks := &ProxyHooks{
		OnResponse: func(resp *http.Response, ctx *ProxyContext) *http.Response {
			// Change a header and the body.
			resp.Header.Set("X-Response-Modified", "true")
			newBody := "modified body"
			resp.Body = io.NopCloser(strings.NewReader(newBody))
			// Update Content-Length
			resp.ContentLength = int64(len(newBody))
			return resp
		},
	}
	proxy, cleanup := setupTestProxy(t, nil, hooks)
	defer cleanup()

	client := createTestClient(t, proxy, nil)

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "modified body", string(body), "Body should be modified by the hook")
	assert.Equal(t, "true", resp.Header.Get("X-Response-Modified"), "Header should be added by the hook")
}

func TestProxy_Hooks_ShortCircuit(t *testing.T) {
	// Target server should never be hit.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Target server was hit, request was not short-circuited")
	}))
	defer targetServer.Close()

	hooks := &ProxyHooks{
		OnRequest: func(req *http.Request, ctx *ProxyContext) (*http.Request, *http.Response) {
			// Return a custom response directly, bypassing the target server.
			resp := &http.Response{
				StatusCode: http.StatusTeapot,
				Body:       io.NopCloser(strings.NewReader("I'm a teapot")),
				Header:     make(http.Header),
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Request:    req, // Associate request with response
			}
			return nil, resp
		},
	}
	proxy, cleanup := setupTestProxy(t, nil, hooks)
	defer cleanup()

	client := createTestClient(t, proxy, nil)

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusTeapot, resp.StatusCode, "Status code should be from the short-circuited response")
	assert.Equal(t, "I'm a teapot", string(body), "Body should be from the short-circuited response")
}

// createTestClient is a helper to configure an HTTP client for the proxy tests.
func createTestClient(t *testing.T, proxy *Proxy, ca *security.CA) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxy.GetAddr())
	require.NoError(t, err)

	tlsConfig := &tls.Config{}

	if ca != nil {
		// MITM Scenario: Trust the proxy's CA.
		tlsConfig.RootCAs = ca.CertPool
	}

	// In test environments using httptest.NewTLSServer, the target server uses a self-signed cert.
	// The client (and the proxy's upstream connection) must ignore these errors.
	tlsConfig.InsecureSkipVerify = true

	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		},
		// Prevent automatic redirect following
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
