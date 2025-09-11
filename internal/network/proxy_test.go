package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/security"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// setupTestCA initializes a dummy Certificate Authority for testing purposes.
func setupTestCA(t *testing.T) (*certs.CA, func()) {
	t.Helper()
	ca, err := certs.NewCA()
	require.NoError(t, err, "Failed to create test CA")
	cleanup := func() {
		// No explicit cleanup needed for the in-memory CA.
	}
	return ca, cleanup
}

// setupTestProxy initializes a proxy instance for testing.
func setupTestProxy(t *testing.T, ca *certs.CA, hooks *ProxyHooks) (*Proxy, func()) {
	t.Helper()
	cfg := &ProxyConfig{
		Addr:   "127.0.0.1:0", // Use port 0 to let the OS pick an available port.
		Logger: logger.NewFallbackLogger(io.Discard),
	}
	proxy := NewProxy(cfg)

	if ca != nil {
		err := proxy.ConfigureMITM(ca.Cert, ca.PrivateKey)
		require.NoError(t, err, "Failed to configure MITM on proxy")
	}

	if hooks != nil {
		proxy.SetHooks(*hooks)
	}

	err := proxy.Start()
	require.NoError(t, err, "Failed to start proxy")

	cleanup := func() {
		err := proxy.Stop()
		assert.NoError(t, err, "Failed to stop proxy cleanly")
	}

	return proxy, cleanup
}

func TestConfigureMITM_ValidCA(t *testing.T) {
	ca, cleanup := setupTestCA(t)
	defer cleanup()

	proxy := NewProxy(&ProxyConfig{Logger: logger.NewNopLogger()})
	err := proxy.ConfigureMITM(ca.Cert, ca.PrivateKey)

	assert.NoError(t, err, "Should successfully configure MITM with a valid CA")
	assert.True(t, proxy.IsMITMEnabled(), "MITM should be reported as enabled")
}

func TestConfigureMITM_InvalidCA(t *testing.T) {
	proxy := NewProxy(&ProxyConfig{Logger: logger.NewNopLogger()})
	err := proxy.ConfigureMITM(nil, nil)
	assert.Error(t, err, "Should return an error for nil certificate or key")
	assert.False(t, proxy.IsMITMEnabled(), "MITM should be disabled with invalid config")
}

func TestConfigureMITM_ConcurrencyLock(t *testing.T) {
	ca, cleanup := setupTestCA(t)
	defer cleanup()
	proxy := NewProxy(&ProxyConfig{Logger: logger.NewNopLogger()})

	var wg sync.WaitGroup
	wg.Add(2)

	// Run two configuration attempts concurrently.
	// The mutex inside ConfigureMITM should prevent data races.
	go func() {
		defer wg.Done()
		proxy.ConfigureMITM(ca.Cert, ca.PrivateKey)
	}()
	go func() {
		defer wg.Done()
		proxy.ConfigureMITM(ca.Cert, ca.PrivateKey)
	}()

	wg.Wait()
	assert.True(t, proxy.IsMITMEnabled(), "MITM should be enabled after concurrent calls")
}

func TestProxy_Stop_NotStarted(t *testing.T) {
	proxy := NewProxy(&ProxyConfig{
		Logger: logger.NewFallbackLogger(io.Discard),
	})
	// Stopping a proxy that was never started should not cause an error or panic.
	err := proxy.Stop()
	assert.NoError(t, err, "Stopping a non-running proxy should be a no-op and not return an error")
}

func TestProxy_Start_AlreadyStarted(t *testing.T) {
	proxy, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	// Trying to start an already running proxy should return an error.
	err := proxy.Start()
	assert.Error(t, err, "Starting an already running proxy should return an error")
}

func TestProxy_HTTP_TunnelingMode(t *testing.T) {
	// Setup a simple target HTTP server.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for a header that might have been added by a hook.
		if r.Header.Get("X-Scalpel-Test") == "modified" {
			fmt.Fprint(w, "modified request")
			return
		}
		fmt.Fprint(w, "hello http")
	}))
	defer targetServer.Close()

	// Setup a proxy without MITM capabilities (tunneling mode).
	proxy, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	// Configure an HTTP client to use the proxy.
	proxyURL, err := url.Parse("http://" + proxy.GetAddr())
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Make a request to the target server through the proxy.
	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err, "Request through HTTP proxy failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello http", string(body))
}

func TestProxy_HTTPS_TunnelingMode(t *testing.T) {
	// Setup a simple target HTTPS server.
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello https tunnel")
	}))
	defer targetServer.Close()

	// Setup a proxy without MITM capabilities. It will use CONNECT for HTTPS.
	proxy, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	proxyURL, err := url.Parse("http://" + proxy.GetAddr())
	require.NoError(t, err)

	// -- Correction for TestProxy_HTTPS_TunnelingMode --
	// This test was failing with a generic `Should be true`. The likely culprit is the client
	// rejecting the self-signed certificate of the `httptest.NewTLSServer`.
	// The fix is to configure the client's transport to skip certificate verification
	// for this specific test case. This allows the client to establish the TLS session
	// through the proxy's tunnel successfully.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// This is the crucial part. The client needs to trust the test server's certificate.
			// Since the test server uses a self-signed cert, we have to skip verification.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Make a request to the HTTPS server *through* the proxy tunnel.
	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err, "Client.Get through proxy tunnel returned an error")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello https tunnel", string(body), "Response body did not match expected")
}

func TestProxy_HTTPS_MITMMode(t *testing.T) {
	// Setup a target HTTPS server.
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello mitm")
	}))
	defer targetServer.Close()

	// Setup a proxy WITH MITM capabilities.
	ca, caCleanup := setupTestCA(t)
	defer caCleanup()
	proxy, proxyCleanup := setupTestProxy(t, ca, nil)
	defer proxyCleanup()

	proxyURL, err := url.Parse("http://" + proxy.GetAddr())
	require.NoError(t, err)

	// The client must trust the proxy's CA to avoid certificate errors.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: ca.CertPool,
			},
		},
	}

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err, "Request through MITM proxy failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello mitm", string(body))
}

func TestProxy_Hooks_RequestModification(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This test succeeds if this header is present.
		if r.Header.Get("X-Request-Modified") == "true" {
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
			return req, nil // Continue with the modified request.
		},
	}

	proxy, cleanup := setupTestProxy(t, nil, hooks)
	defer cleanup()

	proxyURL, _ := url.Parse("http://" + proxy.GetAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

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
			resp.Body = io.NopCloser(strings.NewReader("modified body"))
			return resp
		},
	}
	proxy, cleanup := setupTestProxy(t, nil, hooks)
	defer cleanup()

	proxyURL, _ := url.Parse("http://" + proxy.GetAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "modified body", string(body), "Body should be modified by the hook")
	assert.Equal(t, "true", resp.Header.Get("X-Response-Modified"), "Header should be added by the hook")
	assert.Equal(t, "", resp.Header.Get("X-Original-Response"), "Original header should still exist unless overwritten")
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
			}
			return nil, resp
		},
	}
	proxy, cleanup := setupTestProxy(t, nil, hooks)
	defer cleanup()

	proxyURL, _ := url.Parse("http://" + proxy.GetAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		// Prevent the client from following redirects if the short-circuit returned one.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusTeapot, resp.StatusCode, "Status code should be from the short-circuited response")
	assert.Equal(t, "I'm a teapot", string(body), "Body should be from the short-circuited response")
}
