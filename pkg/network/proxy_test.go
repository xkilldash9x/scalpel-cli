// internal/network/proxy_test.go
package network

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync" // Import sync
	"testing"
	"time" // Import time

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/security"
)

// -- Test Helpers --

// setupTestCA initializes a dummy Certificate Authority and returns the CA struct and PEM-encoded bytes.
func setupTestCA(t *testing.T) (*security.CA, []byte, []byte) {
	t.Helper()
	ca, err := security.NewCA()
	require.NoError(t, err, "Failed to create test CA")

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	caKeyBytes, err := x509.MarshalPKCS8PrivateKey(ca.PrivateKey)
	require.NoError(t, err)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyBytes})

	return ca, caCertPEM, caKeyPEM
}

// setupTestProxy initializes and starts an InterceptionProxy for testing.
func setupTestProxy(t *testing.T, caCert, caKey []byte) (*InterceptionProxy, string, func()) {
	t.Helper()
	logger := zap.NewNop()

	// The user's comment "FIX: Use the new constructor name NewBrowserClientConfig."
	// is contradicted by the type error and the contents of proxy.go (which uses NewDialerConfig).
	// We will follow proxy.go and use NewDialerConfig(), which should return the correct *DialerConfig type.
	dialerCfg := NewDialerConfig()

	// FIX: Use the new field name InsecureSkipVerify.
	// This should be set on the TLSConfig within the DialerConfig.
	if dialerCfg.TLSConfig == nil {
		dialerCfg.TLSConfig = &tls.Config{}
	}
	dialerCfg.TLSConfig.InsecureSkipVerify = true

	// Create the transport config instance to pass to the proxy constructor
	transportCfg := &ProxyTransportConfig{
		DialerConfig: dialerCfg,
	}

	// Pass the transportCfg instance, not the type
	proxy, err := NewInterceptionProxy(caCert, caKey, transportCfg, logger)
	require.NoError(t, err, "Failed to create interception proxy")

	proxyServer := httptest.NewServer(proxy.proxy)
	t.Cleanup(proxyServer.Close)

	return proxy, proxyServer.URL, func() {}
}

// createTestClient configures an http.Client to use the test proxy.
func createTestClient(t *testing.T, proxyURLStr string, ca *security.CA) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(proxyURLStr)
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	if ca != nil && ca.CertPool != nil {
		tlsConfig.RootCAs = ca.CertPool
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// -- Test Cases --

func TestProxy_HTTP_Forwarding(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "value", r.Header.Get("X-Test-Header"))
		fmt.Fprint(w, "hello http")
	}))
	defer targetServer.Close()

	_, proxyURL, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	client := createTestClient(t, proxyURL, nil)

	req, _ := http.NewRequest("GET", targetServer.URL, nil)
	req.Header.Set("X-Test-Header", "value")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello http", string(body))
}

func TestProxy_HTTPS_TunnelingMode(t *testing.T) {
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello https tunnel")
	}))
	defer targetServer.Close()

	_, proxyURL, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	client := createTestClient(t, proxyURL, nil)

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello https tunnel", string(body))
}

func TestProxy_HTTPS_MITMMode(t *testing.T) {
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello mitm")
	}))
	defer targetServer.Close()

	ca, caCertPEM, caKeyPEM := setupTestCA(t)

	var requestIntercepted, responseIntercepted bool
	proxy, proxyURL, cleanup := setupTestProxy(t, caCertPEM, caKeyPEM)
	defer cleanup()

	proxy.AddRequestHook(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		requestIntercepted = true
		return r, nil
	})
	proxy.AddResponseHook(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		responseIntercepted = true
		return r
	})

	client := createTestClient(t, proxyURL, ca)

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello mitm", string(body))
	assert.True(t, requestIntercepted, "OnRequest hook should have been called")
	assert.True(t, responseIntercepted, "OnResponse hook should have been called")
}

func TestProxy_Hooks_ResponseModification(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Original-Response", "true")
		fmt.Fprint(w, "original body")
	}))
	defer targetServer.Close()

	proxy, proxyURL, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	proxy.AddResponseHook(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		resp.Header.Set("X-Response-Modified", "true")
		newBody := "modified body"
		resp.Body = io.NopCloser(strings.NewReader(newBody))
		resp.ContentLength = int64(len(newBody))
		return resp
	})

	client := createTestClient(t, proxyURL, nil)

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "modified body", string(body))
	assert.Equal(t, "true", resp.Header.Get("X-Response-Modified"))
}

func TestProxy_Hooks_ShortCircuit(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Target server was hit, request was not short-circuited")
	}))
	defer targetServer.Close()

	proxy, proxyURL, cleanup := setupTestProxy(t, nil, nil)
	defer cleanup()

	proxy.AddRequestHook(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusTeapot, "I'm a teapot")
	})

	client := createTestClient(t, proxyURL, nil)

	resp, err := client.Get(targetServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	assert.Equal(t, "I'm a teapot", string(body))
}

// TestProxy_ConcurrentRequests validates the proxy's ability to handle
// multiple simultaneous connections (both HTTP and HTTPS MITM).
// This aligns with the report's mandate that integration tests must validate
// behavior under parallel load to detect deadlocks or logical races.
func TestProxy_ConcurrentRequests(t *testing.T) {
	// Setup HTTP Target
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond) // Simulate minor work
		fmt.Fprintf(w, "http response %s", r.URL.Path)
	}))
	defer httpTarget.Close()

	// Setup HTTPS Target (requires MITM)
	httpsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		fmt.Fprintf(w, "https response %s", r.URL.Path)
	}))
	defer httpsTarget.Close()

	// Setup Proxy with CA for MITM
	ca, caCertPEM, caKeyPEM := setupTestCA(t)
	proxy, proxyURL, cleanup := setupTestProxy(t, caCertPEM, caKeyPEM)
	defer cleanup()

	// Add a simple hook to ensure MITM logic is exercised and count requests safely.
	requestCount := 0
	var countMu sync.Mutex
	proxy.AddRequestHook(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		countMu.Lock()
		requestCount++
		countMu.Unlock()
		return r, nil
	})

	client := createTestClient(t, proxyURL, ca)

	const concurrency = 50
	var wg sync.WaitGroup

	// Launch concurrent requests
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			targetURL := httpTarget.URL
			expectedBody := fmt.Sprintf("http response /req%d", i)
			// Alternate between HTTP and HTTPS to stress different code paths
			if i%2 == 0 {
				targetURL = httpsTarget.URL
				expectedBody = fmt.Sprintf("https response /req%d", i)
			}

			req, _ := http.NewRequest("GET", fmt.Sprintf("%s/req%d", targetURL, i), nil)
			resp, err := client.Do(req)

			// Use assert.NoError to allow the test to continue and potentially find more issues.
			if assert.NoError(t, err) && resp != nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, expectedBody, string(body))
			}
		}(i)
	}

	wg.Wait()
	// Verify all requests were processed
	assert.Equal(t, concurrency, requestCount, "All requests should have passed through the hook")
}
