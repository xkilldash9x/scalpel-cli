package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// -- Test Setup and Helpers --

// Initializes the proxy and necessary components like the CA and logger.
func setupProxyTest(t *testing.T, enableMITM bool) (*InterceptionProxy, *tlsTestHelper, *zap.Logger) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	helper := newTLSTestHelper(t) // Used for CA generation and upstream server certs

	var caCert, caKey []byte
	if enableMITM {
		caCert = helper.caCertPEM
		caKey = helper.caKeyPEM
	}

	// Configure the client used by the proxy for upstream connections
	clientConfig := NewDefaultClientConfig()
	// Default behavior for proxy upstream connections is to ignore errors.
	clientConfig.IgnoreTLSErrors = true

	proxy, err := NewInterceptionProxy(caCert, caKey, clientConfig, logger)
	require.NoError(t, err, "Failed to create InterceptionProxy")

	return proxy, helper, logger
}

// Starts the proxy server in a goroutine and returns the listening address.
// This implementation avoids the limitations of proxy.Start() by manually managing the listener,
// ensuring reliable ephemeral port usage and lifecycle management.
func startProxyServer(t *testing.T, proxy *InterceptionProxy) string {
	t.Helper()

	// 1. Create a listener on an ephemeral port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to listen on ephemeral port")
	proxyAddr := listener.Addr().String()

	// 2. Create the http.Server instance.
	server := &http.Server{
		Handler: proxy.proxy,
		// Apply standard timeouts
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     zap.NewStdLog(proxy.logger.Named("http_server")),
	}

	// 3. Update the proxy's internal state (mimicking what Start() does).
	proxy.serverMutex.Lock()
	proxy.server = server
	proxy.serverMutex.Unlock()

	// 4. Start the server using Serve() instead of ListenAndServe().
	go func() {
		err := server.Serve(listener)
		// Expected error upon shutdown
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("Proxy server stopped with unexpected error: %v", err)
		}

		// Clean up internal state after stopping (mimicking Start() cleanup)
		proxy.serverMutex.Lock()
		if proxy.server == server {
			proxy.server = nil
		}
		proxy.serverMutex.Unlock()
	}()

	// Ensure the proxy is stopped when the test finishes
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := proxy.Stop(ctx)
		if err != nil && !strings.Contains(err.Error(), "proxy server not started") {
			t.Logf("Failed to stop proxy gracefully: %v", err)
		}
	})

	return proxyAddr
}

// Creates an http.Client that is configured to use the proxy.
func createProxyClient(t *testing.T, proxyAddr string, caPool *x509.CertPool) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	require.NoError(t, err)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			// If testing MITM, the client must trust the proxy's CA.
			RootCAs: caPool,
		},
	}

	// If caPool is nil (e.g., testing HTTP or HTTPS tunneling), we typically need to skip verification
	// when the upstream server uses self signed certs (like httptest).
	if caPool == nil {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

// -- Test Cases: MITM Configuration (Global State Management) --

// Verifies successful loading of a CA and modification of the global goproxy state.
func TestConfigureMITM_ValidCA(t *testing.T) {
	helper := newTLSTestHelper(t)

	// Capture global state before test
	mitmConfigMutex.Lock()
	originalCA := goproxy.GoproxyCa
	mitmConfigMutex.Unlock()

	// Execute configuration
	err := configureMITM(helper.caCertPEM, helper.caKeyPEM)
	require.NoError(t, err)

	// Verify global state modification and restore after test
	mitmConfigMutex.Lock()
	defer func() {
		goproxy.GoproxyCa = originalCA
		mitmConfigMutex.Unlock()
	}()

	assert.NotNil(t, goproxy.GoproxyCa.PrivateKey)
	assert.NotEmpty(t, goproxy.GoproxyCa.Certificate)
	assert.NotNil(t, goproxy.GoproxyCa.Leaf, "Leaf certificate should be parsed")
	assert.NotNil(t, goproxy.MitmConnect.TLSConfig)
}

// Verifies error handling for corrupted CA files.
func TestConfigureMITM_InvalidCA(t *testing.T) {
	helper := newTLSTestHelper(t)

	// Corrupt the key
	invalidKey := []byte("invalid key data")

	err := configureMITM(helper.caCertPEM, invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CA certificate/key pair")
}

// Stresses the locking mechanism that protects the global MITM state.
func TestConfigureMITM_ConcurrencyLock(t *testing.T) {
	// Generate two distinct helpers for this test to ensure different CAs are used.
	helper1 := &tlsTestHelper{t: t}
	helper1.generateCA()
	helper2 := &tlsTestHelper{t: t}
	helper2.generateCA()

	// Concurrently try to configure MITM with different CAs.
	iterations := 50
	wg := sync.WaitGroup{}

	for i := 0; i < iterations; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			err := configureMITM(helper1.caCertPEM, helper1.caKeyPEM)
			assert.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			err := configureMITM(helper2.caCertPEM, helper2.caKeyPEM)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	// The test passes if no race conditions occur (run with -race flag).
}

// -- Test Cases: Proxy Lifecycle (Start/Stop) --

// Verifies error handling if Stop is called before the proxy is started.
func TestProxy_Stop_NotStarted(t *testing.T) {
	proxy, _, _ := setupProxyTest(t, false)
	ctx := context.Background()
	err := proxy.Stop(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proxy server not started or already stopped")
}

// Verifies error handling if Start is called on an already running proxy.
func TestProxy_Start_AlreadyStarted(t *testing.T) {
	proxy, _, _ := setupProxyTest(t, false)
	// Start the proxy using the test helper, which manages the lifecycle.
	startProxyServer(t, proxy)

	// Attempt to start it again using the production Start method.
	err := proxy.Start("127.0.0.1:0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proxy server already started")
}

// -- Test Cases: Proxy Functionality (Tunneling and MITM Integration) --

// Verifies standard HTTP proxying functionality.
func TestProxy_HTTP_TunnelingMode(t *testing.T) {
	// 1. Setup upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Seen", "true")
		w.Write([]byte("Hello from upstream"))
	}))
	defer upstream.Close()

	// 2. Setup proxy (MITM disabled is sufficient for HTTP)
	proxy, _, _ := setupProxyTest(t, false)
	proxyAddr := startProxyServer(t, proxy)

	// 3. Setup client
	client := createProxyClient(t, proxyAddr, nil)

	// 4. Execute request
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 5. Verify response
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Hello from upstream", string(body))
	assert.Equal(t, "true", resp.Header.Get("X-Upstream-Seen"))
}

// Verifies HTTPS CONNECT tunneling when MITM is disabled.
func TestProxy_HTTPS_TunnelingMode(t *testing.T) {
	// 1. Setup upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("HTTPS Tunnel Success"))
	}))
	defer upstream.Close()

	// 2. Setup proxy (MITM disabled)
	proxy, _, _ := setupProxyTest(t, false)
	proxyAddr := startProxyServer(t, proxy)

	// 3. Setup client.
	// The client needs to trust the upstream server's cert (or skip verification).
	// createProxyClient(nil) sets InsecureSkipVerify=true, which works for httptest's self signed certs.
	client := createProxyClient(t, proxyAddr, nil)

	// 4. Execute request
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 5. Verify response
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "HTTPS Tunnel Success", string(body))

	// 6. Verify the connection was tunneled (not intercepted)
	// The certificate presented to the client must be the upstream server's certificate.
	require.NotNil(t, resp.TLS)
	require.NotEmpty(t, resp.TLS.PeerCertificates)
	upstreamCert := upstream.Certificate()
	assert.True(t, upstreamCert.Equal(resp.TLS.PeerCertificates[0]))
}

// Verifies HTTPS interception when a CA is configured.
func TestProxy_HTTPS_MITMMode(t *testing.T) {
	// 1. Setup upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("HTTPS MITM Success"))
	}))
	defer upstream.Close()

	// 2. Setup proxy (MITM enabled)
	proxy, helper, _ := setupProxyTest(t, true)
	proxyAddr := startProxyServer(t, proxy)

	// Add a hook to verify interception occurred
	var intercepted bool
	proxy.AddRequestHook(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		intercepted = true
		// Verify the request URL scheme is correctly identified within the MITM context
		assert.Equal(t, "https", r.URL.Scheme)
		return r, nil
	})

	// 3. Setup client trusting the PROXY's CA.
	client := createProxyClient(t, proxyAddr, helper.caPool)

	// 4. Execute request
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 5. Verify response
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "HTTPS MITM Success", string(body))
	assert.True(t, intercepted, "Request hook should have been executed (MITM active)")

	// 6. Verify the connection was intercepted
	// The certificate presented to the client must be signed by the proxy's CA.
	require.NotNil(t, resp.TLS)
	presentedCert := resp.TLS.PeerCertificates[0]

	// Verify the issuer is the proxy CA
	assert.Equal(t, helper.caCert.Subject.CommonName, presentedCert.Issuer.CommonName)

	// Verify it is NOT the upstream server's certificate
	upstreamCert := upstream.Certificate()
	assert.False(t, upstreamCert.Equal(presentedCert))
}

// -- Test Cases: Interception Hooks (Integration) --

// Verifies that request hooks can inspect and modify a request.
func TestProxy_Hooks_RequestModification(t *testing.T) {
	// 1. Setup upstream server (Echoes a specific header)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Header.Get("X-Proxy-Modified")))
	}))
	defer upstream.Close()

	// 2. Setup proxy and register hook
	proxy, _, _ := setupProxyTest(t, false)

	proxy.AddRequestHook(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		r.Header.Set("X-Proxy-Modified", "HookWasHere")
		return r, nil
	})

	proxyAddr := startProxyServer(t, proxy)
	client := createProxyClient(t, proxyAddr, nil)

	// 3. Execute request and verify
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "HookWasHere", string(body))
}

// Verifies that response hooks can inspect and modify a response.
func TestProxy_Hooks_ResponseModification(t *testing.T) {
	// 1. Setup upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OriginalBody"))
	}))
	defer upstream.Close()

	// 2. Setup proxy and register hook
	proxy, _, _ := setupProxyTest(t, false)

	proxy.AddResponseHook(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		r.Header.Set("X-Response-Modified", "true")
		newBody := "ModifiedBody"
		r.Body = io.NopCloser(strings.NewReader(newBody))
		r.ContentLength = int64(len(newBody))
		return r
	})

	proxyAddr := startProxyServer(t, proxy)
	client := createProxyClient(t, proxyAddr, nil)

	// 3. Execute request and verify
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "true", resp.Header.Get("X-Response-Modified"))
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ModifiedBody", string(body))
}

// Verifies a request hook can return a response directly, bypassing the upstream server.
func TestProxy_Hooks_ShortCircuit(t *testing.T) {
	// 1. Setup upstream server
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()

	// 2. Setup proxy and register short-circuiting hook
	proxy, _, _ := setupProxyTest(t, false)

	proxy.AddRequestHook(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusTeapot, "Short Circuited")
	})

	proxyAddr := startProxyServer(t, proxy)
	client := createProxyClient(t, proxyAddr, nil)

	// 3. Execute request and verify
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	assert.False(t, upstreamHit, "Upstream server should not have been hit")
}

// -- Test Cases: Robustness and Error Handling --

// Verifies proxy behavior when the upstream connection fails.
func TestProxy_Robustness_UpstreamFailure(t *testing.T) {
	// 1. Define a non-routable address for the target
	targetURL := "http://192.0.2.1:8080" // TEST-NET-1

	// 2. Setup proxy
	proxy, _, _ := setupProxyTest(t, false)
	// Configure the proxy's upstream client with a short timeout
	proxy.clientConfig.DialerConfig.Timeout = 100 * time.Millisecond
	// We must reconfigure the transport after changing the config post-initialization
	proxy.proxy.Tr = NewHTTPTransport(proxy.clientConfig)

	proxyAddr := startProxyServer(t, proxy)
	client := createProxyClient(t, proxyAddr, nil)

	// 3. Execute request
	resp, err := client.Get(targetURL)

	// The client should receive a response from the proxy, not a connection error.
	require.NoError(t, err)
	defer resp.Body.Close()

	// 4. Verify the proxy generated a 502 Bad Gateway response
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Proxy error: upstream connection failed")
}

// Verifies error handling if a request hook returns invalid data.
func TestProxy_Robustness_MalformedRequestHookReturn(t *testing.T) {
	proxy, _, _ := setupProxyTest(t, false)

	// Register a malfunctioning hook: returns nil request without a response.
	proxy.AddRequestHook(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return nil, nil
	})

	// Test the internal handler directly (unit test style)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, resp := proxy.handleRequest(req, &goproxy.ProxyCtx{})

	// Verify the proxy generates a 500 Internal Server Error
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Proxy error: request hook malfunction")
}

// Verifies error handling if a response hook returns nil.
func TestProxy_Robustness_MalformedResponseHookReturn(t *testing.T) {
	proxy, _, _ := setupProxyTest(t, false)

	// Register a malfunctioning hook: returns nil response.
	proxy.AddResponseHook(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		return nil
	})
	// Register a second hook to ensure the chain breaks.
	var secondHookCalled bool
	proxy.AddResponseHook(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		secondHookCalled = true
		return r
	})

	// Test the internal handler directly
	originalResp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	originalResp.Header.Set("X-Test", "Original")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	finalResp := proxy.handleResponse(originalResp, &goproxy.ProxyCtx{Req: req})

	// Verify the response is the original response, as the chain broke but the proxy recovered.
	require.NotNil(t, finalResp)
	assert.Equal(t, "Original", finalResp.Header.Get("X-Test"))
	assert.False(t, secondHookCalled, "The hook chain should break after a nil return")
}

// Verifies thread safe registration of hooks by checking for race conditions.
func TestAddHooks_Concurrency(t *testing.T) {
	proxy, _, _ := setupProxyTest(t, false)

	wg := sync.WaitGroup{}
	count := 100
	reqHandler := func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) { return r, nil }
	respHandler := func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response { return r }

	// Concurrently add hooks
	for i := 0; i < count; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			proxy.AddRequestHook(reqHandler)
		}()
		go func() {
			defer wg.Done()
			proxy.AddResponseHook(respHandler)
		}()
	}
	wg.Wait()

	// Verify registration count
	proxy.hooksMutex.RLock()
	defer proxy.hooksMutex.RUnlock()
	assert.Len(t, proxy.requestHooks, count)
	assert.Len(t, proxy.responseHooks, count)
}
