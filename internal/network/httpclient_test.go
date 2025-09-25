// internal/network/httpclient_test.go
package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"golang.org/x/net/http2"
)

// -- Test Cases: Configuration and Defaults (ClientConfig) --

// TestNewDefaultClientConfig_Optimizations verifies the defaults are optimized for scanning.
func TestNewDefaultClientConfig_Optimizations(t *testing.T) {
	config := NewDefaultClientConfig()

	assert.Equal(t, DefaultRequestTimeout, config.RequestTimeout)
	assert.Equal(t, DefaultResponseHeaderTimeout, config.ResponseHeaderTimeout)
	assert.Equal(t, DefaultMaxIdleConns, config.MaxIdleConns)
	assert.Equal(t, DefaultMaxIdleConnsPerHost, config.MaxIdleConnsPerHost)
	assert.True(t, config.ForceHTTP2, "HTTP/2 should be preferred by default")
	require.NotNil(t, config.DialerConfig)
	assert.True(t, config.DialerConfig.ForceNoDelay, "TCP_NODELAY should be enabled for HTTP clients")
	assert.NotNil(t, config.Logger)
}

// TestConfigureTLS_Defaults verifies the strong security defaults of the TLS configuration helper.
func TestConfigureTLS_Defaults(t *testing.T) {
	config := NewDefaultClientConfig()
	tlsConfig := configureTLS(config)

	require.NotNil(t, tlsConfig, "TLS config should never be nil")
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.False(t, tlsConfig.InsecureSkipVerify)
	expectedCiphers := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	assert.Equal(t, expectedCiphers, tlsConfig.CipherSuites)
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
	config.IgnoreTLSErrors = true

	tlsConfig := configureTLS(config)

	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	assert.Equal(t, "custom.sni", tlsConfig.ServerName)
	assert.True(t, tlsConfig.InsecureSkipVerify)
	assert.NotSame(t, customTLS, tlsConfig)
	assert.False(t, customTLS.InsecureSkipVerify, "Original object should not be modified")
}

// -- Test Cases: Transport Creation (NewHTTPTransport) --

func TestNewHTTPTransport_ConfigurationMapping(t *testing.T) {
	config := NewDefaultClientConfig()
	config.MaxIdleConns = 55
	config.IdleConnTimeout = 99 * time.Second
	config.DisableCompression = true
	config.ResponseHeaderTimeout = 5 * time.Second
	config.DisableKeepAlives = true

	transport := NewHTTPTransport(config)

	assert.Equal(t, 55, transport.MaxIdleConns)
	assert.Equal(t, 99*time.Second, transport.IdleConnTimeout)
	assert.True(t, transport.DisableCompression)
	assert.Equal(t, 5*time.Second, transport.ResponseHeaderTimeout)
	assert.True(t, transport.DisableKeepAlives, "DisableKeepAlives should be propagated")
}

func TestNewHTTPTransport_Robustness_NilConfig(t *testing.T) {
	transport := NewHTTPTransport(nil)
	assert.Equal(t, DefaultMaxIdleConns, transport.MaxIdleConns)
	assert.NotNil(t, transport.DialContext)
	assert.NotNil(t, transport.TLSClientConfig)
}

func TestNewHTTPTransport_ProxyConfiguration(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	config := NewDefaultClientConfig()
	config.ProxyURL = proxyURL

	transport := NewHTTPTransport(config)
	require.NotNil(t, transport.Proxy)

	req, _ := http.NewRequest("GET", "http://target.com", nil)
	resultURL, err := transport.Proxy(req)

	require.NoError(t, err)
	assert.Equal(t, proxyURL, resultURL)
}

func TestNewHTTPTransport_HTTP2_Enabled(t *testing.T) {
	config := NewDefaultClientConfig()
	config.ForceHTTP2 = true
	transport := NewHTTPTransport(config)

	assert.True(t, transport.ForceAttemptHTTP2)
	require.NotNil(t, transport.TLSClientConfig)
	assert.Contains(t, transport.TLSClientConfig.NextProtos, "h2")
	assert.Contains(t, transport.TLSClientConfig.NextProtos, "http/1.1")
}

func TestNewHTTPTransport_HTTP2_Disabled(t *testing.T) {
	config := NewDefaultClientConfig()
	config.ForceHTTP2 = false
	transport := NewHTTPTransport(config)

	assert.False(t, transport.ForceAttemptHTTP2)
	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, []string{"http/1.1"}, transport.TLSClientConfig.NextProtos)
}

// -- Test Cases: Client Behavior (NewClient and Integration) --

func TestNewClient_RedirectPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
		}
	}))
	defer server.Close()
	client := NewClient(nil)

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/redirected", resp.Header.Get("Location"))
}

func TestClient_TimeoutBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := NewDefaultClientConfig()
	config.RequestTimeout = 100 * time.Millisecond
	client := NewClient(config)

	startTime := time.Now()
	resp, err := client.Get(server.URL)
	duration := time.Since(startTime)

	assert.Error(t, err)
	assert.Nil(t, resp)
	urlErr, ok := err.(*url.Error)
	require.True(t, ok)
	assert.ErrorIs(t, urlErr.Err, context.DeadlineExceeded)
	assert.Less(t, duration, 500*time.Millisecond, "Timeout took significantly longer than expected")
}

func TestClient_HTTPS_Integration(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	// This is the key change: we must explicitly enable HTTP/2 on the test server.
	http2.ConfigureServer(server.Config, &http2.Server{})
	server.StartTLS()
	defer server.Close()

	caCertPool := x509.NewCertPool()
	// The httptest server uses a self signed certificate. We need to get it and trust it.
	caCertPool.AddCert(server.Certificate())

	config := NewDefaultClientConfig()
	config.TLSConfig = &tls.Config{RootCAs: caCertPool}
	config.ForceHTTP2 = true
	client := NewClient(config)

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Hello, client\n", string(body))
	assert.Equal(t, "HTTP/2.0", resp.Proto)
}

func TestClient_InsecureSkipVerify_Integration(t *testing.T) {
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

func TestClient_Behavior_ConnectionPooling(t *testing.T) {
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
	config.DisableKeepAlives = false
	client := NewClient(config)

	iterations := 5
	for i := 0; i < iterations; i++ {
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	assert.Less(t, len(remoteAddrs), iterations, "Connections should have been reused")
	assert.Greater(t, len(remoteAddrs), 0)
}

