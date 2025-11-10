// internal/browser/network/customhttp/client_test.go
package customhttp

import (
	"context"
	"crypto/tls" // Added for explicit TLS configuration
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap" // Added for zap.NewNop()
	"go.uber.org/zap/zaptest"
)

type mockCredProvider struct {
	username string
	password string
	err      error
}

func (m *mockCredProvider) GetCredentials(host string, realm string) (string, string, error) {
	if m.err != nil {
		return "", "", m.err
	}
	return m.username, m.password, nil
}

func TestCustomClient_Do_SimpleGET(t *testing.T) {
	handler := &MockServerHandler{
		StatusCode: http.StatusOK,
		Body:       []byte("hello world"),
		Headers:    map[string]string{"Content-Type": "text/plain"},
	}
	server := NewMockServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(body))
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
}

func TestCustomClient_Do_Redirect(t *testing.T) {
	finalURL := ""
	handler := &MockServerHandler{
		StatusCode: http.StatusOK,
		Body:       []byte("final destination"),
	}
	finalServer := NewMockServer(handler)
	defer finalServer.Close()
	finalURL = finalServer.URL

	redirectHandler := &MockServerHandler{
		StatusCode:  http.StatusFound,
		RedirectURL: finalURL,
	}
	redirectServer := NewMockServer(redirectHandler)
	defer redirectServer.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", redirectServer.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "final destination", string(body))
}

func TestCustomClient_Do_MaxRedirects(t *testing.T) {
	redirectHandler := &MockServerHandler{
		StatusCode: http.StatusFound,
		Redirects:  15, // more than the default max
	}
	redirectServer := NewMockServer(redirectHandler)
	defer redirectServer.Close()
	redirectHandler.RedirectURL = redirectServer.URL // redirect to self

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	client := NewCustomClient(config, logger)
	client.MaxRedirects = 10
	defer client.CloseAll()

	req, err := http.NewRequest("GET", redirectServer.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum redirects (10) followed")
}

func TestCustomClient_Do_Retry(t *testing.T) {
	attempt := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempt < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			attempt++
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.RetryPolicy.InitialBackoff = 1 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, attempt)
}

func TestCustomClient_Do_Cookies(t *testing.T) {
	var receivedCookies string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCookies = r.Header.Get("Cookie")
		cookie := &http.Cookie{Name: "server-cookie", Value: "sv", Path: "/"}
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	serverURL, _ := url.Parse(server.URL)
	initialCookie := &http.Cookie{Name: "client-cookie", Value: "cv", Path: "/"}
	client.Config.CookieJar.SetCookies(serverURL, []*http.Cookie{initialCookie})

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "client-cookie=cv", receivedCookies)

	cookies := client.Config.CookieJar.Cookies(serverURL)
	assert.Len(t, cookies, 2)
}

func TestCustomClient_Do_BasicAuth(t *testing.T) {
	handler := &MockServerHandler{
		StatusCode:   http.StatusOK,
		Body:         []byte("authenticated"),
		AuthRequired: true,
		AuthUser:     "testuser",
		AuthPass:     "testpass",
	}
	server := NewMockServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.CredentialsProvider = &mockCredProvider{
		username: "testuser",
		password: "testpass",
	}
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "authenticated", string(body))
}

func TestCustomClient_Do_RequestBodyRetry(t *testing.T) {
	attempt := 0
	var receivedBody string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		if attempt < 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			attempt++
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.RetryPolicy.InitialBackoff = 1 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	body := "request body"
	req, err := http.NewRequest("POST", server.URL, strings.NewReader(body))
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, body, receivedBody)
	assert.Equal(t, 1, attempt)
}

func TestCustomClient_Do_RequestTimeout(t *testing.T) {
	handler := &MockServerHandler{
		Delay: 200 * time.Millisecond,
	}
	server := NewMockServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.RequestTimeout = 100 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(context.Background(), req)
	require.Error(t, err)
	// Check for timeout error (specific string depends on H1/H2 implementation)
	assert.Contains(t, err.Error(), "timeout")
}

func TestCustomClient_ConnectionEviction(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.IdleConnTimeout = 50 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	// Initialize clients properly to prevent nil pointer dereferences when Close() or IsIdle() are called.
	nopLogger := zap.NewNop()
	h1c := &H1Client{Conn: nil, Logger: nopLogger}
	// H2Client requires maps and channels to be initialized for safety, as H2Client.Close() accesses them.
	h2c := &H2Client{
		Conn:     nil,
		Logger:   nopLogger,
		streams:  make(map[uint32]*h2StreamState),
		doneChan: make(chan struct{}),
		pingAcks: make(map[uint64]chan struct{}),
	}

	// We must lock the client when manipulating its internal state to prevent data races with the background evictor.
	client.mu.Lock()
	client.h1Clients["host1"] = h1c
	client.h2Clients["host2"] = h2c
	client.mu.Unlock()

	time.Sleep(100 * time.Millisecond)

	// Manually trigger eviction for the test.
	client.evictIdleConnections(config.IdleConnTimeout)

	// Lock again to verify the state safely. Use RLock for reading.
	client.mu.RLock()
	assert.Empty(t, client.h1Clients, "H1 client should have been evicted")
	assert.Empty(t, client.h2Clients, "H2 client should have been evicted")
	client.mu.RUnlock()
}

// TestCustomClient_H2_Fallback verifies fallback to H1 when H2 negotiation fails.
func TestCustomClient_H2_Fallback(t *testing.T) {
	// h2RejectionCount := 0 // Not needed as we test negotiation failure.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			// This should not happen if H2 is disabled on the server.
			t.Error("Received H2 request on H1-only server configuration")
			http.Error(w, "H2 should not have been negotiated", http.StatusInternalServerError)
			return
		}
		// H1 request should succeed
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("h1 fallback ok"))
	})

	// Create a TLS server that explicitly only supports H1.
	server := httptest.NewUnstartedServer(handler)
	// Configure TLS to explicitly exclude "h2" from ALPN.
	if server.TLS == nil {
		server.TLS = &tls.Config{}
	}
	server.TLS.NextProtos = []string{"http/1.1"}
	server.StartTLS()
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.InsecureSkipVerify = true
	// Ensure retries are enabled, although negotiation fallback happens on the first attempt.
	config.RetryPolicy.MaxRetries = 3
	config.RetryPolicy.InitialBackoff = 1 * time.Millisecond

	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "h1 fallback ok", string(body))

	// We primarily care that the final result was a successful H1 connection.
	assert.Equal(t, 1, resp.ProtoMajor)
}
