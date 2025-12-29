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
	// Use PUT instead of POST because POST (non-idempotent) is no longer retried on status 503.
	req, err := http.NewRequest("PUT", server.URL, strings.NewReader(body))
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, body, receivedBody)
	assert.Equal(t, 1, attempt)
}

func TestCustomClient_Do_Retry_NonIdempotent_Status(t *testing.T) {
	attempt := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		// Always return 503 (Retryable status)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.RetryPolicy.MaxRetries = 3
	config.RetryPolicy.InitialBackoff = 1 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	body := "data"
	req, err := http.NewRequest("POST", server.URL, strings.NewReader(body))
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err) // We expect a response (the 503), not an error
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	// POST (non-idempotent) should NOT be retried on 503 status.
	assert.Equal(t, 1, attempt)
}

// TestCustomClient_Do_Retry_NonIdempotent_NetworkError verifies that non-idempotent requests ARE retried on network errors.
func TestCustomClient_Do_Retry_NonIdempotent_NetworkError(t *testing.T) {
	attempt := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			// Close the connection immediately on the first attempt (network error)
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, _ := hijacker.Hijack()
				conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.RetryPolicy.MaxRetries = 3
	config.RetryPolicy.InitialBackoff = 1 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	body := "data"
	req, err := http.NewRequest("POST", server.URL, strings.NewReader(body))
	require.NoError(t, err)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, attempt, "POST request should be retried on network error")
}

func TestCustomClient_Do_Redirect_PreserveAuthSameOrigin(t *testing.T) {
	var finalAuthHeader string

	// Single server instance handles both paths.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			// Redirect to /end on the same server
			w.Header().Set("Location", "/end")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/end" {
			finalAuthHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(t)
	client := NewCustomClient(NewBrowserClientConfig(), logger)
	defer client.CloseAll()

	startURL := server.URL + "/start"
	req, err := http.NewRequest("GET", startURL, nil)
	require.NoError(t, err)

	// Set the authorization header manually
	authValue := "Bearer testtoken123"
	req.Header.Set("Authorization", authValue)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Authorization header should be preserved on same-origin redirect.
	assert.Equal(t, authValue, finalAuthHeader)
}

func TestCustomClient_Do_Redirect_StripAuthCrossOrigin(t *testing.T) {
	var finalAuthHeader string

	// Server 2 (Cross-origin target)
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	server2 := httptest.NewServer(handler2)
	defer server2.Close()

	// Server 1 (Origin)
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to Server 2
		w.Header().Set("Location", server2.URL)
		w.WriteHeader(http.StatusFound)
	})
	server1 := httptest.NewServer(handler1)
	defer server1.Close()

	logger := zaptest.NewLogger(t)
	client := NewCustomClient(NewBrowserClientConfig(), logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", server1.URL, nil)
	require.NoError(t, err)

	// Set the authorization header
	authValue := "Bearer testtoken123"
	req.Header.Set("Authorization", authValue)

	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Authorization header should be stripped on cross-origin redirect.
	assert.Empty(t, finalAuthHeader)
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

// TestCustomClient_H2_Fallback_Persistence verifies that once H2 negotiation fails,
// the client remembers this and does not attempt H2 on subsequent retries or requests.
func TestCustomClient_H2_Fallback_Persistence(t *testing.T) {
	attempt := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			t.Error("Received H2 request, which should have been prevented by fallback persistence.")
			http.Error(w, "H2 not allowed", http.StatusInternalServerError)
			return
		}

		// Fail the first H1 attempt to trigger a retry.
		if attempt == 0 {
			attempt++
			w.WriteHeader(http.StatusServiceUnavailable) // Retryable error
			return
		}
		// Succeed on the second H1 attempt.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("h1 success"))
	})

	// Create a TLS server that explicitly only supports H1 (forcing H2 negotiation failure).
	server := httptest.NewUnstartedServer(handler)
	if server.TLS == nil {
		server.TLS = &tls.Config{}
	}
	server.TLS.NextProtos = []string{"http/1.1"}
	server.StartTLS()
	defer server.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.InsecureSkipVerify = true
	config.RetryPolicy.MaxRetries = 1
	config.RetryPolicy.InitialBackoff = 1 * time.Millisecond

	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	// Execute the request. Logic: H2 fail -> H1 (503) -> Retry -> Direct H1 (200).
	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, resp.ProtoMajor)

	// Verify internal state: the host should be marked as H2 unsupported.
	serverURL, _ := url.Parse(server.URL)
	client.mu.RLock()
	isUnsupported := client.h2Unsupported[serverURL.Host]
	client.mu.RUnlock()
	assert.True(t, isUnsupported, "Host should be marked as H2 unsupported after negotiation failure.")

	// Verify subsequent requests also skip H2.
	req2, _ := http.NewRequest("GET", server.URL, nil)
	resp2, err := client.Do(context.Background(), req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, 1, resp2.ProtoMajor, "Subsequent request should directly use H1")
}

func TestEnsureBodyReplayable_Limit(t *testing.T) {
	// Define the limit (assuming MaxReplayableBodyBytes is 2MB in client.go)
	const limit = 2 * 1024 * 1024

	t.Run("Content-Length exceeds limit", func(t *testing.T) {
		// Use io.NopCloser to prevent http.NewRequest from automatically setting GetBody,
		// which would bypass the logic we are testing.
		body := io.NopCloser(strings.NewReader("small body"))
		req, _ := http.NewRequest("POST", "http://example.com", body)
		req.ContentLength = limit + 1

		err := ensureBodyReplayable(req)
		assert.Error(t, err)
		if err != nil {
			assert.Contains(t, err.Error(), "request body too large")
		}
	})

	t.Run("Body read exceeds limit (unknown Content-Length)", func(t *testing.T) {
		// Create a reader that generates data exceeding the limit.
		largeBody := strings.Repeat("a", limit+10)
		// Use io.NopCloser to prevent http.NewRequest from automatically setting GetBody.
		body := io.NopCloser(strings.NewReader(largeBody))
		req, _ := http.NewRequest("POST", "http://example.com", body)
		// Content-Length is unknown (-1)
		req.ContentLength = -1

		err := ensureBodyReplayable(req)
		assert.Error(t, err)
		if err != nil {
			assert.Contains(t, err.Error(), "request body exceeded limit")
		}
	})

	t.Run("Body within limit", func(t *testing.T) {
		bodyStr := strings.Repeat("a", limit)
		body := strings.NewReader(bodyStr)
		req, _ := http.NewRequest("POST", "http://example.com", body)

		err := ensureBodyReplayable(req)
		require.NoError(t, err)
		assert.NotNil(t, req.GetBody)
	})
}
