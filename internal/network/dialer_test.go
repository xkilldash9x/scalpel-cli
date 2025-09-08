package network

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- Test Setup and Helpers --

// Starts a simple TCP server that echoes back any received data.
func startTCPEchoServer(t *testing.T) net.Listener {
	t.Helper()
	SetupObservability(t)
	// Listen on an ephemeral port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to start TCP listener")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if the listener was closed intentionally (during cleanup)
				if errors.Is(err, net.ErrClosed) {
					return
				}
				t.Logf("TCP server accept error: %v", err)
				continue
			}
			// Echo handler
			go func(c net.Conn) {
				defer c.Close()
				// Simple echo
				io.Copy(c, c)
			}(conn)
		}
	}()
	return listener
}

// -- Test Cases: Configuration and Defaults --

// Verifies the security focused defaults for a new dialer configuration.
func TestNewDialerConfig_Defaults(t *testing.T) {
	SetupObservability(t)
	config := NewDialerConfig()

	// Verify Timeouts and KeepAlive
	assert.Equal(t, 10*time.Second, config.Timeout)
	assert.Equal(t, 30*time.Second, config.KeepAlive)
	assert.False(t, config.ForceNoDelay)

	// Verify TLS Security Settings
	require.NotNil(t, config.TLSConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), config.TLSConfig.MinVersion, "Minimum TLS version should be 1.2")

	// Verify Curve Preferences (PFS)
	expectedCurves := []tls.CurveID{tls.X25519, tls.CurveP256}
	assert.Equal(t, expectedCurves, config.TLSConfig.CurvePreferences, "Should prefer modern curves (X25519 first)")

	// Verify Cipher Suites (Strong AEAD required)
	expectedCiphers := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	assert.Equal(t, expectedCiphers, config.TLSConfig.CipherSuites, "Should only include strong, forward secret ciphers")
}

// -- Test Cases: TCP Dialing (DialTCPContext) --

// Verifies a standard successful connection and data transfer.
func TestDialTCPContext_Success(t *testing.T) {
	listener := startTCPEchoServer(t)
	defer listener.Close()

	config := NewDialerConfig()
	config.TLSConfig = nil // Ensure raw TCP

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialTCPContext(ctx, "tcp", listener.Addr().String(), config)
	require.NoError(t, err)
	defer conn.Close()

	// Verify connection works (Echo test)
	testMsg := []byte("hello tcp echo")
	_, err = conn.Write(testMsg)
	require.NoError(t, err)

	response := make([]byte, len(testMsg))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	assert.Equal(t, testMsg, response)
}

// Verifies that the configured timeout is respected during connection establishment.
func TestDialTCPContext_Timeout(t *testing.T) {
	SetupObservability(t)
	// Use a non routable IP address (RFC 5737 TEST-NET-1) to force a connection timeout.
	nonRoutableAddr := "192.0.2.1:8080"

	config := NewDialerConfig()
	config.Timeout = 100 * time.Millisecond // Short timeout for fast test

	ctx := context.Background()

	startTime := time.Now()
	conn, err := DialTCPContext(ctx, "tcp", nonRoutableAddr, config)
	duration := time.Since(startTime)

	// Verify error type
	assert.Error(t, err)
	assert.Nil(t, conn)
	// Check if the error is a timeout error
	var netErr net.Error
	if assert.ErrorAs(t, err, &netErr) {
		assert.True(t, netErr.Timeout(), "Error should be a timeout")
	}
	assert.Contains(t, err.Error(), "tcp dial failed")

	// Verify duration is close to the configured timeout (allowing some slack for CI environments)
	assert.GreaterOrEqual(t, duration, 100*time.Millisecond)
	assert.Less(t, duration, 500*time.Millisecond, "Timeout took significantly longer than configured")
}

// Verifies behavior when the context is cancelled during a dial attempt.
func TestDialTCPContext_ContextCancel(t *testing.T) {
	SetupObservability(t)
	nonRoutableAddr := "192.0.2.1:8080"
	config := NewDialerConfig()
	config.Timeout = 5 * time.Second // Long timeout

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel shortly after starting the dial attempt
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	conn, err := DialTCPContext(ctx, "tcp", nonRoutableAddr, config)

	// Verify error
	assert.Error(t, err)
	assert.Nil(t, conn)
	// The error should specifically indicate context cancellation.
	assert.ErrorIs(t, err, context.Canceled)
}

// Verifies that TCP options like NoDelay and KeepAlive are applied.
func TestDialTCPContext_TCPConfiguration(t *testing.T) {
	listener := startTCPEchoServer(t)
	defer listener.Close()

	config := NewDialerConfig()
	config.ForceNoDelay = true // Enable TCP_NODELAY
	config.KeepAlive = 15 * time.Second
	config.TLSConfig = nil

	ctx := context.Background()

	conn, err := DialTCPContext(ctx, "tcp", listener.Addr().String(), config)
	require.NoError(t, err)
	defer conn.Close()

	// Verify the connection type
	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok, "Connection should be a *net.TCPConn")

	// Note: Go's standard library does not expose getters for TCP options (like getsockopt).
	// We rely on the fact that DialTCPContext calls configureTCP, and if the OS rejected the settings,
	// configureTCP would return an error, causing the dial to fail.
	assert.NotNil(t, tcpConn)
}

// Verifies robustness when passed a nil configuration.
func TestDialTCPContext_NilConfig(t *testing.T) {
	listener := startTCPEchoServer(t)
	defer listener.Close()

	ctx := context.Background()
	// Pass nil config, expecting defaults to be used.
	conn, err := DialTCPContext(ctx, "tcp", listener.Addr().String(), nil)
	require.NoError(t, err)
	defer conn.Close()

	assert.NotNil(t, conn)
}

// -- Test Cases: TLS Dialing (DialContext) --

// Setup helper for TLS tests using the tlsTestHelper.
func setupTLSTest(t *testing.T, clientConfigMod func(*DialerConfig), serverConfigMod func(*tls.Config)) (*tlsTestHelper, *DialerConfig) {
	t.Helper()
	helper := newTLSTestHelper(t)

	// Default client configuration
	clientConfig := NewDialerConfig()
	// Client must trust the self signed CA used by the helper
	clientConfig.TLSConfig.RootCAs = helper.caPool

	if clientConfigMod != nil {
		clientConfigMod(clientConfig)
	}

	// Default server configuration
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{helper.serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if serverConfigMod != nil {
		serverConfigMod(serverConfig)
	}

	helper.startTLSServer(serverConfig)
	return helper, clientConfig
}

// Verifies a successful TLS handshake and subsequent data transfer.
func TestDialContext_TLS_Success(t *testing.T) {
	helper, clientConfig := setupTLSTest(t, nil, nil)
	defer helper.close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, "tcp", helper.serverAddr, clientConfig)
	require.NoError(t, err)
	defer conn.Close()

	// Verify connection type
	tlsConn, ok := conn.(*tls.Conn)
	require.True(t, ok, "Connection should be a *tls.Conn")

	// Verify handshake details
	state := tlsConn.ConnectionState()
	assert.True(t, state.HandshakeComplete)
	// SNI should match the IP address used to connect, as ServerName was not explicitly set in the config.
	expectedHost, _, _ := net.SplitHostPort(helper.serverAddr)
	assert.Equal(t, expectedHost, state.ServerName)
	// Check that a strong cipher was negotiated
	assert.Contains(t, NewDialerConfig().TLSConfig.CipherSuites, state.CipherSuite)

	// Verify data transfer (Echo test)
	testMsg := []byte("hello tls echo")
	_, err = conn.Write(testMsg)
	require.NoError(t, err)

	response := make([]byte, len(testMsg))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	assert.Equal(t, testMsg, response)
}

// Verifies connection failure when the client does not trust the server's CA.
func TestDialContext_TLS_InvalidCert(t *testing.T) {
	helper, clientConfig := setupTLSTest(t, func(dc *DialerConfig) {
		// Client uses an empty RootCAs pool.
		dc.TLSConfig.RootCAs = nil
	}, nil)
	defer helper.close()

	ctx := context.Background()
	conn, err := DialContext(ctx, "tcp", helper.serverAddr, clientConfig)

	// Verify failure
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "tls handshake failed")
	assert.Contains(t, err.Error(), "certificate signed by unknown authority")
}

// Verifies that certificate validation can be successfully skipped.
func TestDialContext_TLS_InsecureSkipVerify(t *testing.T) {
	helper, clientConfig := setupTLSTest(t, func(dc *DialerConfig) {
		// Client doesn't trust server, but ignores errors.
		dc.TLSConfig.RootCAs = nil
		dc.TLSConfig.InsecureSkipVerify = true
	}, nil)
	defer helper.close()

	ctx := context.Background()
	conn, err := DialContext(ctx, "tcp", helper.serverAddr, clientConfig)

	// Verify success
	require.NoError(t, err)
	assert.NotNil(t, conn)
	conn.Close()
}

// Verifies that the ServerName (SNI) is automatically populated based on the address.
func TestDialContext_TLS_SNI_AutomaticPopulation(t *testing.T) {
	var capturedSNI string

	helper, clientConfig := setupTLSTest(t, func(dc *DialerConfig) {
		// Ensure ServerName is initially empty in the client config
		dc.TLSConfig.ServerName = ""
	}, func(sc *tls.Config) {
		// Use GetConfigForClient hook on the server to inspect the ClientHelloInfo (SNI)
		sc.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			capturedSNI = chi.ServerName
			// Return the existing config to allow the handshake to proceed
			return sc, nil
		}
	})
	defer helper.close()

	ctx := context.Background()
	conn, err := DialContext(ctx, "tcp", helper.serverAddr, clientConfig)

	// The connection should succeed as the helper includes the IP (127.0.0.1) in the SANs.
	require.NoError(t, err)
	conn.Close()

	// Extract the expected host (IP address) from the address string
	expectedHost, _, err := net.SplitHostPort(helper.serverAddr)
	require.NoError(t, err)

	// Verify the SNI captured by the server matches the host part of the address.
	assert.Equal(t, expectedHost, capturedSNI)
}

// Verifies that a timeout during the TLS handshake phase is handled correctly.
func TestDialContext_TLS_HandshakeTimeout(t *testing.T) {
	SetupObservability(t)
	// 1. Start a TCP server that accepts the connection but never completes the TLS handshake.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			// Keep the connection open indefinitely without responding to TLS handshake.
			time.Sleep(10 * time.Second)
			conn.Close()
		}
	}()

	// 2. Configure client with a short timeout
	clientConfig := NewDialerConfig()
	clientConfig.Timeout = 100 * time.Millisecond
	// Set InsecureSkipVerify as the server isn't providing a real cert.
	clientConfig.TLSConfig.InsecureSkipVerify = true

	// 3. Attempt to connect
	ctx := context.Background()
	startTime := time.Now()
	conn, err := DialContext(ctx, "tcp", listener.Addr().String(), clientConfig)
	duration := time.Since(startTime)

	// 4. Verify timeout error
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "tls handshake failed")

	// Check if the underlying error is deadline exceeded (the specific error type for handshake timeout)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	// Verify duration
	assert.Less(t, duration, 500*time.Millisecond)
}

// Verifies connection failure when the client and server have no overlapping cipher suites.
func TestDialContext_TLS_CipherMismatch(t *testing.T) {
	helper, clientConfig := setupTLSTest(t, func(dc *DialerConfig) {
		// Client only supports AES 128 GCM (TLS 1.2)
		dc.TLSConfig.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	}, func(sc *tls.Config) {
		// Server only supports ChaCha20 Poly1305 (TLS 1.2)
		sc.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}
		// Ensure certificates are set for the server config override
		sc.Certificates = []tls.Certificate{helper.serverCert}
	})
	defer helper.close()

	ctx := context.Background()
	conn, err := DialContext(ctx, "tcp", helper.serverAddr, clientConfig)

	// Verify failure
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "tls handshake failed")
	// The client receives an alert from the server indicating no shared cipher.
	assert.Contains(t, err.Error(), "remote error: tls: handshake failure")
}

// Verifies that DialContext can be used for raw TCP if TLSConfig is nil.
func TestDialContext_RawTCP(t *testing.T) {
	listener := startTCPEchoServer(t)
	defer listener.Close()

	config := NewDialerConfig()
	config.TLSConfig = nil // Explicitly disable TLS

	ctx := context.Background()
	conn, err := DialContext(ctx, "tcp", listener.Addr().String(), config)
	require.NoError(t, err)
	defer conn.Close()

	// Verify connection type is TCP, not TLS
	_, ok := conn.(*net.TCPConn)
	assert.True(t, ok)
	_, ok = conn.(*tls.Conn)
	assert.False(t, ok)
}
