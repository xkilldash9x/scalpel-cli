// browser/network/proxy.go
package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"
)

// Note: This file implements an Interception (MITM) Proxy Server.
// The configuration for a client to *use* a forward proxy is handled in dialer.go and httpclient.go.

var (
	// Ensures configureMITM initialization logic runs exactly once.
	mitmInitOnce sync.Once
	// Stores the result of the MITM initialization attempt.
	mitmInitError error
	// Tracks whether MITM is successfully configured globally.
	isMITMEnabled bool
)

// RequestHandler is the function signature for a hook that can inspect and/or
// modify an HTTP request as it passes through the proxy. It can either return a
// modified request to be forwarded, or it can generate a response directly,
// effectively blocking the request from reaching its destination.
type RequestHandler func(*http.Request, *goproxy.ProxyCtx) (*http.Request, *http.Response)

// ResponseHandler is the function signature for a hook that can inspect and/or
// modify an HTTP response as it returns from the upstream server.
type ResponseHandler func(*http.Response, *goproxy.ProxyCtx) *http.Response

// ProxyTransportConfig defines the configuration for the proxy's own upstream
// connections. This allows for scenarios like proxy chaining, where the interception
// proxy forwards its traffic through another downstream proxy.
type ProxyTransportConfig struct {
	// DialerConfig specifies the low-level dialing configuration for the proxy's
	// outgoing connections.
	DialerConfig *DialerConfig
}

// InterceptionProxy implements a full Man-in-the-Middle (MITM) proxy server that
// can intercept, inspect, and modify both HTTP and HTTPS traffic. It uses a
// dynamically-pluggable hook system to allow for custom processing of requests
// and responses.
//
// When provided with a CA certificate and key, it can perform TLS interception
// for HTTPS traffic. If not, it will operate as a simple tunneling proxy for
// HTTPS requests.
type InterceptionProxy struct {
	proxy           *goproxy.ProxyHttpServer
	server          *http.Server
	serverMutex     sync.Mutex
	transportConfig *ProxyTransportConfig
	requestHooks    []RequestHandler
	responseHooks   []ResponseHandler
	hooksMutex      sync.RWMutex
	logger          *zap.Logger
}

// NewInterceptionProxy creates, configures, and returns a new InterceptionProxy.
// It initializes the underlying `goproxy` server, sets up the transport for
// upstream connections (including support for proxy chaining), and configures
// the MITM capabilities if a CA certificate and key are provided.
//
// Parameters:
//   - caCert: The PEM-encoded CA certificate for signing intercepted TLS connections.
//   - caKey: The PEM-encoded private key for the CA certificate.
//   - transportConfig: Configuration for the proxy's upstream connections.
//   - logger: The logger for the proxy to use.
//
// Returns the configured InterceptionProxy or an error if configuration fails.
func NewInterceptionProxy(caCert, caKey []byte, transportConfig *ProxyTransportConfig, logger *zap.Logger) (*InterceptionProxy, error) {
	proxy := goproxy.NewProxyHttpServer()

	if logger == nil {
		logger = zap.NewNop()
	}
	log := logger.Named("interception_proxy")

	// Create a defensive copy of the transport config.
	var cfgCopy ProxyTransportConfig
	if transportConfig == nil {
		// Default configuration if none provided.
		cfgCopy = ProxyTransportConfig{
			DialerConfig: NewDialerConfig(),
		}
		log.Info("Using default transport config for upstream connections.")
	} else {
		cfgCopy = *transportConfig
		if cfgCopy.DialerConfig == nil {
			cfgCopy.DialerConfig = NewDialerConfig()
		}
	}

	// Configure the HTTP transport (proxy.Tr) for upstream connections made by goproxy.
	transport := &http.Transport{
		TLSClientConfig:       cfgCopy.DialerConfig.TLSConfig.Clone(),
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		// Disable compression in the proxy's transport to simplify interception logic.
		DisableCompression: true,
	}

	// Prepare the DialerConfig for the transport's DialContext.
	dialerConfigForTransport := cfgCopy.DialerConfig.Clone()

	if cfgCopy.DialerConfig.ProxyURL != nil {
		// If an upstream proxy is configured (proxy chaining), use http.Transport.Proxy.
		transport.Proxy = http.ProxyURL(cfgCopy.DialerConfig.ProxyURL)

		// CRITICAL: When Transport.Proxy is used, the DialContext must connect directly to the proxy.
		// We must clear the ProxyURL from the config used by DialContext to prevent loops.
		dialerConfigForTransport.ProxyURL = nil
		log.Info("Configured upstream proxy chaining.", zap.String("upstream_proxy", cfgCopy.DialerConfig.ProxyURL.String()))
	}

	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Use DialTCPContext with the prepared config (ensuring direct connection if upstream proxy is set via Transport.Proxy).
		return DialTCPContext(ctx, network, addr, dialerConfigForTransport)
	}

	proxy.Tr = transport

	// Configure the dialer specifically for CONNECT requests handled manually by goproxy (e.g., tunneling when MITM is disabled).
	// This dialer needs to establish the connection to the target, potentially through the upstream proxy using CONNECT.
	// We use the original config here, as DialTCPContext correctly implements CONNECT tunneling if ProxyURL is set.
	proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		// Use context.Background() as goproxy manages the lifecycle for these connections independently.
		return DialTCPContext(context.Background(), network, addr, cfgCopy.DialerConfig)
	}

	if caCert != nil && caKey != nil {
		// Attempt to initialize MITM capabilities using the provided CA.
		if err := configureMITM(caCert, caKey); err != nil {
			return nil, fmt.Errorf("failed to configure global MITM capabilities: %w", err)
		}
		log.Info("MITM capabilities initialized.")
	} else {
		log.Warn("CA certificate or key missing, MITM disabled. Operating in tunneling mode.")
	}

	ip := &InterceptionProxy{
		proxy:           proxy,
		transportConfig: &cfgCopy,
		logger:          log,
	}

	ip.setupHandlers()

	return ip, nil
}

// AddRequestHook registers a new RequestHandler to be executed on incoming
// requests. Handlers are executed in the order they are added. This method is
// thread-safe.
func (ip *InterceptionProxy) AddRequestHook(handler RequestHandler) {
	ip.hooksMutex.Lock()
	defer ip.hooksMutex.Unlock()
	ip.requestHooks = append(ip.requestHooks, handler)
}

// AddResponseHook registers a new ResponseHandler to be executed on incoming
// responses. Handlers are executed in the order they are added. This method is
// thread-safe.
func (ip *InterceptionProxy) AddResponseHook(handler ResponseHandler) {
	ip.hooksMutex.Lock()
	defer ip.hooksMutex.Unlock()
	ip.responseHooks = append(ip.responseHooks, handler)
}

// setupHandlers configures the core interception logic.
func (ip *InterceptionProxy) setupHandlers() {
	// Configure the CONNECT handler to decide between MITM and tunneling.
	ip.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// Check the global state set during initialization.
		if isMITMEnabled {
			// MITM is configured and ready.
			return goproxy.MitmConnect, host
		}
		// MITM is not configured, fall back to tunneling (using proxy.ConnectDial).
		return goproxy.OkConnect, host
	}))

	ip.proxy.OnRequest().DoFunc(ip.handleRequest)
	ip.proxy.OnResponse().DoFunc(ip.handleResponse)
}

// handleRequest processes an incoming request through the registered hooks.
func (ip *InterceptionProxy) handleRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	reqURL := getRequestURL(ctx)

	// Acquire read lock and copy the slice for safe concurrent iteration.
	ip.hooksMutex.RLock()
	hooks := make([]RequestHandler, len(ip.requestHooks))
	copy(hooks, ip.requestHooks)
	ip.hooksMutex.RUnlock()

	currentReq := r
	for _, hook := range hooks {
		newReq, resp := hook(currentReq, ctx)

		if resp != nil {
			return newReq, resp
		}

		if newReq == nil {
			ip.logger.Error("A request hook returned a nil request, breaking chain. This indicates a faulty hook implementation.", zap.String("url", reqURL))
			return currentReq, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusInternalServerError, "Proxy Error: A request processing hook failed by returning a nil request.")
		}
		currentReq = newReq
	}

	return currentReq, nil
}

// handleResponse processes an upstream response through the registered hooks.
func (ip *InterceptionProxy) handleResponse(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	reqURL := getRequestURL(ctx)

	if r == nil {
		// Handle upstream connection failures (e.g., DNS errors, connection refused, timeouts).
		var errorMsg string
		if ctx.Error != nil {
			errorMsg = ctx.Error.Error()
		} else {
			errorMsg = "unknown error"
		}

		ip.logger.Warn("Proxy received nil response from upstream", zap.String("url", reqURL), zap.String("error", errorMsg))

		if ctx.Req == nil {
			ip.logger.Error("Critical proxy error: ctx.Req is nil during upstream failure handling.")
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf("Proxy error: upstream connection failed and request context was lost: %s", errorMsg))),
			}
		}

		// Return a 502 Bad Gateway or 504 Gateway Timeout depending on the error type.
		statusCode := http.StatusBadGateway
		if netErr, ok := ctx.Error.(net.Error); ok && netErr.Timeout() {
			statusCode = http.StatusGatewayTimeout
		}

		return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, statusCode, fmt.Sprintf("Proxy error: upstream connection failed: %s", errorMsg))
	}

	// Acquire read lock and copy the slice for safe concurrent iteration.
	ip.hooksMutex.RLock()
	hooks := make([]ResponseHandler, len(ip.responseHooks))
	copy(hooks, ip.responseHooks)
	ip.hooksMutex.RUnlock()

	lastValidResp := r
	for _, hook := range hooks {
		currentResp := hook(lastValidResp, ctx)

		if currentResp == nil {
			ip.logger.Error("A response hook returned a nil response, breaking chain. Returning last valid state.", zap.String("url", reqURL))
			return lastValidResp
		}
		lastValidResp = currentResp
	}
	return lastValidResp
}

// Start runs the proxy server and blocks until the context is cancelled or a fatal error occurs.
// (Implementation details for starting the HTTP server omitted for brevity, focusing on the configuration logic).

// configureMITM sets up the certificate authority for the proxy.
// CRITICAL: This function modifies global state within the goproxy library.
func configureMITM(caCert, caKey []byte) error {
	mitmInitOnce.Do(func() {
		ca, err := tls.X509KeyPair(caCert, caKey)
		if err != nil {
			mitmInitError = fmt.Errorf("invalid CA certificate/key pair: %w", err)
			return
		}
		if len(ca.Certificate) == 0 {
			mitmInitError = errors.New("CA certificate chain is empty")
			return
		}
		// Parse the certificate to populate the Leaf field.
		if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
			mitmInitError = fmt.Errorf("failed to parse CA certificate leaf: %w", err)
			return
		}

		// Configure the global goproxy CA.
		goproxy.GoproxyCa = ca

		// goproxy.TLSConfigFromCA returns a *function* that generates a *tls.Config.
		baseTLSConfigFunc := goproxy.TLSConfigFromCA(&ca)

		// Create a new wrapper function to apply security hardening to the generated TLS config.
		hardenedTLSConfigFunc := func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
			// Call the original function to get the dynamically generated config.
			tlsConfig, err := baseTLSConfigFunc(host, ctx)
			if err != nil {
				return nil, err
			}

			// Apply security hardening to the TLS config used for MITM connections to the client.
			// Ensure modern TLS versions are enforced (TLS 1.2+).
			if tlsConfig.MinVersion < tls.VersionTLS12 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
			return tlsConfig, nil
		}

		// Update the global CONNECT actions used by goproxy, passing our new hardened function.
		goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: hardenedTLSConfigFunc}
		goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: hardenedTLSConfigFunc}
		goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: hardenedTLSConfigFunc}
		goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: hardenedTLSConfigFunc}

		// Success
		isMITMEnabled = true
	})

	// Return the result of the initialization attempt.
	return mitmInitError
}

// getRequestURL is a helper to safely extract the request URL from the context for logging.
func getRequestURL(ctx *goproxy.ProxyCtx) string {
	if ctx != nil && ctx.Req != nil && ctx.Req.URL != nil {
		return ctx.Req.URL.String()
	}
	return "unknown"
}
