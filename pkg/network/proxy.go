// pkg/network/proxy.go
package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
)

// RequestHandler defines the signature for functions that inspect or modify requests.
type RequestHandler func(*http.Request, *goproxy.ProxyCtx) (*http.Request, *http.Response)

// ResponseHandler defines the signature for functions that inspect or modify responses.
type ResponseHandler func(*http.Response, *goproxy.ProxyCtx) *http.Response

// InterceptionProxy holds the state and configuration for the MITM proxy.
type InterceptionProxy struct {
	proxy         *goproxy.ProxyHttpServer
	server        *http.Server
	clientConfig  *ClientConfig
	requestHooks  []RequestHandler
	responseHooks []ResponseHandler
	hooksMutex    sync.RWMutex
	logger        *zap.Logger
}

// NewInterceptionProxy creates and configures a new MITM proxy instance.
func NewInterceptionProxy(caCert, caKey []byte, clientConfig *ClientConfig, logger *zap.Logger) (*InterceptionProxy, error) {
	proxy := goproxy.NewProxyHttpServer()

	if logger == nil {
		// Fallback to the standardized Nop logger.
		logger = observability.NewNopLogger()
	}
	log := logger.Named("interception_proxy")

	if clientConfig == nil {
		clientConfig = NewDefaultClientConfig()
		// Defaulting to ignore TLS errors is appropriate for security proxies analyzing upstream traffic.
		clientConfig.IgnoreTLSErrors = true
		log.Info("Using default client config with IgnoreTLSErrors enabled for upstream connections.")
	}
	// Ensure the proxy uses our robust, standardized HTTP transport for upstream connections.
	proxy.Tr = NewHTTPTransport(clientConfig)

	if caCert != nil && caKey != nil {
		if err := configureMITM(caCert, caKey); err != nil {
			return nil, fmt.Errorf("failed to configure MITM capabilities: %w", err)
		}
		log.Info("MITM capabilities enabled.")
	} else {
		log.Warn("CA certificate or key missing, MITM disabled. Operating in tunneling mode.")
	}

	ip := &InterceptionProxy{
		proxy:        proxy,
		clientConfig: clientConfig,
		logger:       log,
	}

	ip.setupHandlers()

	return ip, nil
}

// AddRequestHook registers a new request handler function.
func (ip *InterceptionProxy) AddRequestHook(handler RequestHandler) {
	ip.hooksMutex.Lock()
	defer ip.hooksMutex.Unlock()
	ip.requestHooks = append(ip.requestHooks, handler)
}

// AddResponseHook registers a new response handler function.
func (ip *InterceptionProxy) AddResponseHook(handler ResponseHandler) {
	ip.hooksMutex.Lock()
	defer ip.hooksMutex.Unlock()
	ip.responseHooks = append(ip.responseHooks, handler)
}

// setupHandlers configures the core interception logic.
func (ip *InterceptionProxy) setupHandlers() {
	// Handle CONNECT requests (used for HTTPS).
	ip.proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// Check if the global CA is configured.
		if goproxy.GoproxyCa.PrivateKey != nil {
			// If we have a CA key, perform MITM.
			return goproxy.MitmConnect, host
		}
		// Otherwise, tunnel the traffic (no interception of TLS content).
		return goproxy.OkConnect, host
	})

	// Request interception point (HTTP and decrypted HTTPS).
	ip.proxy.OnRequest().DoFunc(ip.handleRequest)

	// Response interception point.
	ip.proxy.OnResponse().DoFunc(ip.handleResponse)
}

// handleRequest processes the incoming request through the registered hooks.
func (ip *InterceptionProxy) handleRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	ip.logger.Debug("Proxy intercepted request", zap.String("method", r.Method), zap.String("url", r.URL.String()))
	
	// Use RLock for concurrent access to hooks.
	ip.hooksMutex.RLock()
	defer ip.hooksMutex.RUnlock()

	currentReq := r
	for _, hook := range ip.requestHooks {
		newReq, resp := hook(currentReq, ctx)
		
		// If a hook returns a response, the request processing is short-circuited.
		if resp != nil {
			ip.logger.Debug("Request short-circuited by hook", zap.String("url", r.URL.String()))
			return newReq, resp
		}
		
		// Robustness check. A hook must return a valid request if it doesn't return a response.
		if newReq == nil {
			ip.logger.Error("Request hook returned nil request without a response, breaking chain", zap.String("url", r.URL.String()))
			// Return an error response to the client.
			return currentReq, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusInternalServerError, "Proxy error: request hook malfunction")
		}
		currentReq = newReq
	}

	// Proceed with the (potentially modified) request to the upstream server.
	return currentReq, nil
}

// handleResponse processes the upstream response through the registered hooks.
func (ip *InterceptionProxy) handleResponse(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// Handle cases where upstream fails to respond (e.g., connection error, timeout).
	if r == nil {
		errorMsg := "unknown error"
		if ctx.Error != nil {
			errorMsg = ctx.Error.Error()
		}

		reqURL := "unknown"
		if ctx.Req != nil && ctx.Req.URL != nil {
			reqURL = ctx.Req.URL.String()
		}

		ip.logger.Warn("Proxy received nil response from upstream", zap.String("url", reqURL), zap.Error(ctx.Error))

		// Robustness Fix: If ctx.Req is nil (which can happen in edge cases), goproxy.NewResponse may panic.
		if ctx.Req == nil {
			ip.logger.Error("Critical proxy error: ctx.Req is nil during upstream failure handling.")
			// Constructing a minimal response manually as a last resort to prevent a crash and inform the client.
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf("Proxy error: upstream connection failed and request context lost: %v", errorMsg))),
			}
		}
		
		// We must return an error response to the client, not nil.
		return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusBadGateway, fmt.Sprintf("Proxy error: upstream connection failed: %v", errorMsg))
	}

	// Determine the request URL safely for logging.
	reqURL := "unknown"
	if ctx.Req != nil && ctx.Req.URL != nil {
		reqURL = ctx.Req.URL.String()
	} else if r.Request != nil && r.Request.URL != nil {
		reqURL = r.Request.URL.String()
	}

	ip.logger.Debug("Proxy received response", zap.Int("status", r.StatusCode), zap.String("url", reqURL))

	ip.hooksMutex.RLock()
	defer ip.hooksMutex.RUnlock()

	currentResp := r
	for _, hook := range ip.responseHooks {
		currentResp = hook(currentResp, ctx)
		
		// Robustness check. A hook must return a valid response.
		if currentResp == nil {
			ip.logger.Error("Response hook returned nil response, breaking chain", zap.String("url", reqURL))
			// Return the original response rather than potentially crashing the proxy or returning nil downstream.
			return r
		}
	}
	return currentResp
}

// Start runs the proxy server. This function blocks until the server stops.
func (ip *InterceptionProxy) Start(addr string) error {
	ip.logger.Info("Starting interception proxy", zap.String("address", addr))

	// Configuring timeouts on the HTTP server prevents resource exhaustion (e.g., Slowloris defense).
	ip.server = &http.Server{
		Addr:         addr,
		Handler:      ip.proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		// Pass the Zap logger to the underlying HTTP server for internal error logging.
		ErrorLog:     zap.NewStdLog(ip.logger.Named("http_server")),
	}

	err := ip.server.ListenAndServe()
	// http.ErrServerClosed is expected during graceful shutdown.
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		ip.logger.Error("Proxy server error", zap.Error(err))
		return fmt.Errorf("proxy server failed: %w", err)
	}

	ip.logger.Info("Interception proxy stopped.")
	return nil
}

// Stop gracefully shuts down the proxy server.
func (ip *InterceptionProxy) Stop(ctx context.Context) error {
	if ip.server == nil {
		return errors.New("proxy server not started")
	}
	ip.logger.Info("Stopping interception proxy...")
	return ip.server.Shutdown(ctx)
}

// configureMITM sets up the certificate authority for the proxy.
// Note: This modifies global state within the goproxy library.
func configureMITM(caCert, caKey []byte) error {
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return fmt.Errorf("invalid CA certificate/key pair: %w", err)
	}
	if len(ca.Certificate) == 0 {
		return errors.New("CA certificate chain is empty")
	}
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return fmt.Errorf("failed to parse CA certificate leaf: %w", err)
	}

	// The library requires setting this global variable.
	goproxy.GoproxyCa = ca
	// Configure the connection actions explicitly for robustness.
	tlsConfig := goproxy.TLSConfigFromCA(&ca)
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}

	return nil
}
