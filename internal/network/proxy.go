// internal/network/proxy.go
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
)

var (
	// Ensures configureMITM initialization logic runs exactly once.
	mitmInitOnce sync.Once
	// Stores the result of the MITM initialization attempt.
	mitmInitError error
	// Tracks whether MITM is successfully configured globally.
	isMITMEnabled bool
)

// RequestHandler defines the signature for functions that inspect or modify requests.
type RequestHandler func(*http.Request, *goproxy.ProxyCtx) (*http.Request, *http.Response)

// ResponseHandler defines the signature for functions that inspect or modify responses.
type ResponseHandler func(*http.Response, *goproxy.ProxyCtx) *http.Response

// InterceptionProxy holds the state and configuration for the MITM proxy.
type InterceptionProxy struct {
	proxy         *goproxy.ProxyHttpServer
	server        *http.Server
	serverMutex   sync.Mutex
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
		logger = zap.NewNop()
	}
	log := logger.Named("interception_proxy")

	// Create a defensive copy of the client config to prevent external mutation after initialization.
	var cfgCopy ClientConfig
	if clientConfig == nil {
		cfgCopy = *NewDefaultClientConfig()
		// Default behavior for proxy upstream connections should often be permissive.
		cfgCopy.IgnoreTLSErrors = true
		log.Info("Using default client config with IgnoreTLSErrors enabled for upstream connections.")
	} else {
		cfgCopy = *clientConfig
	}
	// Use the robust HTTP transport for upstream connections.
	proxy.Tr = NewHTTPTransport(&cfgCopy)

	if caCert != nil && caKey != nil {
		// Attempt to initialize MITM capabilities using the provided CA.
		// This function ensures initialization happens only once globally.
		if err := configureMITM(caCert, caKey); err != nil {
			return nil, fmt.Errorf("failed to configure global MITM capabilities: %w", err)
		}
		log.Info("MITM capabilities initialized.")
	} else {
		log.Warn("CA certificate or key missing, MITM disabled. Operating in tunneling mode.")
	}

	ip := &InterceptionProxy{
		proxy:        proxy,
		clientConfig: &cfgCopy,
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
	// Configure the CONNECT handler to decide between MITM and tunneling.
	ip.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// Check the global state set during initialization.
		if isMITMEnabled {
			// MITM is configured and ready.
			return goproxy.MitmConnect, host
		}
		// MITM is not configured, fall back to tunneling.
		return goproxy.OkConnect, host
	}))

	ip.proxy.OnRequest().DoFunc(ip.handleRequest)
	ip.proxy.OnResponse().DoFunc(ip.handleResponse)
}

// handleRequest processes an incoming request through the registered hooks.
func (ip *InterceptionProxy) handleRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	reqURL := getRequestURL(ctx)
	ip.logger.Debug("Proxy intercepted request", zap.String("method", r.Method), zap.String("url", reqURL))

	ip.hooksMutex.RLock()
	hooks := ip.requestHooks
	ip.hooksMutex.RUnlock()

	currentReq := r
	for _, hook := range hooks {
		newReq, resp := hook(currentReq, ctx)

		if resp != nil {
			ip.logger.Debug("Request short-circuited by a hook", zap.String("url", reqURL))
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

		return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusBadGateway, fmt.Sprintf("Proxy error: upstream connection failed: %s", errorMsg))
	}

	ip.logger.Debug("Proxy received response", zap.Int("status", r.StatusCode), zap.String("url", reqURL))

	ip.hooksMutex.RLock()
	hooks := ip.responseHooks
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
func (ip *InterceptionProxy) Start(ctx context.Context, addr string) error {
	ip.serverMutex.Lock()
	if ip.server != nil {
		ip.serverMutex.Unlock()
		return errors.New("proxy server already started")
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      ip.proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     zap.NewStdLog(ip.logger.Named("http_server")),
	}
	ip.server = server
	ip.serverMutex.Unlock()

	shutdownErr := make(chan error)
	go func() {
		// Wait for the context to be cancelled.
		<-ctx.Done()
		ip.logger.Info("Shutdown signal received, stopping interception proxy...")

		// Create a new context for the shutdown process with a timeout.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Call the server's Shutdown method.
		shutdownErr <- server.Shutdown(shutdownCtx)
	}()

	ip.logger.Info("Starting interception proxy", zap.String("address", addr))
	err := server.ListenAndServe()

	// If ListenAndServe returns ErrServerClosed, it's a graceful shutdown.
	// We then wait for the result from our shutdown goroutine.
	if errors.Is(err, http.ErrServerClosed) {
		err = <-shutdownErr
	}

	ip.serverMutex.Lock()
	if ip.server == server {
		ip.server = nil
	}
	ip.serverMutex.Unlock()

	if err != nil {
		ip.logger.Error("Proxy server stopped with an error", zap.Error(err))
		return fmt.Errorf("proxy server failed: %w", err)
	}

	ip.logger.Info("Interception proxy stopped gracefully.")
	return nil
}

// configureMITM sets up the certificate authority for the proxy.
// CRITICAL: This function modifies global state within the goproxy library.
// It uses sync.Once to ensure it is executed exactly once during the application lifecycle.
// Subsequent calls will return the result of the first invocation.
func configureMITM(caCert, caKey []byte) error {
	mitmInitOnce.Do(func() {
		// sync.Once handles the synchronization; no extra mutex is needed here to protect the initialization itself.

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

		// Configure the global goproxy CA and TLS configuration.
		goproxy.GoproxyCa = ca
		tlsConfig := goproxy.TLSConfigFromCA(&ca)

		// Update the global CONNECT actions used by goproxy.
		goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
		goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
		goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
		goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}

		// Success
		isMITMEnabled = true
		// mitmInitError remains nil.
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