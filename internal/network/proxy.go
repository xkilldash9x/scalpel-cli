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

// Global lock for protecting global goproxy state modification.
var mitmConfigMutex sync.Mutex

// RequestHandler defines the signature for functions that inspect or modify requests.
type RequestHandler func(*http.Request, *goproxy.ProxyCtx) (*http.Request, *http.Response)

// ResponseHandler defines the signature for functions that inspect or modify responses.
type ResponseHandler func(*http.Response, *goproxy.ProxyCtx) *http.Response

// InterceptionProxy holds the state and configuration for the MITM proxy.
type InterceptionProxy struct {
	proxy         *goproxy.ProxyHttpServer
	server        *http.Server
	serverMutex   sync.Mutex // Add mutex for server state management
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

	if clientConfig == nil {
		clientConfig = NewDefaultClientConfig()
		clientConfig.IgnoreTLSErrors = true
		log.Info("Using default client config with IgnoreTLSErrors enabled for upstream connections.")
	}
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
	ip.proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if goproxy.GoproxyCa.PrivateKey != nil {
			return goproxy.MitmConnect, host
		}
		return goproxy.OkConnect, host
	})

	ip.proxy.OnRequest().DoFunc(ip.handleRequest)
	ip.proxy.OnResponse().DoFunc(ip.handleResponse)
}

// handleRequest processes the incoming request through the registered hooks.
func (ip *InterceptionProxy) handleRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	ip.logger.Debug("Proxy intercepted request", zap.String("method", r.Method), zap.String("url", r.URL.String()))

	// Acquire RLock just long enough to copy the slice reference.
	ip.hooksMutex.RLock()
	hooks := ip.requestHooks
	ip.hooksMutex.RUnlock()

	currentReq := r
	for _, hook := range hooks {
		newReq, resp := hook(currentReq, ctx)

		if resp != nil {
			ip.logger.Debug("Request short-circuited by hook", zap.String("url", r.URL.String()))
			return newReq, resp
		}

		if newReq == nil {
			ip.logger.Error("Request hook returned nil request without a response, breaking chain", zap.String("url", r.URL.String()))
			return currentReq, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusInternalServerError, "Proxy error: request hook malfunction")
		}
		currentReq = newReq
	}

	return currentReq, nil
}

// handleResponse processes the upstream response through the registered hooks.
func (ip *InterceptionProxy) handleResponse(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
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

		if ctx.Req == nil {
			ip.logger.Error("Critical proxy error: ctx.Req is nil during upstream failure handling.")
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf("Proxy error: upstream connection failed and request context lost: %v", errorMsg))),
			}
		}

		return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusBadGateway, fmt.Sprintf("Proxy error: upstream connection failed: %v", errorMsg))
	}

	reqURL := "unknown"
	if ctx.Req != nil && ctx.Req.URL != nil {
		reqURL = ctx.Req.URL.String()
	} else if r.Request != nil && r.Request.URL != nil {
		reqURL = r.Request.URL.String()
	}

	ip.logger.Debug("Proxy received response", zap.Int("status", r.StatusCode), zap.String("url", reqURL))

	ip.hooksMutex.RLock()
	hooks := ip.responseHooks
	ip.hooksMutex.RUnlock()

	currentResp := r
	for _, hook := range hooks {
		currentResp = hook(currentResp, ctx)

		if currentResp == nil {
			ip.logger.Error("Response hook returned nil response, breaking chain", zap.String("url", reqURL))
			return r
		}
	}
	return currentResp
}

// Start runs the proxy server. This function blocks until the server stops.
func (ip *InterceptionProxy) Start(addr string) error {
	ip.logger.Info("Starting interception proxy", zap.String("address", addr))

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

	err := server.ListenAndServe()

	ip.serverMutex.Lock()
	if ip.server == server {
		ip.server = nil
	}
	ip.serverMutex.Unlock()

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		ip.logger.Error("Proxy server error", zap.Error(err))
		return fmt.Errorf("proxy server failed: %w", err)
	}

	ip.logger.Info("Interception proxy stopped.")
	return nil
}

// Stop gracefully shuts down the proxy server.
func (ip *InterceptionProxy) Stop(ctx context.Context) error {
	ip.serverMutex.Lock()
	server := ip.server
	ip.serverMutex.Unlock()

	if server == nil {
		return errors.New("proxy server not started or already stopped")
	}
	ip.logger.Info("Stopping interception proxy...")
	return server.Shutdown(ctx)
}

// configureMITM sets up the certificate authority for the proxy.
// CRITICAL: This function modifies global state within the goproxy library.
// Due to library limitations, only one MITM CA configuration can be active per Go process.
// Calling this function overrides any previous configuration globally.
func configureMITM(caCert, caKey []byte) error {
	mitmConfigMutex.Lock()
	defer mitmConfigMutex.Unlock()

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

	goproxy.GoproxyCa = ca
	tlsConfig := goproxy.TLSConfigFromCA(&ca)
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}

	return nil
}
