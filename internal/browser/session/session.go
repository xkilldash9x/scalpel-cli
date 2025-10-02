// Package session implements a functional, headless browser engine in pure Go.
// It integrates a robust network stack, a Go based DOM representation (golang.org/x/net/html),
// and the Goja JavaScript runtime, synchronized via an event loop and a custom DOM bridge (jsbind).
//
// CONCURRENCY MODEL:
// This implementation adheres to Goja's single-threaded constraint by assigning one
// dedicated Goja VM instance per Session, managed by an eventloop.EventLoop. This creates
// a "browser tab" metaphor, where each session is an isolated, stateful environment.
//
// To manage concurrency at the application level, two layers of synchronization are used:
// 1. High-Level Operation Lock (opMu): A sync.Mutex that serializes major, state-altering
//    operations (e.g., Navigate, Click, ExecuteScript). This prevents logical race conditions,
//    such as a script execution interfering with a page navigation. The acquireOpLock helper
//    manages this lock with re-entrancy support via context.
// 2. Low-Level VM Access (Event Loop): The eventloop ensures all JavaScript execution
//    occurs on a single, dedicated goroutine, satisfying Goja's core requirement and
//    preventing memory corruption within the VM's internal state.
package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/antchfx/htmlquery"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/dom"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/jsbind"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/layout"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/shadowdom"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/style"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

// Context key for managing operation lock re-entrancy.
type opLockKey struct{}

var operationLockKey = opLockKey{}

// Session represents a single, functional browsing context, equivalent to a tab.
// It implements schemas.SessionContext.
// The public API is safe for concurrent use.
type Session struct {
	id          string
	ctx         context.Context // Master context for the session's lifecycle.
	cancel      context.CancelFunc
	logger      *zap.Logger
	cfg         *config.Config
	persona     schemas.Persona
	closeStatus int32 // 0 = open, 1 = closing
	// Core functional components
	client             *http.Client
	interactor         *dom.Interactor
	harvester          *Harvester
	layoutEngine       *layout.Engine
	styleEngine        *style.Engine
	shadowEngine       *shadowdom.Engine
	humanoidController humanoid.Controller
	jsRegistry         *require.Registry

	// JavaScript Engine and Event Loop
	// Protected by 'mu' for safe access/shutdown.
	eventLoop *eventloop.EventLoop

	// Humanoid configuration
	humanoidCfg *humanoid.Config

	// Operation serialization lock.
	// opMu serializes high level operations (Navigation, Interactions, JS Execution)
	// to ensure state consistency. Managed via acquireOpLock for re-entrancy.
	opMu sync.Mutex

	// State management
	// mu protects the internal state variables (fine grained locking).
	mu sync.RWMutex

	currentURL *url.URL
	layoutRoot *layout.LayoutBox
	domBridge  *jsbind.DOMBridge

	// History stack implementation (Protected by mu)
	historyStack []*schemas.HistoryState
	historyIndex int

	// Persistent configuration across navigations (Protected by mu)
	persistentScripts []string
	exposedFunctions  map[string]interface{}

	// Artifacts
	consoleLogs   []schemas.ConsoleLog
	consoleLogsMu sync.Mutex // Specific mutex for high frequency access.

	findingsChan chan<- schemas.Finding
	onClose      func()
	closeOnce    sync.Once
}

// acquireOpLock grabs the operation lock if it's not already held by the current goroutine.
// This is tracked via context to enable re-entrancy without deadlocking.
// It returns a context marked as locked and a function to release the lock.
func (s *Session) acquireOpLock(ctx context.Context) (context.Context, func()) {
	if ctx.Value(operationLockKey) != nil {
		// Lock is already held by this operation chain. Return existing context and a no op unlock function.
		return ctx, func() {}
	}

	// Check if the session is already closing before attempting to lock.
	if s.ctx.Err() != nil {
		// If closed, return the session context (which is Done) and a no op unlock.
		// The subsequent operation will fail quickly when checking the context.
		return s.ctx, func() {}
	}

	// Acquire the lock.
	s.opMu.Lock()

	// Return a new context marked as locked, and the actual unlock function.
	lockedCtx := context.WithValue(ctx, operationLockKey, true)
	return lockedCtx, s.opMu.Unlock
}

type sessionConsolePrinter struct {
	s *Session
}

func (p *sessionConsolePrinter) Log(msg string) {
	p.s.captureConsoleLog("log", msg)
}

func (p *sessionConsolePrinter) Warn(msg string) {
	p.s.captureConsoleLog("warn", msg)
}

func (p *sessionConsolePrinter) Error(msg string) {
	p.s.captureConsoleLog("error", msg)
}

// Ensure Session implements the required interfaces.
var _ schemas.SessionContext = (*Session)(nil)
var _ jsbind.BrowserEnvironment = (*Session)(nil)
var _ dom.CorePagePrimitives = (*Session)(nil)
var _ humanoid.Executor = (*Session)(nil)

// NewSession initializes a new browsing session.
func NewSession(
	parentCtx context.Context,
	cfg *config.Config,
	persona schemas.Persona,
	logger *zap.Logger,
	findingsChan chan<- schemas.Finding,
) (*Session, error) {
	sessionID := uuid.New().String()
	log := logger.With(zap.String("session_id", sessionID), zap.String("mode", "GojaHeadlessEngine"))

	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the new engines required by the rendering pipeline.
	shadowEngine := &shadowdom.Engine{}
	styleEngine := style.NewEngine(shadowEngine)
	layoutEngine := layout.NewEngine(float64(persona.Width), float64(persona.Height))

	s := &Session{
		id:                sessionID,
		ctx:               ctx,
		cancel:            cancel,
		logger:            log,
		cfg:               cfg,
		persona:           persona,
		findingsChan:      findingsChan,
		layoutEngine:      layoutEngine,
		styleEngine:       styleEngine,
		shadowEngine:      shadowEngine,
		historyStack:      make([]*schemas.HistoryState, 0),
		historyIndex:      -1,
		persistentScripts: make([]string, 0),
		exposedFunctions:  make(map[string]interface{}),
		consoleLogs:       make([]schemas.ConsoleLog, 0),
	}

	if err := s.initializeJSEngine(log); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize JS engine: %w", err)
	}

	var domHCfg dom.HumanoidConfig
	humanoidCfg := cfg.Browser.Humanoid
	if cfg.Browser.Humanoid.Enabled {
		if humanoidCfg.Rng == nil {
			source := rand.NewSource(time.Now().UnixNano())
			humanoidCfg.Rng = rand.New(source)
		}
		humanoidCfg.FinalizeSessionPersona(humanoidCfg.Rng)
		s.humanoidCfg = &humanoidCfg
		domHCfg = dom.HumanoidConfig{
			Enabled:        true,
			KeyHoldMeanMs:  s.humanoidCfg.KeyHoldMeanMs,
			ClickHoldMinMs: int(s.humanoidCfg.ClickHoldMinMs),
			ClickHoldMaxMs: int(s.humanoidCfg.ClickHoldMaxMs),
		}
	}
	// The humanoid controller uses 's' (humanoid.Executor), which implements methods using the public, locking API.
	s.humanoidController = humanoid.New(humanoidCfg, log.Named("humanoid"), s)

	if err := s.initializeNetworkStack(log); err != nil {
		if el := s.getEventLoop(); el != nil {
			el.Stop()
		}
		cancel()
		return nil, fmt.Errorf("failed to initialize network stack: %w", err)
	}

	// The stabilizer function is used internally by the Interactor.
	// It assumes the caller (Interactor/Session methods) holds the opMu lock.
	stabilizeFn := func(ctx context.Context) error {
		return s.stabilize(ctx)
	}
	// The interactor uses 's' (dom.CorePagePrimitives), which implements methods using the public, locking API.
	s.interactor = dom.NewInteractor(NewZapAdapter(log.Named("interactor")), domHCfg, stabilizeFn, s)
	s.initializeDOMBridge(log)

	// Initialize the state for the initial (empty) document.
	s.resetStateForNewDocument(nil, nil, log, make(map[string]interface{}), make([]string, 0))

	return s, nil
}

// getEventLoop safely gets the event loop pointer.
func (s *Session) getEventLoop() *eventloop.EventLoop {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.eventLoop
}

// getDOMBridge safely gets the DOM bridge pointer.
func (s *Session) getDOMBridge() *jsbind.DOMBridge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domBridge
}

func (s *Session) initializeDOMBridge(log *zap.Logger) {
	el := s.getEventLoop()
	if el == nil {
		log.Error("Critical error: Event loop missing during DOMBridge initialization.")
		return
	}
	// The DOMBridge uses 's' (jsbind.BrowserEnvironment), which implements methods safely.
	bridge := jsbind.NewDOMBridge(log.Named("dom_bridge"), el, s)

	s.mu.Lock()
	s.domBridge = bridge
	s.mu.Unlock()
}

func (s *Session) initializeJSEngine(log *zap.Logger) error {
	s.jsRegistry = new(require.Registry)
	printer := &sessionConsolePrinter{s: s}
	s.jsRegistry.RegisterNativeModule("console", console.RequireWithPrinter(printer))

	el := eventloop.NewEventLoop(eventloop.WithRegistry(s.jsRegistry))
	el.Start()

	// Initialize the VM synchronously on the event loop.
	initDone := make(chan struct{})
	el.RunOnLoop(func(vm *goja.Runtime) {
		defer close(initDone)
		// Set the interrupt handler to the session context's Done channel.
		vm.Interrupt(s.ctx.Done())

		s.jsRegistry.Enable(vm)
		navigator := vm.NewObject()
		_ = navigator.Set("userAgent", s.persona.UserAgent)
		_ = navigator.Set("platform", s.persona.Platform)
		_ = navigator.Set("languages", s.persona.Languages)
		_ = vm.Set("navigator", navigator)
	})
	<-initDone

	s.mu.Lock()
	s.eventLoop = el
	s.mu.Unlock()

	log.Info("JavaScript engine (Goja) and event loop initialized.")
	return nil
}

func (s *Session) captureConsoleLog(logLevel string, message string) {
	switch logLevel {
	case "info", "log":
		s.logger.Info("[JS Console]", zap.String("message", message))
	case "warn":
		s.logger.Warn("[JS Console]", zap.String("message", message))
	case "error":
		s.logger.Error("[JS Console]", zap.String("message", message))
	default:
		s.logger.Debug("[JS Console]", zap.String("message", message), zap.String("level", logLevel))
	}

	// Use a dedicated mutex for console logs to minimize contention.
	s.consoleLogsMu.Lock()
	defer s.consoleLogsMu.Unlock()
	s.consoleLogs = append(s.consoleLogs, schemas.ConsoleLog{
		Type:      logLevel,
		Timestamp: time.Now(),
		Text:      message,
	})
}

// resetStateForNewDocument prepares the session (DOM and JS context) for a new page load.
// It must be called without holding the main state lock (s.mu).
// It assumes the operation lock (s.opMu) is held if called as part of an operation.
func (s *Session) resetStateForNewDocument(doc *html.Node, layoutRoot *layout.LayoutBox, log *zap.Logger, exposedFunctions map[string]interface{}, persistentScripts []string) {
	if doc == nil {
		var err error
		doc, err = html.Parse(strings.NewReader("<html><head></head><body></body></html>"))
		if err != nil {
			log.Error("Critical error: Failed to parse empty HTML document.", zap.Error(err))
			return
		}
	}

	// Update the layout root and capture the current URL under the state lock.
	s.mu.Lock()
	initialURL := ""
	if s.currentURL != nil {
		initialURL = s.currentURL.String()
	}
	s.layoutRoot = layoutRoot
	s.mu.Unlock()

	bridge := s.getDOMBridge()
	if bridge == nil {
		return // Session closing
	}
	bridge.UpdateDOM(doc)

	loop := s.getEventLoop()
	if loop == nil {
		return // Session closing
	}

	// Reset the JavaScript context synchronously on the event loop.
	done := make(chan struct{})
	loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)
		if s.ctx.Err() != nil {
			return
		}

		// Rebind the DOM bridge to the new VM context.
		bridge.BindToRuntime(vm, initialURL)

		// Re-inject persistent functions and scripts.
		for name, function := range exposedFunctions {
			if err := vm.GlobalObject().Set(name, function); err != nil {
				log.Error("Failed to expose persistent function", zap.String("name", name), zap.Error(err))
			}
		}
		for i, script := range persistentScripts {
			log.Debug("Injecting persistent script", zap.Int("index", i))
			if _, err := vm.RunString(script); err != nil {
				// Check if the error is due to interruption (e.g., session closing).
				if _, ok := err.(*goja.InterruptedError); !ok {
					log.Warn("Error executing persistent script", zap.Error(err))
				}
			}
		}

		// Schedule DOMContentLoaded and load events.
		loop.SetTimeout(func(vm *goja.Runtime) {
			if s.ctx.Err() != nil {
				return
			}
			if b := s.getDOMBridge(); b != nil {
				docNode := b.GetDocumentNode()
				b.DispatchEventOnNode(docNode, "DOMContentLoaded")
				b.DispatchEventOnNode(docNode, "load")
			}
		}, 1*time.Millisecond)
	})
	// Wait for the reset to complete.
	<-done
}

func (s *Session) initializeNetworkStack(log *zap.Logger) error {
	netConfig := network.NewBrowserClientConfig()
	netConfig.Logger = NewZapAdapter(log.Named("network"))
	netConfig.InsecureSkipVerify = s.cfg.Browser.IgnoreTLSErrors || s.cfg.Network.IgnoreTLSErrors
	netConfig.RequestTimeout = s.cfg.Network.NavigationTimeout
	if netConfig.RequestTimeout == 0 {
		netConfig.RequestTimeout = 60 * time.Second
	}
	// The standard library cookiejar is concurrency safe.
	jar, _ := cookiejar.New(nil)
	netConfig.CookieJar = jar
	transport := network.NewHTTPTransport(netConfig)
	compressionTransport := network.NewCompressionMiddleware(transport)
	// The Harvester must be concurrency safe.
	s.harvester = NewHarvester(compressionTransport, log.Named("harvester"), s.cfg.Network.CaptureResponseBodies)
	s.client = &http.Client{
		Transport: s.harvester,
		Timeout:   netConfig.RequestTimeout,
		Jar:       netConfig.CookieJar,
		// Handle redirects manually in executeRequest.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return nil
}

func (s *Session) ID() string { return s.id }

func (s *Session) GetContext() context.Context { return s.ctx }

// Close shuts down the session, stops the event loop, and releases resources.
// It is safe to call multiple times.
func (s *Session) Close(ctx context.Context) error {
	// Use atomic flag to ensure shutdown logic runs only once.
	if !atomic.CompareAndSwapInt32(&s.closeStatus, 0, 1) {
		s.logger.Debug("Close called on an already closing session.", zap.String("stack", string(debug.Stack())))
		return nil
	}

	s.logger.Info("-- Close called for the FIRST time --", zap.String("stack", string(debug.Stack())))

	var returnErr error

	s.closeOnce.Do(func() {
		s.logger.Info("Initiating session shutdown.")

		// 1. Cancel the session's master context. This signals ongoing operations to stop.
		s.cancel()

		// 2. Acquire the operation lock. This waits for any currently running operation
		// (which should finish quickly due to context cancellation) to complete.
		s.opMu.Lock()
		s.opMu.Unlock() // Unlock immediately, we just needed synchronization.

		// Safely grab the event loop pointer.
		s.mu.Lock()
		loop := s.eventLoop
		s.mu.Unlock()

		// 3. Stop the event loop. Now that operations are halted, we can safely shut down the loop.
		if loop != nil {
			stopDone := make(chan struct{})
			go func() {
				loop.Stop()
				close(stopDone)
			}()

			// Wait for the loop to stop or the provided context to time out.
			select {
			case <-stopDone:
				s.logger.Debug("Event loop stopped gracefully.")
			case <-ctx.Done():
				s.logger.Warn("Timeout waiting for event loop to stop.", zap.Error(ctx.Err()))
				returnErr = fmt.Errorf("timeout waiting for session event loop to close: %w", ctx.Err())
			}
		}

		// 4. Nullify resources under lock.
		s.mu.Lock()
		s.eventLoop = nil
		s.domBridge = nil
		s.layoutRoot = nil
		s.mu.Unlock()

		if s.client != nil {
			s.client.CloseIdleConnections()
		}

		if s.onClose != nil {
			s.onClose()
		}
		s.logger.Info("Session closed.")
	})

	return returnErr
}

func (s *Session) SetOnClose(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onClose = fn
}

// stabilize waits for the session to become idle (network activity ceased and JS event loop clear).
// It assumes the operation lock (s.opMu) is held if called as part of an operation.
func (s *Session) stabilize(ctx context.Context) error {
	// Combine session context with the operation context.
	stabCtx, stabCancel := CombineContext(s.ctx, ctx)
	defer stabCancel()

	quietPeriod := 1500 * time.Millisecond
	if s.cfg.Network.PostLoadWait > 0 {
		quietPeriod = s.cfg.Network.PostLoadWait
	}

	// Wait for network activity to cease.
	if s.harvester != nil {
		if err := s.harvester.WaitNetworkIdle(stabCtx, quietPeriod); err != nil {
			// Non critical error, proceed anyway.
			s.logger.Debug("Network stabilization finished with potential pending requests.", zap.Error(err))
		}
	}

	// Wait for a short duration after network idle for JS execution.
	select {
	case <-time.After(quietPeriod):
	case <-stabCtx.Done():
		return stabCtx.Err()
	}

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during stabilization")
	}

	// Ensure the event loop has processed all pending tasks.
	done := make(chan struct{})
	loop.RunOnLoop(func(vm *goja.Runtime) {
		close(done)
	})

	select {
	case <-done:
	case <-stabCtx.Done():
		return stabCtx.Err()
	}

	s.logger.Debug("Stabilization complete.")
	return nil
}

// Navigate loads the specified URL. Concurrency safe.
func (s *Session) Navigate(ctx context.Context, targetURL string) error {
	// Acquire the operation lock.
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.navigateInternal(lockedCtx, targetURL)
}

// navigateInternal performs the navigation logic.
// Assumes s.opMu is held. Must be called with the locked context.
func (s *Session) navigateInternal(ctx context.Context, targetURL string) error {
	// 1. Combine session context and the operation context.
	baseNavCtx, baseNavCancel := CombineContext(s.ctx, ctx)

	// 2. Apply the specific navigation timeout for the network request.
	// When using http.NewRequestWithContext, it's crucial to manage timeouts via the context.
	timeout := s.cfg.Network.NavigationTimeout
	if timeout == 0 {
		timeout = 60 * time.Second // Default navigation timeout if not configured.
	}

	// Create the context specifically for the HTTP request and body reading.
	requestCtx, requestCancel := context.WithTimeout(baseNavCtx, timeout)

	// Ensure all contexts are cancelled when the function returns.
	defer func() {
		requestCancel()
		baseNavCancel()
	}()

	resolvedURL, err := s.ResolveURL(targetURL)
	if err != nil {
		return fmt.Errorf("failed to resolve URL '%s': %w", targetURL, err)
	}
	s.logger.Info("Navigating", zap.String("url", resolvedURL.String()))

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed before navigation")
	}

	// Dispatch 'beforeunload' event synchronously. Use the base context.
	done := make(chan struct{})
	loop.RunOnLoop(func(vm *goja.Runtime) {
		if bridge := s.getDOMBridge(); bridge != nil {
			docNode := bridge.GetDocumentNode()
			bridge.DispatchEventOnNode(docNode, "beforeunload")
		}
		close(done)
	})
	select {
	case <-done:
	case <-baseNavCtx.Done():
		return baseNavCtx.Err()
	}

	// Create the request using the context with the specific timeout.
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, resolvedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s': %w", resolvedURL.String(), err)
	}
	s.prepareRequestHeaders(req)

	// Execute the request (handles state updates). Lock is held.
	// Pass requestCtx which includes the timeout.
	if err := s.executeRequest(requestCtx, req); err != nil {
		return err
	}

	// Optional humanoid delay. Use the base context.
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		if err := s.Sleep(baseNavCtx, 500*time.Millisecond+time.Duration(rand.Intn(1000))*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

// executeRequest handles the HTTP request/response cycle.
// Assumes s.opMu is held.
func (s *Session) executeRequest(ctx context.Context, req *http.Request) error {
	const maxRedirects = 10
	currentReq := req
	for i := 0; i < maxRedirects; i++ {
		s.logger.Debug("Executing request", zap.String("method", currentReq.Method), zap.String("url", currentReq.URL.String()))
		resp, err := s.client.Do(currentReq)
		if err != nil {
			return fmt.Errorf("request for '%s' failed: %w", currentReq.URL.String(), err)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			nextReq, err := s.handleRedirect(ctx, resp, currentReq)
			// Ensure the response body is closed.
			_ = resp.Body.Close()
			if err != nil {
				return fmt.Errorf("failed to handle redirect: %w", err)
			}
			currentReq = nextReq
			continue
		}
		return s.processResponse(resp)
	}
	return fmt.Errorf("maximum number of redirects (%d) exceeded", maxRedirects)
}

func (s *Session) handleRedirect(ctx context.Context, resp *http.Response, originalReq *http.Request) (*http.Request, error) {
	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("redirect response missing Location header")
	}

	nextURL, err := originalReq.URL.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redirect Location '%s': %w", location, err)
	}

	method := originalReq.Method
	var body io.ReadCloser
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		if method != http.MethodHead {
			method = http.MethodGet
		}
		body = nil
	} else if originalReq.GetBody != nil {
		body, err = originalReq.GetBody()
		if err != nil {
			return nil, fmt.Errorf("failed to get body for redirect reuse: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, nextURL.String(), body)
	if err != nil {
		return nil, err
	}

	s.prepareRequestHeaders(req)
	req.Header.Set("Referer", originalReq.URL.String())
	return req, nil
}

// processResponse handles the response body, parsing, layout, state updates, and script execution.
// Assumes s.opMu is held.
func (s *Session) processResponse(resp *http.Response) error {
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.logger.Warn("Request resulted in error status code", zap.Int("status", resp.StatusCode), zap.String("url", resp.Request.URL.String()))
	}

	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(strings.ToLower(contentType), "text/html")
	var doc *html.Node
	var layoutRoot *layout.LayoutBox

	if isHTML {
		// Read the entire body (io.ReadAll reads until EOF), crucial for connection reuse.
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		doc, err = htmlquery.Parse(bytes.NewReader(bodyBytes))
		if err != nil {
			s.logger.Error("Failed to parse HTML response.", zap.Error(err), zap.String("url", resp.Request.URL.String()))
			s.updateState(resp.Request.URL, nil, nil, true)
			return nil
		}

		// Build Style and Layout trees.
		styleEngine := style.NewEngine(s.shadowEngine)
		styleEngine.SetViewport(float64(s.persona.Width), float64(s.persona.Height))
		s.buildAndAddStylesheets(styleEngine, doc, resp.Request.URL)
		styleTree := styleEngine.BuildTree(doc, nil)

		layoutRoot = s.layoutEngine.BuildAndLayoutTree(styleTree)

	} else {
		s.logger.Debug("Response is not HTML.", zap.String("content_type", contentType))
	}

	// Update the session state and reset the JS context.
	s.updateState(resp.Request.URL, doc, layoutRoot, true)

	// Execute page scripts after the JS context is ready.
	if isHTML && doc != nil {
		s.executePageScripts(doc)
	}
	return nil
}

// buildAndAddStylesheets fetches and parses external stylesheets concurrently.
func (s *Session) buildAndAddStylesheets(styleEngine *style.Engine, doc *html.Node, baseURL *url.URL) {
	styleTags := htmlquery.Find(doc, "//style")
	for _, tag := range styleTags {
		p := parser.NewParser(htmlquery.InnerText(tag))
		styleEngine.AddAuthorSheet(p.Parse())
	}

	linkTags := htmlquery.Find(doc, "//link[@rel='stylesheet' and @href]")
	if len(linkTags) == 0 {
		return
	}

	var wg sync.WaitGroup
	stylesheetChan := make(chan parser.StyleSheet, len(linkTags))
	for _, tag := range linkTags {
		href := htmlquery.SelectAttr(tag, "href")
		if href == "" {
			continue
		}
		cssURL, err := baseURL.Parse(href)
		if err != nil {
			s.logger.Warn("Failed to resolve CSS URL", zap.String("href", href), zap.Error(err))
			continue
		}
		wg.Add(1)
		// Fetch concurrently.
		go func(url string) {
			defer wg.Done()
			// Use session context for cancellation.
			req, _ := http.NewRequestWithContext(s.ctx, "GET", url, nil)
			s.prepareRequestHeaders(req)
			resp, err := s.client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			p := parser.NewParser(string(body))
			stylesheetChan <- p.Parse()
		}(cssURL.String())
	}

	go func() {
		wg.Wait()
		close(stylesheetChan)
	}()

	for ss := range stylesheetChan {
		styleEngine.AddAuthorSheet(ss)
	}
}

// updateState updates the session's internal state and triggers the JS context reset.
// Assumes s.opMu is held.
func (s *Session) updateState(newURL *url.URL, doc *html.Node, layoutRoot *layout.LayoutBox, resetContext bool) {
	s.mu.Lock()
	s.currentURL = newURL
	title := ""
	if doc != nil {
		if titleNode := htmlquery.FindOne(doc, "//title"); titleNode != nil {
			title = strings.TrimSpace(htmlquery.InnerText(titleNode))
		}
	}
	var exposedFunctionsCopy map[string]interface{}
	var persistentScriptsCopy []string

	if resetContext {
		newState := &schemas.HistoryState{
			State: nil,
			Title: title,
			URL:   newURL.String(),
		}
		s.pushHistoryInternal(newState)
		// Make copies of persistent data to ensure safety after the lock is released.
		exposedFunctionsCopy = make(map[string]interface{})
		for k, v := range s.exposedFunctions {
			exposedFunctionsCopy[k] = v
		}
		persistentScriptsCopy = make([]string, len(s.persistentScripts))
		copy(persistentScriptsCopy, s.persistentScripts)
	} else {
		if s.historyIndex >= 0 && s.historyIndex < len(s.historyStack) {
			s.historyStack[s.historyIndex].Title = title
		}
	}
	// Release the state lock before the potentially long running context reset.
	s.mu.Unlock()

	if resetContext {
		s.resetStateForNewDocument(doc, layoutRoot, s.logger, exposedFunctionsCopy, persistentScriptsCopy)
	}

	s.logger.Debug("Session state updated", zap.String("url", newURL.String()), zap.String("title", title), zap.Bool("context_reset", resetContext))
}

// executePageScripts executes inline and external scripts.
// Assumes s.opMu is held.
func (s *Session) executePageScripts(doc *html.Node) {
	loop := s.getEventLoop()
	if loop == nil {
		return
	}

	gqDoc := goquery.NewDocumentFromNode(doc)
	gqDoc.Find("script").Each(func(i int, sel *goquery.Selection) {
		scriptType, _ := sel.Attr("type")
		normalizedType := strings.ToLower(strings.TrimSpace(scriptType))
		if normalizedType != "" && normalizedType != "text/javascript" && normalizedType != "application/javascript" && normalizedType != "module" {
			return
		}
		if src, exists := sel.Attr("src"); exists && src != "" {
			// Fetch asynchronously.
			s.fetchAndExecuteScript(src)
		} else {
			// Execute inline on the event loop.
			scriptContent := sel.Text()
			if scriptContent != "" {
				loop.RunOnLoop(func(vm *goja.Runtime) {
					if _, err := vm.RunString(scriptContent); err != nil {
						if _, ok := err.(*goja.InterruptedError); !ok {
							s.logger.Warn("Error executing inline script", zap.Error(err))
						}
					}
				})
			}
		}
	})
}

// fetchAndExecuteScript fetches an external script asynchronously.
func (s *Session) fetchAndExecuteScript(src string) {
	resolvedURL, err := s.ResolveURL(src)
	if err != nil {
		s.logger.Warn("Failed to resolve external script URL", zap.String("src", src), zap.Error(err))
		return
	}

	go func() {
		req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, resolvedURL.String(), nil)
		if err != nil {
			s.logger.Error("Failed to create request for external script", zap.Error(err), zap.String("url", resolvedURL.String()))
			return
		}

		s.prepareRequestHeaders(req)
		req.Header.Set("Accept", "*/*")

		resp, err := s.client.Do(req)
		if err != nil {
			// Log error only if the session is not closing.
			if s.ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				s.logger.Warn("Failed to fetch external script", zap.Error(err), zap.String("url", resolvedURL.String()))
			}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.logger.Warn("Failed to read body of external script", zap.Error(err), zap.String("url", resolvedURL.String()))
			return
		}

		if s.ctx.Err() != nil {
			return
		}
		loop := s.getEventLoop()
		if loop == nil {
			return
		}

		loop.RunOnLoop(func(vm *goja.Runtime) {
			if _, err := vm.RunScript(resolvedURL.String(), string(body)); err != nil {
				if _, ok := err.(*goja.InterruptedError); !ok {
					s.logger.Warn("Error executing external script", zap.Error(err), zap.String("url", resolvedURL.String()))
				}
			}
		})
	}()
}

// GetDOMSnapshot retrieves the current DOM. Concurrency safe.
func (s *Session) GetDOMSnapshot(ctx context.Context) (io.Reader, error) {
	// Acquire the operation lock to ensure the DOM is stable.
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()

	bridge := s.getDOMBridge()
	if bridge == nil {
		return bytes.NewBufferString("<html></html>"), nil
	}
	htmlContent, err := bridge.GetOuterHTML()
	if err != nil {
		return nil, err
	}
	if lockedCtx.Err() != nil {
		return nil, lockedCtx.Err()
	}
	return strings.NewReader(htmlContent), nil
}

// Interact performs a sequence of interactions using the humanoid controller.
// This is now the primary entry point for complex, multi step actions.
func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()

	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}

	for _, step := range config.Steps {
		if lockedCtx.Err() != nil {
			return lockedCtx.Err()
		}

		s.logger.Info("Executing interaction step", zap.String("action", string(step.Action)), zap.String("selector", step.Selector))

		switch step.Action {
		case schemas.ActionClick:
			if err := s.humanoidController.IntelligentClick(lockedCtx, step.Selector, nil); err != nil {
				return fmt.Errorf("failed to execute click on '%s': %w", step.Selector, err)
			}
		case schemas.ActionType:
			if err := s.humanoidController.Type(lockedCtx, step.Selector, step.Value, nil); err != nil {
				return fmt.Errorf("failed to execute type on '%s': %w", step.Selector, err)
			}
		case schemas.ActionNavigate:
			if err := s.navigateInternal(lockedCtx, step.Value); err != nil {
				return fmt.Errorf("failed to navigate to '%s': %w", step.Value, err)
			}
		case schemas.ActionWait:
			if step.Milliseconds > 0 {
				if err := s.Sleep(lockedCtx, time.Duration(step.Milliseconds)*time.Millisecond); err != nil {
					return err
				}
			} else {
				if err := s.stabilize(lockedCtx); err != nil {
					return err
				}
			}
		case schemas.ActionSelect:
			if err := s.executeSelectInternal(lockedCtx, step.Selector, step.Value); err != nil {
				return fmt.Errorf("failed to execute select on '%s': %w", step.Selector, err)
			}
		case schemas.ActionSubmit:
			// A "submit" is just a click on a submit button or element within a form.
			if err := s.humanoidController.IntelligentClick(lockedCtx, step.Selector, nil); err != nil {
				return fmt.Errorf("failed to execute submit (via click) on '%s': %w", step.Selector, err)
			}
		default:
			return fmt.Errorf("unsupported interaction action: %s", step.Action)
		}

		// Always stabilize after an action to wait for consequences.
		if err := s.stabilize(lockedCtx); err != nil {
			return err
		}
	}

	return nil
}

// Click simulates a human like mouse click by delegating to the humanoid controller.
func (s *Session) Click(ctx context.Context, selector string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()

	if err := s.humanoidController.IntelligentClick(lockedCtx, selector, nil); err != nil {
		return err
	}
	return s.stabilize(lockedCtx)
}

// Type simulates human like typing by delegating to the humanoid controller.
func (s *Session) Type(ctx context.Context, selector string, text string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()

	if err := s.humanoidController.Type(lockedCtx, selector, text, nil); err != nil {
		return err
	}
	return s.stabilize(lockedCtx)
}

// Submit submits a form by clicking on a submit element within it.
func (s *Session) Submit(ctx context.Context, selector string) error {
	// A human submits a form by clicking a button, so we delegate to Click.
	return s.Click(ctx, selector)
}

// ScrollPage scrolls the page. This is for explicit full page scrolling.
// Most scrolling is now handled implicitly by the humanoid controller.
func (s *Session) ScrollPage(ctx context.Context, direction string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()

	scrollAmount := 500
	var script string
	switch strings.ToLower(direction) {
	case "down":
		script = fmt.Sprintf("window.scrollBy(0, %d);", scrollAmount)
	case "up":
		script = fmt.Sprintf("window.scrollBy(0, -%d);", scrollAmount)
	case "bottom":
		script = "window.scrollTo(0, document.body.scrollHeight || 10000);"
	case "top":
		script = "window.scrollTo(0, 0);"
	default:
		return fmt.Errorf("unsupported scroll direction: %s", direction)
	}
	_, err := s.executeScriptInternal(lockedCtx, script, nil)
	return err
}

// WaitForAsync waits for a duration or stabilization. Concurrency safe.
func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.waitForAsyncInternal(lockedCtx, milliseconds)
}

// waitForAsyncInternal performs the wait logic. Assumes s.opMu is held.
func (s *Session) waitForAsyncInternal(ctx context.Context, milliseconds int) error {
	if milliseconds > 0 {
		return s.Sleep(ctx, time.Duration(milliseconds)*time.Millisecond)
	}
	return s.stabilize(ctx)
}

// ExposeFunction exposes a Go function to JavaScript. Concurrency safe.
func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.exposeFunctionInternal(lockedCtx, name, function)
}

// exposeFunctionInternal exposes the function. Assumes s.opMu is held.
func (s *Session) exposeFunctionInternal(ctx context.Context, name string, function interface{}) error {
	// Update persistent configuration.
	s.mu.Lock()
	s.exposedFunctions[name] = function
	s.mu.Unlock()

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed or event loop not initialized")
	}

	// Inject into the current VM synchronously.
	errChan := make(chan error, 1)
	loop.RunOnLoop(func(vm *goja.Runtime) {
		vm.ClearInterrupt()
		errChan <- vm.Set(name, function)
	})

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// InjectScriptPersistently injects a script persistently. Concurrency safe.
func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.injectScriptPersistentlyInternal(lockedCtx, script)
}

// injectScriptPersistentlyInternal injects the script. Assumes s.opMu is held.
func (s *Session) injectScriptPersistentlyInternal(ctx context.Context, script string) error {
	// Update persistent configuration.
	s.mu.Lock()
	s.persistentScripts = append(s.persistentScripts, script)
	s.mu.Unlock()

	// Execute immediately using the internal version.
	_, err := s.executeScriptInternal(ctx, script, nil)
	return err
}

// ExecuteScript executes JavaScript. Concurrency safe.
func (s *Session) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeScriptInternal(lockedCtx, script, args)
}

// executeScriptInternal executes the script. Assumes s.opMu is held.
func (s *Session) executeScriptInternal(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	var result interface{}
	// Use the low level execution helper.
	err := s.executeScriptLowLevel(ctx, script, &result, args)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return json.RawMessage("null"), nil
	}
	return json.Marshal(result)
}

// executeScriptLowLevel handles the low level interaction with the Goja event loop.
// It includes robust panic recovery to prevent a misbehaving script from
// crashing the session's entire event loop goroutine.
// Assumes s.opMu is held.
func (s *Session) executeScriptLowLevel(ctx context.Context, script string, res interface{}, args []interface{}) error {
	execCtx, execCancel := CombineContext(s.ctx, ctx)
	defer execCancel()
	if execCtx.Err() != nil {
		return execCtx.Err()
	}

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed: event loop unavailable")
	}

	resultChan := make(chan struct {
		Value goja.Value
		Error error
	}, 1)

	loop.RunOnLoop(func(vm *goja.Runtime) {
		// This defer/recover block is critical. It prevents a panic inside Goja
		// (e.g., from a badly written script) from killing the event loop goroutine.
		defer func() {
			if r := recover(); r != nil {
				err := fmt.Errorf("panic in javascript execution: %v", r)
				s.logger.Error("Recovered from panic in event loop", zap.Error(err), zap.String("stack", string(debug.Stack())))
				// Send the panic as an error to the calling function.
				resultChan <- struct {
					Value goja.Value
					Error error
				}{nil, err}
			}
		}()

		vm.ClearInterrupt()
		// Set up a specific interrupt channel for this execution.
		execInterruptHandle := make(chan struct{})
		vm.Interrupt(execInterruptHandle)
		// Restore the default session interrupt handler afterwards.
		defer vm.Interrupt(s.ctx.Done())
		executionDone := make(chan struct{})

		// Monitor the context. If canceled, signal the interrupt handler.
		go func() {
			select {
			case <-execCtx.Done():
				close(execInterruptHandle)
			case <-executionDone:
			}
		}()

		var val goja.Value
		var err error

		// The actual script execution happens within this function scope.
		func() {
			defer close(executionDone)
			// TODO: Handle args if provided.
			val, err = vm.RunString(script)
		}()

		// Send the result back.
		select {
		case resultChan <- struct {
			Value goja.Value
			Error error
		}{val, err}:
		case <-execCtx.Done():
			// If context is done, don't block.
		}
	})

	// Wait for the result or cancellation.
	select {
	case result := <-resultChan:
		return s.processScriptResult(execCtx, result.Value, result.Error, res)
	case <-execCtx.Done():
		return execCtx.Err()
	}
}

func (s *Session) waitForPromise(ctx context.Context, promise *goja.Promise) (goja.Value, error) {
	loop := s.getEventLoop()
	if loop == nil {
		return nil, errors.New("session closed while waiting for promise")
	}

	resultChan := make(chan struct {
		Value goja.Value
		Error error
	}, 1)

	var check func()

	check = func() {
		if ctx.Err() != nil {
			select {
			case resultChan <- struct {
				Value goja.Value
				Error error
			}{nil, ctx.Err()}:
			default:
			}
			return
		}

		switch promise.State() {
		case goja.PromiseStateFulfilled:
			resultChan <- struct {
				Value goja.Value
				Error error
			}{promise.Result(), nil}
		case goja.PromiseStateRejected:
			err := fmt.Errorf("javascript promise rejected: %v", promise.Result().Export())
			resultChan <- struct {
				Value goja.Value
				Error error
			}{nil, err}
		case goja.PromiseStatePending:
			loop.SetTimeout(func(_ *goja.Runtime) {
				check()
			}, 10*time.Millisecond)
		}
	}

	loop.RunOnLoop(func(_ *goja.Runtime) {
		check()
	})

	select {
	case res := <-resultChan:
		return res.Value, res.Error
	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled while waiting for promise: %w", ctx.Err())
	}
}

func (s *Session) processScriptResult(ctx context.Context, value goja.Value, err error, res interface{}) error {
	if err != nil {
		var gojaException *goja.Exception
		var interruptedError *goja.InterruptedError

		// Check for interruption first. This is the most common case for cancellation.
		if errors.As(err, &interruptedError) {
			// If the script was interrupted, the definitive source of truth is the context passed to the function.
			// Return the context's error to provide a clear reason (canceled or deadline exceeded).
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("javascript execution interrupted by context: %w", ctxErr)
			}
			// If the context is fine but the session is closing, that's another valid reason.
			if s.ctx.Err() != nil {
				return fmt.Errorf("javascript execution interrupted (session closing): %w", err)
			}
			// An interruption without a clear reason is unexpected.
			return fmt.Errorf("javascript execution interrupted unexpectedly: %w", err)
		}

		// Check for a standard JS exception.
		if errors.As(err, &gojaException) {
			return fmt.Errorf("javascript exception: %s", gojaException.String())
		}
		// Fallback for other errors, including panics that were recovered.
		return fmt.Errorf("javascript execution error: %w", err)
	}

	// If the result is a Promise, we must wait for it to resolve.
	if promise, ok := value.Export().(*goja.Promise); ok {
		var promiseErr error
		value, promiseErr = s.waitForPromise(ctx, promise)
		if promiseErr != nil {
			return promiseErr
		}
	}

	// Export the final value to the provided result interface.
	if res != nil && value != nil && !goja.IsUndefined(value) && !goja.IsNull(value) {
		loop := s.getEventLoop()
		if loop == nil {
			return errors.New("session closed: event loop unavailable for result export")
		}

		exportErrChan := make(chan error, 1)
		loop.RunOnLoop(func(vm *goja.Runtime) {
			exportErrChan <- vm.ExportTo(value, res)
		})

		select {
		case exportErr := <-exportErrChan:
			return exportErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *Session) GetCurrentURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentURL != nil {
		return s.currentURL.String()
	}
	return ""
}

// ExecuteClick performs the click action. Concurrency safe. Implements humanoid.Executor.
func (s *Session) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeClickInternal(lockedCtx, selector, minMs, maxMs)
}

// executeClickInternal performs the click action. Assumes s.opMu is held.
func (s *Session) executeClickInternal(ctx context.Context, selector string, minMs, maxMs int) error {
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		// Placeholder for humanoid timing simulation.
	}

	bridge := s.getDOMBridge()
	if bridge == nil {
		return errors.New("session closed during click operation")
	}

	// The default action (state change, navigation) MUST happen before the event fires,
	// just like in a real browser where the default action can be prevented by JS.
	err = s.handleClickConsequenceInternal(ctx, element)
	// Do not return yet, we must still fire the JS event.

	// Now, dispatch the JavaScript 'click' event on the event loop.
	loop := s.getEventLoop()
	if loop != nil {
		loop.RunOnLoop(func(vm *goja.Runtime) {
			bridge.DispatchEventOnNode(element, "click")
		})
	}

	// Return the original error from the consequence handler, if any.
	return err
}

// ExecuteType performs the typing action. Concurrency safe. Implements humanoid.Executor.
func (s *Session) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeTypeInternal(lockedCtx, selector, text, holdMeanMs)
}

// executeTypeInternal performs the typing action. Assumes s.opMu is held.
func (s *Session) executeTypeInternal(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during interaction")
	}

	loop.RunOnLoop(func(vm *goja.Runtime) {
		if bridge := s.getDOMBridge(); bridge != nil {
			bridge.DispatchEventOnNode(element, "focus")
		}
	})

	escapedSelector := strings.ReplaceAll(selector, "'", "\\'")
	scriptToGetValue := fmt.Sprintf(`document.querySelector('%s').value || ''`, escapedSelector)

	var result json.RawMessage
	// Use the internal script execution version as the lock is held.
	result, err = s.executeScriptInternal(ctx, scriptToGetValue, nil)
	if err != nil {
		return fmt.Errorf("could not get initial value of element '%s': %w", selector, err)
	}
	var currentValue string
	if err := json.Unmarshal(result, &currentValue); err != nil {
		return fmt.Errorf("could not decode element value: %w", err)
	}

	for _, char := range text {
		if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
			if err := s.Sleep(ctx, 50*time.Millisecond); err != nil {
				return err
			}
		}

		currentValue += string(char)
		escapedValue := strings.ReplaceAll(currentValue, "'", "\\'")
		escapedValue = strings.ReplaceAll(escapedValue, `\`, `\\`)

		scriptToSetValue := fmt.Sprintf(`document.querySelector('%s').value = '%s'`, escapedSelector, escapedValue)
		// Use the internal script execution version.
		if _, err := s.executeScriptInternal(ctx, scriptToSetValue, nil); err != nil {
			s.logger.Warn("Failed to update element value via script", zap.String("selector", selector), zap.Error(err))
		}

		currentLoop := s.getEventLoop()
		if currentLoop == nil {
			return errors.New("session closed during typing loop")
		}
		currentLoop.RunOnLoop(func(vm *goja.Runtime) {
			if bridge := s.getDOMBridge(); bridge != nil {
				bridge.DispatchEventOnNode(element, "keydown")
				bridge.DispatchEventOnNode(element, "keypress")
				bridge.DispatchEventOnNode(element, "input")
				bridge.DispatchEventOnNode(element, "keyup")
			}
		})
	}

	finalLoop := s.getEventLoop()
	if finalLoop != nil {
		finalLoop.RunOnLoop(func(vm *goja.Runtime) {
			if bridge := s.getDOMBridge(); bridge != nil {
				bridge.DispatchEventOnNode(element, "blur")
			}
		})
	}

	return nil
}

// ExecuteSelect selects an option. Concurrency safe.
func (s *Session) ExecuteSelect(ctx context.Context, selector string, value string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeSelectInternal(lockedCtx, selector, value)
}

// executeSelectInternal performs the select logic. Assumes s.opMu is held.
func (s *Session) executeSelectInternal(ctx context.Context, selector string, value string) error {
	selectNode, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during interaction")
	}

	isSelect := false
	// Synchronize with the event loop to safely inspect the node data if necessary.
	done := make(chan struct{})
	loop.RunOnLoop(func(_ *goja.Runtime) {
		defer close(done)
		if strings.ToLower(selectNode.Data) == "select" {
			isSelect = true
		}
	})

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	if !isSelect {
		return fmt.Errorf("element '%s' is not a select element", selector)
	}

	escapedSelector := strings.ReplaceAll(selector, "'", "\\'")
	escapedValue := strings.ReplaceAll(value, "'", "\\'")
	escapedValue = strings.ReplaceAll(escapedValue, `\`, `\\`)

	// REFACTOR: This script is more robust and efficient.
	// It directly sets the .value property of the select element, which is how JS
	// engines typically handle this. It then confirms the change by reading the value back.
	// This avoids iterating through all options and is less code.
	script := fmt.Sprintf(`
        (function() {
            const select = document.querySelector('%s');
            if (!select) { return false; }
            select.value = '%s';
            // Verify that the value was actually set. This handles cases
            // where an option with the given value doesn't exist.
            return select.value === '%s';
        })()
    `, escapedSelector, escapedValue, escapedValue)

	// Use the internal script execution version.
	resultRaw, err := s.executeScriptInternal(ctx, script, nil)
	if err != nil {
		return fmt.Errorf("script to set select value failed for '%s': %w", selector, err)
	}

	var found bool
	if err := json.Unmarshal(resultRaw, &found); err != nil || !found {
		return fmt.Errorf("option with value '%s' not found or script failed", value)
	}

	finalLoop := s.getEventLoop()
	if finalLoop != nil {
		finalLoop.RunOnLoop(func(vm *goja.Runtime) {
			if bridge := s.getDOMBridge(); bridge != nil {
				bridge.DispatchEventOnNode(selectNode, "input")
				bridge.DispatchEventOnNode(selectNode, "change")
			}
		})
	}

	return nil
}

// IsVisible checks visibility. Concurrency safe.
func (s *Session) IsVisible(ctx context.Context, selector string) bool {
	// Acquire the operation lock to ensure a stable layout state.
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.isVisibleInternal(lockedCtx, selector)
}

// isVisibleInternal checks visibility. Assumes s.opMu is held.
func (s *Session) isVisibleInternal(ctx context.Context, selector string) bool {
	s.mu.RLock()
	currentLayoutRoot := s.layoutRoot
	s.mu.RUnlock()

	if currentLayoutRoot == nil {
		return false
	}
	geo, err := s.layoutEngine.GetElementGeometry(currentLayoutRoot, selector)
	return err == nil && geo != nil
}

// JSNavigate handles navigation initiated by JavaScript. Called from the event loop.
func (s *Session) JSNavigate(targetURL string) {
	// Run in a new goroutine to avoid blocking the event loop.
	go func() {
		// Call the public Navigate method, which acquires the operation lock.
		if err := s.Navigate(s.ctx, targetURL); err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				s.logger.Error("JS initiated navigation failed", zap.Error(err))
			}
		}
	}()
}

// NotifyURLChange handles URL updates from JS. Called from the event loop. Must not acquire opMu.
func (s *Session) NotifyURLChange(targetURL string) {
	// Uses fine grained lock s.mu.
	s.mu.Lock()
	defer s.mu.Unlock()

	newURL, err := url.Parse(targetURL)
	if err == nil {
		s.currentURL = newURL
		s.logger.Debug("URL updated by JS (e.g., hash change)", zap.String("url", newURL.String()))
	} else {
		s.logger.Warn("Failed to parse URL from JS notification", zap.String("url", targetURL), zap.Error(err))
	}
}

// ExecuteFetch handles fetch() API calls. Called from the event loop. Must not acquire opMu.
func (s *Session) ExecuteFetch(ctx context.Context, reqData schemas.FetchRequest) (*schemas.FetchResponse, error) {
	fetchCtx, fetchCancel := CombineContext(s.ctx, ctx)
	defer fetchCancel()

	resolvedURL, err := s.ResolveURL(reqData.URL)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if len(reqData.Body) > 0 {
		bodyReader = bytes.NewReader(reqData.Body)
	}

	httpReq, err := http.NewRequestWithContext(fetchCtx, reqData.Method, resolvedURL.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	s.prepareRequestHeaders(httpReq)
	for _, h := range reqData.Headers {
		httpReq.Header.Add(h.Name, h.Value)
	}

	// Safely copy the client configuration for modification.
	fetchClient := *s.client
	fetchClient.CheckRedirect = nil
	if reqData.Credentials == "omit" {
		fetchClient.Jar = nil
	}

	httpResp, err := fetchClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	// Ensure the body is fully read for connection reuse.
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	response := &schemas.FetchResponse{
		URL:        httpResp.Request.URL.String(),
		Status:     httpResp.StatusCode,
		StatusText: httpResp.Status,
		Headers:    []schemas.NVPair{},
		Body:       respBody,
	}
	for name, values := range httpResp.Header {
		for _, value := range values {
			response.Headers = append(response.Headers, schemas.NVPair{Name: name, Value: value})
		}
	}
	return response, nil
}

// AddCookieFromString is called by the JavaScript environment. Must not acquire opMu.
func (s *Session) AddCookieFromString(cookieStr string) error {
	if s.client.Jar == nil {
		return fmt.Errorf("cookie jar not initialized")
	}
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	if currentURL == nil {
		return nil
	}
	header := http.Header{}
	header.Add("Set-Cookie", cookieStr)
	res := http.Response{Header: header}
	cookies := res.Cookies()
	if len(cookies) > 0 {
		// The cookiejar implementation is thread safe.
		s.client.Jar.SetCookies(currentURL, cookies)
	}
	return nil
}

// GetCookieString is called by the JavaScript environment. Must not acquire opMu.
func (s *Session) GetCookieString() (string, error) {
	if s.client.Jar == nil {
		return "", nil
	}
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	if currentURL == nil {
		return "", nil
	}
	// The cookiejar implementation is thread safe.
	cookies := s.client.Jar.Cookies(currentURL)
	var cookieStrings []string
	for _, c := range cookies {
		if !c.HttpOnly {
			cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
	}
	return strings.Join(cookieStrings, "; "), nil
}

// History methods are called by the JS environment. Must not acquire opMu.

func (s *Session) PushHistory(state *schemas.HistoryState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushHistoryInternal(state)
	return nil
}

// pushHistoryInternal updates the history stack. Caller must hold s.mu.
func (s *Session) pushHistoryInternal(state *schemas.HistoryState) {
	s.historyStack = s.historyStack[:s.historyIndex+1]
	s.historyStack = append(s.historyStack, state)
	s.historyIndex++
}

func (s *Session) ReplaceHistory(state *schemas.HistoryState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.historyIndex >= 0 {
		s.historyStack[s.historyIndex] = state
	} else {
		s.pushHistoryInternal(state)
	}
	return nil
}

func (s *Session) GetHistoryLength() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.historyStack)
}

func (s *Session) GetCurrentHistoryState() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.historyIndex >= 0 && s.historyIndex < len(s.historyStack) {
		return s.historyStack[s.historyIndex].State
	}
	return nil
}

// ResolveURL resolves a URL. Concurrency safe.
func (s *Session) ResolveURL(targetURL string) (*url.URL, error) {
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	if currentURL != nil {
		return currentURL.ResolveReference(parsedURL), nil
	}
	if !parsedURL.IsAbs() {
		return nil, fmt.Errorf("must be an absolute URL for initial navigation: %s", targetURL)
	}
	return parsedURL, nil
}

func (s *Session) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DispatchMouseEvent implements humanoid.Executor. Concurrency safe.
func (s *Session) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	// We only care about the final "mouse up" to trigger a click.
	if data.Type == schemas.MouseRelease {
		// Acquire the high level operation lock to ensure state consistency during this action.
		lockedCtx, unlock := s.acquireOpLock(ctx)
		defer unlock()

		// Check if the context was cancelled (e.g., session closing) before proceeding.
		if lockedCtx.Err() != nil {
			return lockedCtx.Err()
		}

		bridge := s.getDOMBridge()
		if bridge == nil {
			return errors.New("session is closed, DOM bridge unavailable")
		}

		// 1. Perform a "hit test" to find the element at the cursor.
		// Note: FindNodeAtPoint is a temporary implementation.
		hitNode := bridge.FindNodeAtPoint(data.X, data.Y)

		if hitNode != nil {
			// 2. Lock the DOM and perform the default action.
			// The PerformDefaultClickAction function expects the lock to be held by the caller.
			bridge.Lock()
			defer bridge.Unlock()
			bridge.PerformDefaultClickAction(hitNode)
		}
	}
	return nil
}

// SendKeys implements humanoid.Executor. Concurrency safe.
func (s *Session) SendKeys(ctx context.Context, keys string) error {
	// Acquire operation lock.
	_, unlock := s.acquireOpLock(ctx)
	defer unlock()

	s.logger.Debug("Sending keys (TODO: implement key dispatch)", zap.String("keys", keys))
	// TODO: Implement key event dispatch.
	return nil
}

// GetElementGeometry returns element geometry. Concurrency safe.
func (s *Session) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	// Acquire operation lock for stable layout state.
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.getElementGeometryInternal(lockedCtx, selector)
}

// getElementGeometryInternal gets geometry. Assumes s.opMu is held.
func (s *Session) getElementGeometryInternal(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	s.mu.RLock()
	currentLayoutRoot := s.layoutRoot
	s.mu.RUnlock()
	if currentLayoutRoot == nil {
		return nil, fmt.Errorf("layout tree not available")
	}
	return s.layoutEngine.GetElementGeometry(currentLayoutRoot, selector)
}

// CollectArtifacts collects session data. Concurrency safe.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	// Acquire the operation lock for a stable state.
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.collectArtifactsInternal(lockedCtx)
}

// collectArtifactsInternal collects artifacts. Assumes s.opMu is held.
func (s *Session) collectArtifactsInternal(ctx context.Context) (*schemas.Artifacts, error) {
	artifacts := &schemas.Artifacts{}

	s.consoleLogsMu.Lock()
	artifacts.ConsoleLogs = make([]schemas.ConsoleLog, len(s.consoleLogs))
	copy(artifacts.ConsoleLogs, s.consoleLogs)
	s.consoleLogsMu.Unlock()

	if s.harvester != nil {
		harData := s.harvester.GenerateHAR()
		rawHar, _ := json.Marshal(harData)
		artifacts.HAR = (*json.RawMessage)(&rawHar)
	}

	// Get DOM snapshot.
	domSnapshot, _ := s.GetDOMSnapshot(ctx)
	if domSnapshot != nil {
		snapshotBytes, _ := io.ReadAll(domSnapshot)
		artifacts.DOM = string(snapshotBytes)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	artifacts.Storage = schemas.StorageState{}

	return artifacts, nil
}

func (s *Session) AddFinding(finding schemas.Finding) error {
	if s.findingsChan != nil {
		if finding.Timestamp.IsZero() {
			finding.Timestamp = time.Now()
		}
		// Non blocking send.
		select {
		case s.findingsChan <- finding:
			return nil
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
			return fmt.Errorf("findings channel is full")
		}
	}
	return fmt.Errorf("findings channel not initialized")
}

func (s *Session) prepareRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", s.persona.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", strings.Join(s.persona.Languages, ","))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	if currentURL != nil {
		req.Header.Set("Referer", currentURL.String())
	}
}

// findElementNode queries the DOM bridge synchronously on the event loop.
// Assumes s.opMu is held.
func (s *Session) findElementNode(selector string) (*html.Node, error) {
	bridge := s.getDOMBridge()
	if bridge == nil {
		return nil, fmt.Errorf("DOM bridge is not initialized or session is closed")
	}

	loop := s.getEventLoop()
	if loop == nil {
		return nil, errors.New("session closed: event loop unavailable")
	}

	var resultNode *html.Node
	var resultErr error
	done := make(chan struct{})

	// Execute the query on the event loop to ensure thread safety for DOM access.
	loop.RunOnLoop(func(vm *goja.Runtime) {
		defer func() {
			// Recover from potential panics in the underlying query library.
			if r := recover(); r != nil {
				s.logger.Error("Panic recovered during QuerySelector",
					zap.Any("panic_value", r),
					zap.String("selector", selector),
					zap.String("stack", string(debug.Stack())))
				// If a panic occurred, report it as an error.
				resultErr = fmt.Errorf("panic during QuerySelector: %v", r)
			}
			close(done)
		}()
		// We rely on the DOMBridge's QuerySelector implementation.
		resultNode, resultErr = bridge.QuerySelector(selector)
	})

	// Wait for the query to complete.
	<-done

	if resultErr != nil {
		// Provide a more informative error if it was a specific XPath panic.
		if strings.Contains(resultErr.Error(), "unknown item: 35") || strings.Contains(resultErr.Error(), "invalid xpath") || strings.Contains(resultErr.Error(), "panic during QuerySelector") {
			return nil, fmt.Errorf("failed to execute selector '%s'. This might be due to an invalid selector or the underlying query engine incorrectly parsing CSS as XPath: %w", selector, resultErr)
		}
		return nil, fmt.Errorf("failed to find element '%s': %w", selector, resultErr)
	}

	// Ensure that we return an error if the element is not found.
	if resultNode == nil {
		return nil, fmt.Errorf("element not found for selector: %s", selector)
	}

	return resultNode, nil
}

// handleClickConsequenceInternal handles the consequences of a click.
// Assumes s.opMu is held. Must be called with the locked context.
func (s *Session) handleClickConsequenceInternal(ctx context.Context, element *html.Node) error {
	// This function must now handle all possible default actions for a click.
	bridge := s.getDOMBridge()
	if bridge == nil {
		return errors.New("session closed")
	}

	// Use the bridge's locking mechanism to ensure safe DOM manipulation.
	bridge.Lock()
	defer bridge.Unlock()

	// 1. Handle form input elements (checkboxes, radios)
	if strings.ToLower(element.Data) == "input" {
		inputType := strings.ToLower(htmlquery.SelectAttr(element, "type"))
		if inputType == "checkbox" {
			// Toggle the "checked" attribute.
			if _, isChecked := getAttr(element, "checked"); isChecked {
				removeAttr(element, "checked")
			} else {
				addAttr(element, "checked", "checked")
			}
			return nil // No further action for a checkbox click.
		}
		if inputType == "radio" {
			// Uncheck all other radios in the same group and check this one.
			radioName := htmlquery.SelectAttr(element, "name")
			if radioName != "" {
				// Find the root to query from.
				root := element
				for root.Parent != nil {
					root = root.Parent
				}
				// Query for all radios in the same form/document with the same name.
				radios := htmlquery.Find(root, fmt.Sprintf(`//input[@type='radio' and @name='%s']`, radioName))
				for _, radio := range radios {
					removeAttr(radio, "checked")
				}
			}
			// Check the clicked radio button.
			addAttr(element, "checked", "checked")
			return nil // No further action.
		}
	}

	// 2. Handle navigation links (<a>)
	if strings.ToLower(element.Data) == "a" {
		if href := htmlquery.SelectAttr(element, "href"); href != "" {
			// CRITICAL: Call navigateInternal, not Navigate, as the lock is already held.
			return s.navigateInternal(ctx, href)
		}
	}

	// 3. Handle form submissions
	// If the element is a submit button or is inside a form, find the parent form.
	form := findParentForm(element)
	if form != nil {
		// Check if the clicked element is a submit button, which is the default for buttons inside forms.
		isSubmitButton := false
		if strings.ToLower(element.Data) == "button" && strings.ToLower(htmlquery.SelectAttr(element, "type")) != "reset" {
			isSubmitButton = true
		}
		if strings.ToLower(element.Data) == "input" && strings.ToLower(htmlquery.SelectAttr(element, "type")) == "submit" {
			isSubmitButton = true
		}

		if isSubmitButton {
			return s.submitFormInternal(ctx, form)
		}
	}
	return nil
}

// submitFormInternal handles form submission.
// Assumes s.opMu is held. Must be called with the locked context.
func (s *Session) submitFormInternal(ctx context.Context, form *html.Node) error {
	var action, method, enctype string
	var formData url.Values

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during form submission preparation")
	}

	// Gather form data synchronously on the event loop.
	done := make(chan struct{})

	loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)

		action = htmlquery.SelectAttr(form, "action")
		method = strings.ToUpper(htmlquery.SelectAttr(form, "method"))
		enctype = htmlquery.SelectAttr(form, "enctype")

		if method == "" {
			method = http.MethodGet
		}
		if enctype == "" {
			enctype = "application/x-www-form-urlencoded"
		}

		formData = url.Values{}

		inputs := htmlquery.Find(form, ".//input | .//textarea | .//select")
		for _, input := range inputs {
			name := htmlquery.SelectAttr(input, "name")
			if name == "" {
				continue
			}
			tagName := strings.ToLower(input.Data)

			if _, disabled := getAttr(input, "disabled"); disabled {
				continue
			}

			switch tagName {
			case "input":
				inputType := strings.ToLower(htmlquery.SelectAttr(input, "type"))
				if (inputType == "checkbox" || inputType == "radio") {
					if _, checked := getAttr(input, "checked"); checked {
						formData.Add(name, htmlquery.SelectAttr(input, "value"))
					}
				} else if inputType != "submit" && inputType != "reset" && inputType != "button" && inputType != "image" {
					formData.Add(name, htmlquery.SelectAttr(input, "value"))
				}
			case "textarea":
				formData.Add(name, htmlquery.InnerText(input))
			case "select":
				selectedOption := htmlquery.FindOne(input, ".//option[@selected]")
				if selectedOption != nil {
					formData.Add(name, htmlquery.SelectAttr(selectedOption, "value"))
				} else {
					firstOption := htmlquery.FindOne(input, ".//option")
					if firstOption != nil {
						formData.Add(name, htmlquery.SelectAttr(firstOption, "value"))
					}
				}
			}
		}
	})

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	targetURL, err := s.ResolveURL(action)
	if err != nil {
		return fmt.Errorf("failed to resolve form action URL: %w", err)
	}

	var req *http.Request

	if method == http.MethodPost {
		if enctype != "application/x-www-form-urlencoded" {
			s.logger.Warn("Unsupported form enctype, submitting as urlencoded", zap.String("enctype", enctype))
		}
		body := strings.NewReader(formData.Encode())
		req, err = http.NewRequestWithContext(ctx, method, targetURL.String(), body)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else { // GET request
		targetURL.RawQuery = formData.Encode()
		req, err = http.NewRequestWithContext(ctx, method, targetURL.String(), nil)
		if err != nil {
			return err
		}
	}

	s.prepareRequestHeaders(req)
	// Execute the request (handles navigation). Lock is held.
	return s.executeRequest(ctx, req)
}

func getAttr(n *html.Node, key string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}
	return "", false
}

// addAttr is a helper to add or update an attribute on a node.
func addAttr(n *html.Node, key, val string) {
	if n == nil {
		return
	}
	// Check if the attribute already exists to update it.
	for i := range n.Attr {
		if n.Attr[i].Key == key {
			n.Attr[i].Val = val
			return
		}
	}
	// If it doesn't exist, append it.
	n.Attr = append(n.Attr, html.Attribute{Key: key, Val: val})
}

// removeAttr is a helper to remove an attribute from a node.
func removeAttr(n *html.Node, key string) {
	if n == nil {
		return
	}
	newAttrs := make([]html.Attribute, 0, len(n.Attr))
	for _, attr := range n.Attr {
		if attr.Key != key {
			newAttrs = append(newAttrs, attr)
		}
	}
	n.Attr = newAttrs
}

func findParentForm(element *html.Node) *html.Node {
	if element == nil {
		return nil
	}
	for p := element.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && strings.ToLower(p.Data) == "form" {
			return p
		}
	}
	return nil
}

// CombineContext creates a new context that is canceled when either the parent or secondary context is canceled.
// This is a robust implementation to prevent goroutine leaks.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	if secondaryCtx.Err() != nil {
		return secondaryCtx, func() {}
	}
	if parentCtx.Err() != nil {
		return parentCtx, func() {}
	}

	combinedCtx, cancel := context.WithCancel(parentCtx)

	stop := make(chan struct{})

	go func() {
		select {
		case <-secondaryCtx.Done():
			cancel()
		case <-combinedCtx.Done():
		case <-stop:
		}
	}()

	return combinedCtx, func() {
		select {
		case stop <- struct{}{}:
		default:
		}
		cancel()
	}
}