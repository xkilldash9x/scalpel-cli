// internal/browser/session/session.go

// Package session implements a functional, headless browser engine in pure Go.
// It integrates a robust network stack, a Go-based DOM representation (golang.org/x/net/html),
// and the Goja JavaScript runtime, synchronized via an event loop and a custom DOM bridge.
package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/antchfx/htmlquery"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/net/html"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/dom"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/layout"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

/*
Architectural Overview:
This implementation provides a functional headless browser engine by integrating the Goja JavaScript runtime
with a stateful Go DOM representation (*html.Node) and a CSS-driven Layout Engine.

Concurrency Model:
The Goja runtime is single threaded. All JS execution and DOM manipulation triggered by JS occur on the
dedicated Event Loop goroutine (managed by goja_nodejs/eventloop). Synchronization between Go interactions
(e.g., Click, Navigate) and the JS runtime is achieved by scheduling tasks onto the event loop using
eventLoop.RunOnLoop().

DOM Bridge (jsbind implementation):
The 'DOMBridge' structure is the synchronization layer. It exposes W3C DOM APIs
to the JS runtime, backed by the *html.Node structure, ensuring a live, interactive environment.

Layout Engine Integration:
After parsing an HTML document and its associated CSS, the `layout.Engine` computes a `LayoutTree`. This
tree contains the geometry (size and position) of every rendered element, enabling accurate visibility checks
and coordinate based interactions.
*/

// Session represents a single, functional browsing context (equivalent to a tab).
// It implements schemas.SessionContext.
type Session struct {
	id      string
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *zap.Logger
	cfg     *config.Config
	persona schemas.Persona

	// Core functional components
	client       *http.Client
	interactor   *dom.Interactor
	harvester    *Harvester
	layoutEngine *layout.Engine

	// JavaScript Engine and Event Loop
	eventLoop  *eventloop.EventLoop
	jsRegistry *require.Registry

	// Humanoid configuration
	humanoidCfg *humanoid.Config

	// State management
	// mu protects the core state variables accessed by both Go routines and the Event Loop thread.
	mu sync.RWMutex

	currentURL *url.URL
	// The root of the rendered layout tree, containing element geometry.
	layoutRoot *layout.LayoutBox
	// DOMBridge holds the synchronized DOM representation and manages interaction with the JS runtime.
	domBridge *DOMBridge

	// Persistent configuration across navigations
	persistentScripts []string
	exposedFunctions  map[string]interface{} // Functions exposed via ExposeFunction

	// Artifacts
	consoleLogs   []schemas.ConsoleLog
	consoleLogsMu sync.Mutex

	findingsChan chan<- schemas.Finding
	onClose      func()
	closeOnce    sync.Once
}

// sessionConsolePrinter implements the console.Printer interface (required for newer goja_nodejs versions).
type sessionConsolePrinter struct {
	s *Session
}

func (p *sessionConsolePrinter) Log(msg string) {
	// In the new API, Log corresponds to console.log() and console.info()
	p.s.captureConsoleLog("log", msg)
}

func (p *sessionConsolePrinter) Warn(msg string) {
	p.s.captureConsoleLog("warn", msg)
}

func (p *sessionConsolePrinter) Error(msg string) {
	p.s.captureConsoleLog("error", msg)
}

// Ensure Session implements the required interface.
var _ schemas.SessionContext = (*Session)(nil)

// We also implement dom.CorePagePrimitives for compatibility with the automated Interactor.
var _ dom.CorePagePrimitives = (*Session)(nil)

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

	s := &Session{
		id:                sessionID,
		ctx:               ctx,
		cancel:            cancel,
		logger:            log,
		cfg:               cfg,
		persona:           persona,
		findingsChan:      findingsChan,
		layoutEngine:      layout.NewEngine(),
		persistentScripts: make([]string, 0),
		exposedFunctions:  make(map[string]interface{}),
		consoleLogs:       make([]schemas.ConsoleLog, 0),
	}

	// 1. Initialize JavaScript Runtime and Event Loop.
	if err := s.initializeJSEngine(log); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize JS engine: %w", err)
	}

	// 2. Configure Humanoid behavior.
	var domHCfg dom.HumanoidConfig
	if cfg.Browser.Humanoid.Enabled {
		cfgCopy := cfg.Browser.Humanoid
		if cfgCopy.Rng == nil {
			source := rand.NewSource(time.Now().UnixNano())
			//nolint:gosec
			cfgCopy.Rng = rand.New(source)
		}
		cfgCopy.FinalizeSessionPersona(cfgCopy.Rng)
		s.humanoidCfg = &cfgCopy

		domHCfg = dom.HumanoidConfig{
			Enabled:        true,
			KeyHoldMeanMs:  s.humanoidCfg.KeyHoldMeanMs,
			ClickHoldMinMs: int(s.humanoidCfg.ClickHoldMinMs),
			ClickHoldMaxMs: int(s.humanoidCfg.ClickHoldMaxMs),
		}
	}

	// 3. Initialize the Network Stack.
	if err := s.initializeNetworkStack(log); err != nil {
		s.eventLoop.Stop()
		cancel()
		return nil, fmt.Errorf("failed to initialize network stack: %w", err)
	}

	// 4. Define the stabilization function.
	stabilizeFn := func(ctx context.Context) error {
		// Stabilization means waiting for both network idle AND JS event loop stability.
		return s.stabilize(ctx)
	}

	// 5. Initialize the Interactor.
	s.interactor = dom.NewInteractor(NewZapAdapter(log.Named("interactor")), domHCfg, stabilizeFn, s)

	// 6. Initialize the DOM Bridge (starts with an empty document).
	s.resetDOMBridge(nil, log)

	return s, nil
}

// initializeJSEngine sets up the Goja runtime, the event loop, and global configurations.
func (s *Session) initializeJSEngine(log *zap.Logger) error {
	// Reworked initialization for new eventloop and console APIs.

	// 1. Initialize Registry.
	s.jsRegistry = new(require.Registry)

	// 2. Configure custom console printer.
	printer := &sessionConsolePrinter{s: s}
	// Register the console module with the custom printer using the new RequireWithPrinter function.
	s.jsRegistry.RegisterNativeModule("console", console.RequireWithPrinter(printer))

	// 3. Initialize Event Loop, providing the registry.
	// By default, the event loop will use the registered "console" module.
	s.eventLoop = eventloop.NewEventLoop(eventloop.WithRegistry(s.jsRegistry))

	// 4. Start the event loop. Start() no longer takes arguments.
	s.eventLoop.Start()

	// 5. Configure the runtime environment (globals, navigator, etc.). This MUST happen on the loop thread.
	// We use a channel to ensure initialization completes before proceeding.
	initDone := make(chan struct{})

	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(initDone)

		// Enable module loading (adds the require() function globally).
		s.jsRegistry.Enable(vm)

		// Console is typically set up automatically by the event loop when using WithRegistry.

		// Set up the global context (window, self).
		global := vm.GlobalObject()
		_ = vm.Set("window", global)
		_ = vm.Set("self", global)

		// Initialize 'navigator' based on persona.
		navigator := vm.NewObject()
		_ = navigator.Set("userAgent", s.persona.UserAgent)
		_ = navigator.Set("platform", s.persona.Platform)
		_ = navigator.Set("languages", s.persona.Languages)
		_ = vm.Set("navigator", navigator)

		// Initialize 'location' (will be fully populated by the bridge on navigation).
		_ = vm.Set("location", vm.NewObject())
	})

	// Wait for initialization.
	<-initDone

	log.Info("JavaScript engine (Goja) and event loop initialized.")
	return nil
}

// captureConsoleLog handles messages from the JS console.
func (s *Session) captureConsoleLog(logLevel string, message string) {

	// Log to the main structured logger.
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

	// Store as an artifact.
	s.consoleLogsMu.Lock()
	defer s.consoleLogsMu.Unlock()
	s.consoleLogs = append(s.consoleLogs, schemas.ConsoleLog{
		Type:      logLevel,
		Timestamp: time.Now(),
		Text:      message,
		// Source/URL/Line require deeper integration with Goja's stack tracing.
	})
}

// resetDOMBridge re-initializes the DOMBridge with a new document and binds it to the JS runtime.
// This simulates a fresh page load context. It must be called while holding the session lock (s.mu).
func (s *Session) resetDOMBridge(doc *html.Node, log *zap.Logger) {
	// If doc is nil, initialize an empty HTML structure.
	if doc == nil {
		var err error
		doc, err = html.Parse(strings.NewReader("<html><head></head><body></body></html>"))
		if err != nil {
			// This should be infallible.
			log.Error("Critical error: Failed to parse empty HTML document.", zap.Error(err))
			return
		}
	}

	// Create the new bridge instance.
	bridge := NewDOMBridge(doc, log.Named("dombridge"))
	s.domBridge = bridge

	// Bind the bridge to the JS runtime. This MUST happen on the event loop thread.
	// We use a channel to wait for completion because this function (resetDOMBridge) is called
	// synchronously during the navigation flow (updateState), and we must ensure the JS context
	// is ready before proceeding (e.g., executing page scripts).
	done := make(chan struct{})
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)

		// Bind the DOM APIs (document, element methods, storage, etc.).
		bridge.BindToRuntime(vm)

		// Update window.location based on the current URL.
		if s.currentURL != nil {
			bridge.UpdateLocation(s.currentURL.String())
		}

		// Apply persistent configurations (Exposed functions and Persistent scripts).
		// Accessing s.exposedFunctions/s.persistentScripts here is safe because we hold the Session lock (s.mu).

		// 1. Expose Go functions.
		for name, function := range s.exposedFunctions {
			if err := vm.Set(name, function); err != nil {
				log.Error("Failed to expose persistent function", zap.String("name", name), zap.Error(err))
			}
		}

		// 2. Inject persistent scripts.
		for i, script := range s.persistentScripts {
			log.Debug("Injecting persistent script", zap.Int("index", i))
			if _, err := vm.RunString(script); err != nil {
				// Errors in persistent scripts are non-fatal.
				log.Warn("Error executing persistent script", zap.Error(err))
			}
		}

		// Fire 'DOMContentLoaded' and 'load' events. In a real browser, 'load' waits for sub-resources.
		// Here, we fire them after the initial DOM is ready and synchronous scripts have run.
		go func() {
			// Allow a brief moment for the main thread to proceed before firing async events.
			time.Sleep(10 * time.Millisecond)
			s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				bridge.DispatchEventOnNode(doc, "DOMContentLoaded")
				bridge.DispatchEventOnNode(doc, "load")
			})
		}()
	})

	// Wait for the binding to complete.
	<-done
}

// initializeNetworkStack sets up the http.Client and Harvester middleware.
func (s *Session) initializeNetworkStack(log *zap.Logger) error {
	netConfig := network.NewBrowserClientConfig()
	netConfig.Logger = NewZapAdapter(log.Named("network"))

	netConfig.InsecureSkipVerify = s.cfg.Browser.IgnoreTLSErrors || s.cfg.Network.IgnoreTLSErrors

	if s.cfg.Network.NavigationTimeout > 0 {
		netConfig.RequestTimeout = s.cfg.Network.NavigationTimeout
	} else {
		netConfig.RequestTimeout = 60 * time.Second
	}

	if netConfig.CookieJar == nil {
		jar, _ := cookiejar.New(nil)
		netConfig.CookieJar = jar
	}

	// Setup Transport chain: Base -> Compression -> Harvester
	transport := network.NewHTTPTransport(netConfig)
	compressionTransport := network.NewCompressionMiddleware(transport)
	s.harvester = NewHarvester(compressionTransport, log.Named("harvester"), s.cfg.Network.CaptureResponseBodies)

	// The Client
	s.client = &http.Client{
		Transport: s.harvester,
		Timeout:   netConfig.RequestTimeout,
		Jar:       netConfig.CookieJar,
		// Handle redirects manually for full control over navigation lifecycle.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nil
}

// ID returns the session ID.
func (s *Session) ID() string {
	return s.id
}

// GetContext returns the session's lifecycle context.
func (s *Session) GetContext() context.Context {
	return s.ctx
}

// Close terminates the session and stops the event loop.
func (s *Session) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.logger.Info("Closing session.")

		// Stop the event loop gracefully. This blocks until the loop finishes processing.
		if s.eventLoop != nil {
			s.eventLoop.Stop()
		}

		s.cancel() // Cancel the session context.

		if s.client != nil {
			s.client.CloseIdleConnections()
		}

		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

// SetOnClose sets a callback function to be executed when the session is closed.
func (s *Session) SetOnClose(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onClose = fn
}

// stabilize waits for the system to reach a stable state (Network Idle + JS Idle).
func (s *Session) stabilize(ctx context.Context) error {
	stabCtx, stabCancel := CombineContext(s.ctx, ctx)
	defer stabCancel()

	quietPeriod := 1500 * time.Millisecond // Default stabilization time
	if s.cfg.Network.PostLoadWait > 0 {
		quietPeriod = s.cfg.Network.PostLoadWait
	}

	// 1. Wait for Network Idle.
	if s.harvester != nil {
		if err := s.harvester.WaitNetworkIdle(stabCtx, quietPeriod); err != nil {
			// Log but don't fail immediately, as JS might still need processing.
			s.logger.Debug("Network stabilization finished with potential pending requests.", zap.Error(err))
		}
	}

	// 2. Wait for JS Event Loop Idle.
	// We achieve this by waiting for the quiet period duration, allowing the concurrent event loop
	// time to process pending tasks (like setTimeout or Promises).
	select {
	case <-time.After(quietPeriod):
		// System waited for the quiet period.
	case <-stabCtx.Done():
		return stabCtx.Err()
	}

	// 3. Final synchronization check.
	// Queue a dummy task on the Event Loop and wait for it to execute.
	// This ensures all tasks that might have been queued during the quiet period (e.g., a timer finishing) have run.
	done := make(chan struct{})
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		close(done)
	})

	select {
	case <-done:
		// The loop has processed the dummy task.
	case <-stabCtx.Done():
		return stabCtx.Err()
	}

	s.logger.Debug("Stabilization complete.")
	return nil
}

// -- Navigation and Execution --

// Navigate loads a URL and updates the session state.
func (s *Session) Navigate(ctx context.Context, targetURL string) error {
	navCtx, navCancel := CombineContext(s.ctx, ctx)
	defer navCancel()

	// 1. Resolve URL.
	resolvedURL, err := s.resolveURL(targetURL)
	if err != nil {
		return fmt.Errorf("failed to resolve URL '%s': %w", targetURL, err)
	}

	s.logger.Info("Navigating", zap.String("url", resolvedURL.String()))

	// 2. Dispatch 'beforeunload' event. A real browser would check the return value.
	// Here, we dispatch it for script compatibility but don't yet handle cancellation.
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		if s.domBridge != nil {
			s.domBridge.DispatchEventOnNode(s.domBridge.document, "beforeunload")
		}
	})

	// 3. Create the request.
	req, err := http.NewRequestWithContext(navCtx, http.MethodGet, resolvedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s': %w", resolvedURL.String(), err)
	}
	s.prepareRequestHeaders(req)

	// 4. Execute the request (handles redirects, updates DOM, resets JS context).
	if err := s.executeRequest(navCtx, req); err != nil {
		return err
	}

	// 5. Stabilization after navigation.
	if err := s.stabilize(navCtx); err != nil {
		if navCtx.Err() != nil {
			return navCtx.Err()
		}
		s.logger.Debug("Stabilization finished with potential issues after navigation.", zap.Error(err))
	}

	// 6. Cognitive pause (if enabled).
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		//nolint:gosec
		if err := hesitate(navCtx, 500*time.Millisecond+time.Duration(rand.Intn(1000))*time.Millisecond); err != nil {
			return err
		}
	}

	return nil
}

// executeRequest sends the HTTP request, handles redirects, and processes the final response.
func (s *Session) executeRequest(ctx context.Context, req *http.Request) error {
	const maxRedirects = 10
	currentReq := req

	for i := 0; i < maxRedirects; i++ {
		s.logger.Debug("Executing request", zap.String("method", currentReq.Method), zap.String("url", currentReq.URL.String()))

		resp, err := s.client.Do(currentReq)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}

		// Check for redirects (3xx status codes).
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			nextReq, err := s.handleRedirect(ctx, resp, currentReq)
			_ = resp.Body.Close()
			if err != nil {
				return fmt.Errorf("failed to handle redirect: %w", err)
			}
			currentReq = nextReq
			continue
		}

		// Process the final response (Parse DOM and Reset Context).
		return s.processResponse(resp)
	}

	return fmt.Errorf("maximum number of redirects (%d) exceeded", maxRedirects)
}

// handleRedirect processes a redirect response (standard HTTP logic).
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

	// HTTP spec compliance for redirect methods (301/302/303 vs 307/308).
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

// processResponse parses the DOM, updates the state, resets the JS context, and executes page scripts.
func (s *Session) processResponse(resp *http.Response) error {
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.logger.Warn("Request resulted in error status code", zap.Int("status", resp.StatusCode), zap.String("url", resp.Request.URL.String()))
	}

	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(strings.ToLower(contentType), "text/html")

	var doc *html.Node

	if isHTML {
		// Read the body into a buffer so we can parse it for both DOM and CSS.
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		// Parse for DOM.
		var parseErr error
		doc, parseErr = htmlquery.Parse(bytes.NewReader(bodyBytes))
		if parseErr != nil {
			// Log the error but continue, as the DOM might be partially usable.
			s.logger.Error("Failed to parse HTML response.", zap.Error(parseErr), zap.String("url", resp.Request.URL.String()))
		}

		// Parse for CSS.
		s.extractAndParseCSS(doc, resp.Request.URL)

	} else {
		s.logger.Debug("Response is not HTML.", zap.String("content_type", contentType))
	}

	// Update state and reset the DOM Bridge and JS Context.
	s.updateState(resp.Request.URL, doc, true)

	// If it was HTML and parsed successfully, execute scripts found in the document.
	if isHTML && doc != nil {
		s.executePageScripts(doc)
	}

	return nil
}

// extractAndParseCSS finds, fetches, and parses CSS from <link> and <style> tags.
func (s *Session) extractAndParseCSS(doc *html.Node, baseURL *url.URL) {
	if doc == nil {
		return
	}

	// -- 1. Reset the Layout Engine (Robust Synchronization) --

	// We must synchronize access to the s.layoutEngine pointer, as it is accessed concurrently
	// by other methods (e.g., IsVisible) and asynchronous fetches.
	s.mu.Lock()

	// Reset the layout engine. Since the upstream library removed Reset(), we re-initialize
	// the engine to guarantee a clean state, preventing style leakage across navigations.
	s.layoutEngine = layout.NewEngine()

	// CRITICAL: Capture the reference to the newly created engine instance.
	// This solves a race condition where asynchronous CSS fetches from a previous navigation
	// might complete after this reset, potentially applying stale styles to the new engine.
	currentEngine := s.layoutEngine

	// We can unlock after initialization and capturing the reference.
	s.mu.Unlock()

	// -- 2. Parse Inline <style> tags (Synchronous) --
	styleTags := htmlquery.Find(doc, "//style")
	for _, tag := range styleTags {
		cssContent := htmlquery.InnerText(tag)
		p := parser.NewParser(cssContent)
		stylesheet := p.Parse()

		// Synchronize the addition of the stylesheet.
		s.mu.Lock()
		// Verify that the engine instance we initialized is still the active one before applying styles.
		// (Handles rapid successive navigations).
		if s.layoutEngine == currentEngine {
			s.layoutEngine.AddStyleSheet(stylesheet)
		}
		s.mu.Unlock()
	}

	// -- 3. Fetch and Parse External <link> tags (Asynchronous) --
	linkTags := htmlquery.Find(doc, "//link[@rel='stylesheet' and @href]")
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

		// Asynchronously fetch the CSS, passing the specific engine instance associated with this navigation.
		s.fetchAndParseCSS(cssURL.String(), currentEngine)
	}
}

// fetchAndParseCSS fetches an external stylesheet and adds it to the specified layout engine instance.
func (s *Session) fetchAndParseCSS(url string, targetEngine *layout.Engine) { // Updated signature
	go func() {
		s.logger.Debug("Fetching external stylesheet", zap.String("url", url))
		req, err := http.NewRequestWithContext(s.ctx, "GET", url, nil)
		if err != nil {
			return
		}
		s.prepareRequestHeaders(req)

		resp, err := s.client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}

		p := parser.NewParser(string(body))
		stylesheet := p.Parse()

		// Synchronize the addition of the stylesheet.
		s.mu.Lock()
		// CRITICAL: Check if the target engine from the original navigation is still the active session engine.
		if s.layoutEngine == targetEngine {
			s.layoutEngine.AddStyleSheet(stylesheet)
		}
		// else: Navigation occurred before fetch completed; discard the stylesheet.
		s.mu.Unlock()
	}()
}

// updateState updates the session's current URL and resets the DOM/JS environment.
func (s *Session) updateState(newURL *url.URL, doc *html.Node, resetContext bool) {
	// We use a standard Lock here because resetDOMBridge performs synchronized operations on the event loop.
	s.mu.Lock()
	defer s.mu.Unlock()

	s.currentURL = newURL

	// Generate the layout tree.
	if doc != nil {
		// Use persona dimensions for the viewport.
		width := float64(s.persona.Width)
		height := float64(s.persona.Height)
		s.layoutRoot = s.layoutEngine.Render(doc, width, height)
	} else {
		s.layoutRoot = nil
	}

	if resetContext {
		// Critical Step: Reset the JS environment and bind the new DOM.
		s.resetDOMBridge(doc, s.logger)
	}

	title := ""
	if s.domBridge != nil {
		// Accessing the bridge here is safe as we hold the main lock.
		title = s.domBridge.GetTitle()
	}

	s.logger.Debug("Session state updated", zap.String("url", newURL.String()), zap.String("title", title), zap.Bool("context_reset", resetContext))
}

// executePageScripts finds and executes <script> tags within the loaded HTML document.
func (s *Session) executePageScripts(doc *html.Node) {
	// Use goquery for robust traversal and attribute checking on the *html.Node structure.
	gqDoc := goquery.NewDocumentFromNode(doc)

	// Iterate over script tags in the order they appear in the document.
	gqDoc.Find("script").Each(func(i int, selection *goquery.Selection) {
		src, exists := selection.Attr("src")
		scriptType, _ := selection.Attr("type")

		// Normalize type and ignore non-JavaScript scripts (e.g., type="application/json").
		normalizedType := strings.ToLower(strings.TrimSpace(scriptType))
		if normalizedType != "" && normalizedType != "text/javascript" && normalizedType != "application/javascript" && normalizedType != "module" {
			return
		}

		if exists && src != "" {
			// External script: Fetch and execute asynchronously.
			s.fetchAndExecuteScript(src)
		} else {
			// Inline script: Execute.
			scriptContent := selection.Text()
			if scriptContent != "" {
				s.logger.Debug("Executing inline script", zap.Int("length", len(scriptContent)))
				// Execute on the event loop. We rely on the event loop processing RunOnLoop calls sequentially to maintain order.
				s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
					if _, err := vm.RunString(scriptContent); err != nil {
						// Errors during page script execution are non-fatal.
						s.logger.Warn("Error executing inline script", zap.Error(err))
					}
				})
			}
		}
	})
}

// fetchAndExecuteScript handles downloading and executing external JavaScript files asynchronously.
func (s *Session) fetchAndExecuteScript(src string) {
	resolvedURL, err := s.resolveURL(src)
	if err != nil {
		s.logger.Warn("Failed to resolve external script URL", zap.String("src", src), zap.Error(err))
		return
	}

	s.logger.Debug("Fetching external script", zap.String("url", resolvedURL.String()))

	// Fetching happens asynchronously in a goroutine.
	go func() {
		req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, resolvedURL.String(), nil)
		if err != nil {
			s.logger.Error("Failed to create request for external script", zap.Error(err))
			return
		}
		s.prepareRequestHeaders(req)
		req.Header.Set("Accept", "*/*") // Scripts can have various MIME types.

		resp, err := s.client.Do(req)
		if err != nil {
			s.logger.Warn("Failed to fetch external script", zap.String("url", resolvedURL.String()), zap.Error(err))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			s.logger.Warn("Received non-200 status for external script", zap.Int("status", resp.StatusCode), zap.String("url", resolvedURL.String()))
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.logger.Error("Failed to read external script body", zap.Error(err))
			return
		}

		scriptContent := string(body)

		// Execute on the event loop.
		s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
			// Use RunScript to provide a filename (URL) for better error reporting/debugging.
			if _, err := vm.RunScript(resolvedURL.String(), scriptContent); err != nil {
				s.logger.Warn("Error executing external script", zap.Error(err), zap.String("url", resolvedURL.String()))
			}
		})
	}()
}

// -- Implementation of dom.CorePagePrimitives --

// GetCurrentURL returns the URL of the current page state.
func (s *Session) GetCurrentURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentURL != nil {
		return s.currentURL.String()
	}
	return ""
}

// GetDOMSnapshot fetches the current HTML body, synchronized with the DOMBridge.
func (s *Session) GetDOMSnapshot(ctx context.Context) (io.Reader, error) {
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge == nil {
		return bytes.NewBufferString("<html><head></head><body></body></html>"), nil
	}

	// Get the serialized HTML from the bridge. This serialization reflects changes made by JS.
	htmlContent, err := bridge.GetOuterHTML()
	if err != nil {
		return nil, fmt.Errorf("failed to render DOM snapshot: %w", err)
	}

	return strings.NewReader(htmlContent), nil
}

// ExecuteClick simulates a click action on an element identified by XPath.
func (s *Session) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
	actionCtx, actionCancel := CombineContext(s.ctx, ctx)
	defer actionCancel()

	// 1. Find the element node using the bridge (ensures synchronization).
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	// 2. Simulate click timing.
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		if err := simulateClickTiming(actionCtx, minMs, maxMs); err != nil {
			return err
		}
	}

	// 3. Trigger JavaScript 'click' event.
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge != nil {
		// Dispatch the event on the JS event loop.
		// This allows JS event handlers (addEventListener, onclick) to execute.
		s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
			// A full implementation would dispatch mousedown, mouseup, and click.
			bridge.DispatchEventOnNode(element, "click")
		})
	}

	// 4. Determine the native HTML consequence of the click (e.g., <a> tag navigation).
	// Note: A production engine must check if JS called event.preventDefault().
	// Here we assume the native action proceeds.
	return s.handleClickConsequence(actionCtx, element)
}

// ExecuteType simulates typing text into an element identified by XPath.
func (s *Session) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	actionCtx, actionCancel := CombineContext(s.ctx, ctx)
	defer actionCancel()

	// 1. Find the element.
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	// 2. Validate element type.
	tagName := strings.ToLower(element.Data)
	if tagName != "input" && tagName != "textarea" {
		return fmt.Errorf("element '%s' is not a supported text input type", selector)
	}

	// 3. Simulate typing timing.
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled && holdMeanMs > 0 {
		if err := simulateTyping(actionCtx, text, holdMeanMs); err != nil {
			return err
		}
	}

	// 4. Update the element's value via the Bridge (synchronizes the underlying DOM).
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge == nil {
		return fmt.Errorf("DOM bridge not available during typing")
	}

	err = bridge.SetElementValue(element, text)
	if err != nil {
		return err
	}

	// 5. Trigger JavaScript events ('input' and 'change').
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		bridge.DispatchEventOnNode(element, "input")
		bridge.DispatchEventOnNode(element, "change")
	})

	return nil
}

// ExecuteSelect handles dropdown selection by value.
func (s *Session) ExecuteSelect(ctx context.Context, selector string, value string) error {
	actionCtx, actionCancel := CombineContext(s.ctx, ctx)
	defer actionCancel()

	// 1. Find the element.
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	if strings.ToLower(element.Data) != "select" {
		return fmt.Errorf("element '%s' is not a select element", selector)
	}

	// 2. Simulate interaction timing.
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		if err := simulateClickTiming(actionCtx, 100, 300); err != nil {
			return err
		}
	}

	// 3. Update the select element state via the Bridge.
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge == nil {
		return fmt.Errorf("DOM bridge not available during select")
	}

	err = bridge.SetSelectValue(element, value)
	if err != nil {
		return fmt.Errorf("failed to set select value for '%s': %w", selector, err)
	}

	// 4. Trigger JavaScript 'change' event.
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		bridge.DispatchEventOnNode(element, "change")
	})

	return nil
}

// IsVisible checks if the element is visible in the viewport.
func (s *Session) IsVisible(ctx context.Context, selector string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.layoutRoot == nil {
		return false
	}

	// GetElementGeometry handles finding the element in the layout tree and checking for display:none.
	// It returns an error if not found or not rendered.
	geo, err := s.layoutEngine.GetElementGeometry(s.layoutRoot, selector)
	if err != nil {
		return false
	}

	// A basic check: if geometry exists, it's considered visible for now.
	// A more advanced check would verify if it's within the viewport bounds.
	return geo != nil
}

// -- High-Level Interaction Methods (Implementing schemas.SessionContext) --

// Interact triggers the automated recursive interaction logic.
func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	if s.interactor == nil {
		return fmt.Errorf("interactor not initialized")
	}

	// Map schema config to dom config.
	domConfig := dom.InteractionConfig{
		MaxDepth:                config.MaxDepth,
		MaxInteractionsPerDepth: config.MaxInteractionsPerDepth,
		InteractionDelayMs:      config.InteractionDelayMs,
		PostInteractionWaitMs:   config.PostInteractionWaitMs,
	}

	return s.interactor.RecursiveInteract(ctx, domConfig)
}

// Click is the high-level click command.
func (s *Session) Click(ctx context.Context, selector string) error {
	minMs, maxMs := 0, 0
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		minMs = int(s.humanoidCfg.ClickHoldMinMs)
		maxMs = int(s.humanoidCfg.ClickHoldMaxMs)
	}
	// Selector is assumed to be XPath as required by dom.Interactor/CorePagePrimitives.
	err := s.ExecuteClick(ctx, selector, minMs, maxMs)
	if err != nil {
		return err
	}
	// Wait for stabilization after the action.
	return s.stabilize(ctx)
}

// Type is the high-level type command.
func (s *Session) Type(ctx context.Context, selector string, text string) error {
	holdMeanMs := 0.0
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		holdMeanMs = s.humanoidCfg.KeyHoldMeanMs
	}
	err := s.ExecuteType(ctx, selector, text, holdMeanMs)
	if err != nil {
		return err
	}
	// Wait for stabilization (e.g., JS validation triggered by typing).
	return s.stabilize(ctx)
}

// Submit attempts to submit the form associated with the given selector.
func (s *Session) Submit(ctx context.Context, selector string) error {
	// 1. Find the element.
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	// 2. Find the associated form.
	var form *html.Node
	if element.Type == html.ElementNode && strings.ToLower(element.Data) == "form" {
		form = element
	} else {
		form = findParentForm(element)
	}

	if form == nil {
		return fmt.Errorf("element '%s' is not associated with a form", selector)
	}

	// 3. Trigger JavaScript 'submit' event.
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge != nil {
		s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
			bridge.DispatchEventOnNode(form, "submit")
		})
	}

	// 4. Simulate the native HTML submission.
	err = s.submitForm(ctx, form)
	if err != nil {
		return err
	}

	// 5. Wait for stabilization (navigation resulting from submission).
	return s.stabilize(ctx)
}

// ScrollPage simulates scrolling the viewport by manipulating JS properties (window.scrollY/scrollX).
// Conforms to schemas.SessionContext.
func (s *Session) ScrollPage(ctx context.Context, direction string) error {
	s.logger.Debug("Simulating ScrollPage", zap.String("direction", direction))

	// Define scroll amount (arbitrary, as there is no layout engine).
	scrollAmount := 500

	script := ""
	switch strings.ToLower(direction) {
	case "down":
		script = fmt.Sprintf("window.scrollBy(0, %d);", scrollAmount)
	case "up":
		script = fmt.Sprintf("window.scrollBy(0, -%d);", scrollAmount)
	case "bottom":
		// Relies on the bridge simulating document.body.scrollHeight (if implemented).
		script = "window.scrollTo(0, document.body.scrollHeight || 10000);"
	case "top":
		script = "window.scrollTo(0, 0);"
	default:
		return fmt.Errorf("unsupported scroll direction: %s. Supported: top, bottom, up, down", direction)
	}

	// Execute the scroll script on the event loop.
	return s.executeScriptInternal(ctx, script, nil)
}

// WaitForAsync waits for the system to become idle (stabilization).
// Conforms to schemas.SessionContext (int milliseconds).
func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	// If a specific time is given, we primarily wait for that duration, allowing background activity (JS/Network) to continue.
	if milliseconds > 0 {
		waitCtx, waitCancel := CombineContext(s.ctx, ctx)
		defer waitCancel()
		return hesitate(waitCtx, time.Duration(milliseconds)*time.Millisecond)
	}

	// If milliseconds is 0 or negative, perform full stabilization.
	return s.stabilize(ctx)
}

// -- JavaScript Integration (Implementing schemas.SessionContext) --

// ExposeFunction allows Go functions to be called from the browser's JavaScript context.
// The function persists across navigations.
func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	// 1. Store the function persistently.
	s.mu.Lock()
	s.exposedFunctions[name] = function
	s.mu.Unlock()

	// 2. Apply to the current active runtime.
	// We use a synchronous channel to wait for the registration to complete on the event loop.
	errChan := make(chan error, 1)

	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		// Goja handles the type conversion automatically. We set it on the global object (window).
		err := vm.Set(name, function)
		if err != nil {
			errChan <- fmt.Errorf("failed to expose function '%s' to current JS runtime: %w", name, err)
			return
		}
		errChan <- nil
	})

	// Wait for the operation to complete.
	select {
	case err := <-errChan:
		if err != nil {
			return err
		}
		s.logger.Debug("Exposed Go function to current JS context", zap.String("name", name))
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// InjectScriptPersistently adds a script that will be executed on all new documents in the session.
func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	// 1. Store the script persistently.
	s.mu.Lock()
	s.persistentScripts = append(s.persistentScripts, script)
	s.mu.Unlock()

	s.logger.Debug("Added persistent script")

	// 2. Execute the script immediately in the current context as well.
	return s.executeScriptInternal(ctx, script, nil)
}

// ExecuteScript runs a snippet of JavaScript in the current document context.
func (s *Session) ExecuteScript(ctx context.Context, script string, res interface{}) error {
	return s.executeScriptInternal(ctx, script, res)
}

// executeScriptInternal handles the execution logic on the event loop and marshals the result.
func (s *Session) executeScriptInternal(ctx context.Context, script string, res interface{}) error {
	execCtx, execCancel := CombineContext(s.ctx, ctx)
	defer execCancel()

	// Use a channel to synchronously retrieve the result and error from the event loop thread.
	resultChan := make(chan struct {
		Value goja.Value
		Error error
	}, 1)

	// Define the execution task.
	task := func(vm *goja.Runtime) {
		// Set up interrupt handling to respect context cancellation during execution.
		// This is crucial for stopping long-running scripts.
		interrupt := make(chan struct{})
		vm.Interrupt(interrupt)

		// Monitor the context and trigger the interrupt if cancelled.
		go func() {
			select {
			case <-execCtx.Done():
				close(interrupt) // Signal Goja VM to stop.
			case <-resultChan:
				// Execution finished before cancellation.
			}
		}()

		val, err := vm.RunString(script)

		// Send the result, ensuring we don't block if the main thread already timed out.
		select {
		case resultChan <- struct {
			Value goja.Value
			Error error
		}{val, err}:
		default:
			// Result ignored, context likely expired on the caller side.
		}
	}

	// Schedule the task on the event loop.
	s.eventLoop.RunOnLoop(task)

	// Wait for the execution to complete.
	select {
	case result := <-resultChan:
		if result.Error != nil {
			// Check if the error was due to an interrupt.
			if _, ok := result.Error.(*goja.InterruptedError); ok {
				return fmt.Errorf("javascript execution interrupted (timeout or cancellation): %w", execCtx.Err())
			}
			// Provide detailed error information if it's a JS exception.
			if exception, ok := result.Error.(*goja.Exception); ok {
				return fmt.Errorf("javascript execution error: %s", exception.String())
			}
			return fmt.Errorf("javascript execution error: %w", result.Error)
		}

		// Handle result marshaling.
		if res != nil && result.Value != nil && !goja.IsUndefined(result.Value) && !goja.IsNull(result.Value) {
			// Use Goja's efficient ExportTo method to marshal the result directly into the target Go variable.
			exportErrChan := make(chan error, 1)
			s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				exportErrChan <- vm.ExportTo(result.Value, res)
			})
			select {
			case exportErr := <-exportErrChan:
				if exportErr != nil {
					return fmt.Errorf("failed to export JS result to target type: %w", exportErr)
				}
			case <-execCtx.Done():
				return execCtx.Err()
			}
		}
		return nil
	case <-execCtx.Done():
		// This case handles timeout before the task even started executing on the loop or during the wait for the result.
		return execCtx.Err()
	}
}

// -- Artifact Collection and Management --

// CollectArtifacts gathers data like HAR logs, DOM state, console logs, and storage from the session.
// Conforms to schemas.SessionContext.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	artifacts := &schemas.Artifacts{}

	// 1. Console Logs
	s.consoleLogsMu.Lock()
	artifacts.ConsoleLogs = make([]schemas.ConsoleLog, len(s.consoleLogs))
	copy(artifacts.ConsoleLogs, s.consoleLogs)
	s.consoleLogsMu.Unlock()

	// 2. HAR Log
	if s.harvester != nil {
		artifacts.HAR = s.harvester.GenerateHAR()
	}

	// 3. Final DOM Snapshot (synchronized via the bridge)
	domSnapshot, err := s.GetDOMSnapshot(ctx)
	if err == nil {
		if snapshotBytes, err := io.ReadAll(domSnapshot); err == nil {
			artifacts.DOM = string(snapshotBytes)
		} else {
			s.logger.Warn("Failed to read DOM snapshot during artifact collection.", zap.Error(err))
		}
	} else {
		s.logger.Warn("Failed to get DOM snapshot during artifact collection.", zap.Error(err))
	}

	// 4. Storage State (Cookies, LocalStorage, SessionStorage)
	if err := s.collectStorageState(ctx, artifacts); err != nil {
		s.logger.Warn("Failed to collect storage state.", zap.Error(err))
	}

	return artifacts, nil
}

// collectStorageState retrieves storage information from the network stack and the DOMBridge.
func (s *Session) collectStorageState(ctx context.Context, artifacts *schemas.Artifacts) error {
	storage := schemas.StorageState{
		Cookies:        make([]*schemas.Cookie, 0),
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
	}

	// 1. LocalStorage and SessionStorage (from the DOMBridge)
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge != nil {
		// The bridge holds the synchronized state of Web Storage.
		ls, ss := bridge.GetStorage()
		storage.LocalStorage = ls
		storage.SessionStorage = ss
	}

	// 2. Cookies (from the http.Client's Jar)
	if s.client != nil && s.client.Jar != nil {
		s.mu.RLock()
		currentURL := s.currentURL
		s.mu.RUnlock()

		if currentURL != nil {
			// Note: This retrieves cookies applicable to the current URL. A full dump requires iterating over the jar's domains.
			httpCookies := s.client.Jar.Cookies(currentURL)
			for _, hc := range httpCookies {
				// Convert http.Cookie to schemas.Cookie
				expires := float64(0)
				if !hc.Expires.IsZero() {
					expires = float64(hc.Expires.Unix())
				}
				cookie := &schemas.Cookie{
					Name:     hc.Name,
					Value:    hc.Value,
					Domain:   hc.Domain,
					Path:     hc.Path,
					Expires:  expires,
					HTTPOnly: hc.HttpOnly,
					Secure:   hc.Secure,
					Session:  hc.Expires.IsZero(),
				}
				// Map SameSite (simplified).
				switch hc.SameSite {
				case http.SameSiteStrictMode:
					cookie.SameSite = schemas.CookieSameSiteStrict
				case http.SameSiteLaxMode:
					cookie.SameSite = schemas.CookieSameSiteLax
				case http.SameSiteNoneMode:
					cookie.SameSite = schemas.CookieSameSiteNone
				}
				storage.Cookies = append(storage.Cookies, cookie)
			}
		}
	}

	artifacts.Storage = storage
	return nil
}

// AddFinding reports a finding discovered during the session.
// Conforms to schemas.SessionContext.
func (s *Session) AddFinding(finding schemas.Finding) error {
	if s.findingsChan != nil {
		// Ensure timestamp is set if missing.
		if finding.Timestamp.IsZero() {
			finding.Timestamp = time.Now()
		}

		select {
		case s.findingsChan <- finding:
			return nil
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
			// Non-blocking send; report error if the channel is full.
			errMsg := "Findings channel buffer full. Dropping finding."
			s.logger.Warn(errMsg, zap.String("vulnerability", finding.Vulnerability.Name))
			return fmt.Errorf(errMsg)
		}
	}
	return fmt.Errorf("findings channel not initialized")
}

// -- Helpers and Utilities --

// resolveURL resolves a potentially relative URL against the current session URL.
func (s *Session) resolveURL(targetURL string) (*url.URL, error) {
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Handle javascript: URIs (should be handled by ExecuteScript, not navigation).
	if strings.HasPrefix(strings.ToLower(targetURL), "javascript:") {
		return nil, fmt.Errorf("javascript: URLs are not supported for navigation")
	}

	// Handle empty or anchor-only URLs.
	if targetURL == "" || strings.HasPrefix(targetURL, "#") {
		if currentURL != nil {
			return currentURL.ResolveReference(parsedURL), nil
		}
		return nil, fmt.Errorf("cannot resolve relative URL '%s' without a base URL", targetURL)
	}

	if currentURL != nil && !parsedURL.IsAbs() {
		return currentURL.ResolveReference(parsedURL), nil
	}

	if !parsedURL.IsAbs() {
		return nil, fmt.Errorf("initial navigation target must be an absolute URL: '%s'", targetURL)
	}

	return parsedURL, nil
}

// prepareRequestHeaders sets standard browser headers based on the persona.
func (s *Session) prepareRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", s.persona.UserAgent)
	// Set default Accept header if not already present (e.g., for script fetching).
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	}
	if len(s.persona.Languages) > 0 {
		req.Header.Set("Accept-Language", strings.Join(s.persona.Languages, ","))
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	// Set Referer if applicable.
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	if currentURL != nil && req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", currentURL.String())
	}
}

// findElementNode locates a single *html.Node in the current DOM using XPath via the DOMBridge.
func (s *Session) findElementNode(selector string) (*html.Node, error) {
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge == nil {
		return nil, fmt.Errorf("DOM is empty (bridge not initialized), cannot find element '%s'", selector)
	}

	// The bridge handles the querying against the synchronized *html.Node.
	return bridge.QuerySelector(selector)
}

// handleClickConsequence determines the standard HTML action resulting from a click.
func (s *Session) handleClickConsequence(ctx context.Context, element *html.Node) error {
	tagName := strings.ToLower(element.Data)

	// Handle Anchor links (<a>)
	if tagName == "a" {
		href := htmlquery.SelectAttr(element, "href")
		if href != "" {
			// Handle javascript: URIs
			if strings.HasPrefix(strings.ToLower(href), "javascript:") {
				script := href[len("javascript:"):]
				s.logger.Debug("Executing javascript: URI navigation", zap.Int("length", len(script)))
				// Execute the script in the current context.
				return s.executeScriptInternal(ctx, script, nil)
			}

			// Standard navigation.
			return s.Navigate(ctx, href)
		}
	}

	// Handle Form Submission
	inputType := strings.ToLower(htmlquery.SelectAttr(element, "type"))
	isSubmit := (tagName == "button" && (inputType == "submit" || inputType == "")) ||
		(tagName == "input" && inputType == "submit")

	if isSubmit {
		form := findParentForm(element)
		if form != nil {
			// Use the internal submitForm logic directly.
			return s.submitForm(ctx, form)
		}
	}

	// Handle State Changes (Checkboxes/Radios)
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge != nil && tagName == "input" {
		if inputType == "checkbox" {
			if err := bridge.ToggleCheckbox(element); err != nil {
				s.logger.Warn("Failed to toggle checkbox state", zap.Error(err))
			}
			// Dispatch 'change' event (click already dispatched).
			s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				bridge.DispatchEventOnNode(element, "change")
			})
			return nil
		}
		if inputType == "radio" {
			if err := bridge.SelectRadio(element); err != nil {
				s.logger.Warn("Failed to select radio button state", zap.Error(err))
			}
			// Dispatch 'change' event.
			s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				bridge.DispatchEventOnNode(element, "change")
			})
			return nil
		}
	}

	return nil
}

// submitForm handles the serialization and submission of a form element.
func (s *Session) submitForm(ctx context.Context, form *html.Node) error {
	action := htmlquery.SelectAttr(form, "action")
	method := strings.ToUpper(htmlquery.SelectAttr(form, "method"))

	if method != http.MethodPost {
		method = http.MethodGet
	}

	// Resolve the action URL.
	targetURL, err := s.resolveURL(action)
	if err != nil || (action == "" && targetURL == nil) {
		targetURL, _ = s.resolveURL("") // Resolve against current URL if action is empty/invalid
		if targetURL == nil {
			return fmt.Errorf("failed to determine form submission URL")
		}
	}

	// Serialize form data via the DOMBridge to ensure synchronized state (e.g., values modified by JS).
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()

	if bridge == nil {
		return fmt.Errorf("DOM bridge not available during form submission")
	}

	formData, err := bridge.SerializeForm(form)
	if err != nil {
		return fmt.Errorf("failed to serialize form data: %w", err)
	}

	// Prepare and execute the request.
	var req *http.Request
	if method == http.MethodPost {
		encodedData := formData.Encode()
		req, err = http.NewRequestWithContext(ctx, method, targetURL.String(), strings.NewReader(encodedData))
		if err != nil {
			return err
		}
		// Default encoding. Handling multipart/form-data requires significant complexity.
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		// GET request: Append data to the URL's query string.
		targetURLCopy := *targetURL
		q := targetURLCopy.Query()
		for key, values := range formData {
			for _, value := range values {
				q.Add(key, value)
			}
		}
		targetURLCopy.RawQuery = q.Encode()

		req, err = http.NewRequestWithContext(ctx, method, targetURLCopy.String(), nil)
		if err != nil {
			return err
		}
	}

	s.prepareRequestHeaders(req)
	req.Header.Set("Referer", s.GetCurrentURL())

	// Execute the request (handles navigation).
	return s.executeRequest(ctx, req)
}

// findParentForm traverses up the DOM tree to find the nearest ancestor <form> element.
func findParentForm(element *html.Node) *html.Node {
	if element == nil {
		return nil
	}
	form := element.Parent
	for form != nil {
		if form.Type == html.ElementNode && strings.ToLower(form.Data) == "form" {
			return form
		}
		form = form.Parent
	}
	return nil
}

// CombineContext creates a new context that is canceled when either parentCtx or secondaryCtx is canceled.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	combinedCtx, cancel := context.WithCancel(parentCtx)

	go func() {
		select {
		case <-secondaryCtx.Done():
			cancel()
		case <-combinedCtx.Done():
		}
	}()

	return combinedCtx, cancel
}

// isDescendant checks if 'descendant' is a child, grandchild, etc., of 'ancestor'.
func isDescendant(ancestor, descendant *html.Node) bool {
	if ancestor == nil || descendant == nil || ancestor == descendant {
		return false
	}
	// Traverse up the parent chain from the descendant.
	for n := descendant.Parent; n != nil; n = n.Parent {
		if n == ancestor {
			return true
		}
	}
	return false
}

// =================================================================================================
// DOM Bridge Implementation (jsbind realization)
// =================================================================================================
// This section implements the core logic for bridging the Goja runtime with the *html.Node representation.

// listenerGroup stores event listeners separated by phase (Capturing vs Bubbling/Target).
// This structure is essential for W3C compliant event propagation.
type listenerGroup struct {
	// Listeners invoked during the Capturing phase (useCapture = true).
	Capturing []goja.Value
	// Listeners invoked during the Target or Bubbling phase (useCapture = false).
	Bubbling []goja.Value
}

// DOMBridge manages the synchronization between the *html.Node DOM representation and the Goja runtime.
type DOMBridge struct {
	// mu protects access to the bridge state.
	mu       sync.RWMutex
	document *html.Node // The root of the HTML document.
	runtime  *goja.Runtime
	logger   *zap.Logger

	// Mapping between *html.Node pointers and their corresponding Goja wrapper objects.
	nodeMap map[*html.Node]*goja.Object

	// Event listeners registered via addEventListener.
	// Structure updated to support listener phases.
	eventListeners map[*html.Node]map[string]*listenerGroup

	// Storage simulation (LocalStorage/SessionStorage)
	localStorage   map[string]string
	sessionStorage map[string]string
}

// NewDOMBridge creates a new DOMBridge instance.
func NewDOMBridge(doc *html.Node, logger *zap.Logger) *DOMBridge {
	return &DOMBridge{
		document:       doc,
		logger:         logger,
		nodeMap:        make(map[*html.Node]*goja.Object),
		eventListeners: make(map[*html.Node]map[string]*listenerGroup),
		localStorage:   make(map[string]string),
		sessionStorage: make(map[string]string),
	}
}

// BindToRuntime injects the DOM APIs into the Goja runtime.
// This function must be executed on the event loop thread.
func (b *DOMBridge) BindToRuntime(vm *goja.Runtime) {
	// Lock is required as we initialize the runtime and mappings.
	b.mu.Lock()
	defer b.mu.Unlock()

	b.runtime = vm

	// 1. Create the 'document' object.
	documentObj := b.wrapNode(b.document)
	_ = vm.Set("document", documentObj)

	// 2. Enhance the 'document' object with specific methods.
	_ = documentObj.Set("getElementById", b.jsGetElementById)
	// Note: We use XPath internally (htmlquery). A production engine requires a CSS selector engine.
	_ = documentObj.Set("querySelector", b.jsQuerySelector)
	_ = documentObj.Set("querySelectorAll", b.jsQuerySelectorAll)
	_ = documentObj.Set("createElement", b.jsCreateElement)
	_ = documentObj.Set("write", b.jsDocumentWrite)

	// 3. Expose essential elements (body, head).
	body := htmlquery.FindOne(b.document, "//body")
	if body != nil {
		_ = documentObj.Set("body", b.wrapNode(body))
	}
	head := htmlquery.FindOne(b.document, "//head")
	if head != nil {
		_ = documentObj.Set("head", b.wrapNode(head))
	}

	// 4. Bind Storage APIs.
	b.bindStorageAPIs(vm)

	// 5. Configure window properties and methods.
	window := vm.GlobalObject()
	// Basic simulation of dimensions.
	_ = window.Set("innerWidth", 1920)
	_ = window.Set("innerHeight", 1080)
	_ = window.Set("scrollX", 0)
	_ = window.Set("scrollY", 0)
	b.bindScrollAPIs(window)
}

// wrapNode creates or retrieves the Goja object wrapper for a given *html.Node.
// Must be called within the bridge lock (b.mu) and on the event loop thread.
func (b *DOMBridge) wrapNode(node *html.Node) *goja.Object {
	if node == nil {
		return nil
	}

	if obj, exists := b.nodeMap[node]; exists {
		return obj
	}

	// Create a new Goja object (simulating HTMLElement).
	obj := b.runtime.NewObject()

	// Basic properties
	_ = obj.Set("nodeType", node.Type)
	_ = obj.Set("tagName", strings.ToUpper(node.Data))
	_ = obj.Set("nodeName", strings.ToUpper(node.Data))

	// Methods for attributes
	b.bindAttributeMethods(obj, node)

	// Methods for traversal (parentNode, childNodes).
	_ = obj.Set("parentNode", func(call goja.FunctionCall) goja.Value {
		return b.runtime.ToValue(b.wrapNode(node.Parent))
	})

	b.defineChildNodesProperty(obj, node)

	// Methods for manipulation (appendChild).
	_ = obj.Set("appendChild", func(call goja.FunctionCall) goja.Value {
		childObj := call.Argument(0).ToObject(b.runtime)
		childNode := b.unwrapNode(childObj)
		if childNode != nil {
			// Standard DOM behavior: Remove from previous parent first.
			if childNode.Parent != nil {
				childNode.Parent.RemoveChild(childNode)
			}
			node.AppendChild(childNode)
		}
		return call.Argument(0)
	})

	// Define 'innerHTML' and 'outerHTML' as getter/setter properties.
	b.defineHTMLProperties(obj, node)

	// Define 'value' property for input elements.
	b.defineValueProperty(obj, node)

	// Event handling (addEventListener)
	_ = obj.Set("addEventListener", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}

		eventType := call.Argument(0).String()
		listenerVal := call.Argument(1)
		optionsArg := call.Argument(2) // The third argument: boolean or options object.

		if _, ok := goja.AssertFunction(listenerVal); !ok {
			// Per W3C spec, if the listener is not a valid callback (e.g., null/undefined), we return silently.
			return goja.Undefined()
		}

		// Determine the 'useCapture' flag according to W3C specification (DOM Living Standard).
		useCapture := false
		if !goja.IsUndefined(optionsArg) {
			// Robustly handle both `addEventListener(t, l, true)` and `addEventListener(t, l, { capture: true })`.

			// We check if the argument is an object. A pragmatic way in Goja is to check if the exported value is a map.
			isObject := false
			if exportVal := optionsArg.Export(); exportVal != nil {
				if _, ok := exportVal.(map[string]interface{}); ok {
					isObject = true
				}
			}

			if isObject {
				// Case: Options object { capture: boolean }
				if objArg := optionsArg.ToObject(b.runtime); objArg != nil {
					if captureVal := objArg.Get("capture"); captureVal != nil {
						useCapture = captureVal.ToBoolean()
					}
				}
			} else {
				// Case: Boolean argument (useCapture). All other types are coerced to boolean.
				useCapture = optionsArg.ToBoolean()
			}
		}

		// Lock is required as we modify the shared eventListeners map.
		b.addEventListener(node, eventType, listenerVal, useCapture)
		return goja.Undefined()
	})

	// Store the mapping.
	b.nodeMap[node] = obj
	return obj
}

// unwrapNode finds the *html.Node corresponding to a Goja object wrapper.
// Must be called within the bridge lock (b.mu) and on the event loop thread.
func (b *DOMBridge) unwrapNode(obj *goja.Object) *html.Node {
	// O(N) search. Optimization needed for production scale (e.g., using Goja's private properties).
	for node, wrapper := range b.nodeMap {
		if wrapper == obj {
			return node
		}
	}
	b.logger.Warn("Failed to unwrap Goja object to *html.Node")
	return nil
}

// defineGetter is a utility to define a getter property on an object using Object.defineProperty.
func (b *DOMBridge) defineGetter(obj *goja.Object, propName string, getter goja.Callable) {
	globalObj := b.runtime.GlobalObject()
	objectConstructorVal := globalObj.Get("Object")
	objectConstructor := objectConstructorVal.ToObject(b.runtime)
	definePropertyVal := objectConstructor.Get("defineProperty")

	defineProperty, ok := goja.AssertFunction(definePropertyVal)
	if !ok {
		b.logger.Error("FATAL: Could not find Object.defineProperty in JS runtime.")
		return
	}

	descriptor := b.runtime.NewObject()
	_ = descriptor.Set("get", getter)
	_ = descriptor.Set("enumerable", true)
	_ = descriptor.Set("configurable", true)

	_, err := defineProperty(objectConstructorVal, obj, b.runtime.ToValue(propName), descriptor)
	if err != nil {
		b.logger.Error("Failed to define getter property", zap.String("property", propName), zap.Error(err))
	}
}

// determineContextNode resolves the *html.Node context from the 'this' value of a JS call.
// Defaults to b.document if the context cannot be determined.
// Must be called within the bridge lock (b.mu) and on the event loop thread.
func (b *DOMBridge) determineContextNode(this goja.Value) *html.Node {
	if goja.IsUndefined(this) || goja.IsNull(this) {
		return b.document
	}

	thisObj := this.ToObject(b.runtime)
	if thisObj == nil || thisObj == b.runtime.GlobalObject() {
		return b.document
	}

	// Attempt to unwrap the object (works for Element and Document objects).
	node := b.unwrapNode(thisObj)
	if node != nil {
		return node
	}

	// Fallback if unwrap fails.
	return b.document
}

// -- Detailed DOMBridge API Bindings --

func (b *DOMBridge) bindAttributeMethods(obj *goja.Object, node *html.Node) {
	_ = obj.Set("getAttribute", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		val := htmlquery.SelectAttr(node, name)
		if val == "" {
			// getAttribute returns null if the attribute does not exist.
			return goja.Null()
		}
		return b.runtime.ToValue(val)
	})

	_ = obj.Set("setAttribute", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		// Update the underlying *html.Node. Safe as we are synchronized by the lock and event loop.
		setAttr(node, name, value)
		return goja.Undefined()
	})

	_ = obj.Set("removeAttribute", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		removeAttr(node, name)
		return goja.Undefined()
	})
}

func (b *DOMBridge) defineChildNodesProperty(obj *goja.Object, node *html.Node) {
	// Define 'childNodes' (live NodeList simulation using a getter).
	getter := func(this goja.Value, args ...goja.Value) (goja.Value, error) {
		var children []*goja.Object
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			wrapped := b.wrapNode(c)
			if wrapped != nil {
				children = append(children, wrapped)
			}
		}
		return b.runtime.ToValue(children), nil
	}
	b.defineGetter(obj, "childNodes", getter)
}

// defineHTMLProperties sets up the getters and setters for innerHTML.
func (b *DOMBridge) defineHTMLProperties(obj *goja.Object, node *html.Node) {
	globalObj := b.runtime.GlobalObject()
	objectConstructorVal := globalObj.Get("Object")
	objectConstructor := objectConstructorVal.ToObject(b.runtime)
	definePropertyVal := objectConstructor.Get("defineProperty")

	defineProperty, ok := goja.AssertFunction(definePropertyVal)
	if !ok {
		b.logger.Error("FATAL: Could not find Object.defineProperty in JS runtime.")
		return
	}

	descriptor := b.runtime.NewObject()
	_ = descriptor.Set("get", func(this goja.Value, args ...goja.Value) (goja.Value, error) {
		var buf bytes.Buffer
		// Render children to serialize inner content.
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			_ = html.Render(&buf, c)
		}
		return b.runtime.ToValue(buf.String()), nil
	})
	_ = descriptor.Set("set", func(call goja.FunctionCall) goja.Value {
		htmlContent := call.Argument(0).String()
		// Parse the new HTML fragment.
		nodes, err := html.ParseFragment(strings.NewReader(htmlContent), node)
		if err != nil {
			b.logger.Warn("Failed to parse HTML for innerHTML assignment", zap.Error(err))
			// Real browser might throw a DOMException.
			return goja.Undefined()
		}

		// Remove existing children.
		for c := node.FirstChild; c != nil; {
			next := c.NextSibling
			node.RemoveChild(c)
			c = next
		}

		// Append new children.
		for _, newNode := range nodes {
			node.AppendChild(newNode)
		}
		return call.Argument(0)
	})
	_ = descriptor.Set("enumerable", true)
	_ = descriptor.Set("configurable", true)

	_, err := defineProperty(objectConstructorVal, obj, b.runtime.ToValue("innerHTML"), descriptor)
	if err != nil {
		b.logger.Error("Failed to define innerHTML property", zap.Error(err))
	}
}

// defineValueProperty sets up the getter/setter for the 'value' property.
func (b *DOMBridge) defineValueProperty(obj *goja.Object, node *html.Node) {
	globalObj := b.runtime.GlobalObject()
	objectConstructorVal := globalObj.Get("Object")
	objectConstructor := objectConstructorVal.ToObject(b.runtime)
	definePropertyVal := objectConstructor.Get("defineProperty")

	defineProperty, ok := goja.AssertFunction(definePropertyVal)
	if !ok {
		b.logger.Error("FATAL: Could not find Object.defineProperty in JS runtime.")
		return
	}

	descriptor := b.runtime.NewObject()
	_ = descriptor.Set("get", func(this goja.Value, args ...goja.Value) (goja.Value, error) {
		tagName := strings.ToLower(node.Data)
		if tagName == "textarea" {
			return b.runtime.ToValue(htmlquery.InnerText(node)), nil
		}
		return b.runtime.ToValue(htmlquery.SelectAttr(node, "value")), nil
	})
	_ = descriptor.Set("set", func(call goja.FunctionCall) goja.Value {
		value := call.Argument(0).String()
		tagName := strings.ToLower(node.Data)
		if tagName == "textarea" {
			// Clear children and add text node.
			for c := node.FirstChild; c != nil; {
				next := c.NextSibling
				node.RemoveChild(c)
				c = next
			}
			node.AppendChild(&html.Node{Type: html.TextNode, Data: value})
		} else {
			setAttr(node, "value", value)
		}
		return call.Argument(0)
	})
	_ = descriptor.Set("enumerable", true)
	_ = descriptor.Set("configurable", true)

	_, err := defineProperty(objectConstructorVal, obj, b.runtime.ToValue("value"), descriptor)
	if err != nil {
		b.logger.Error("Failed to define value property", zap.Error(err))
	}
}

// -- JS API Implementations (Called from Goja) --

// jsGetElementById implements document.getElementById().
func (b *DOMBridge) jsGetElementById(call goja.FunctionCall) goja.Value {
	id := call.Argument(0).String()

	// Lock is required as we access the document and wrap the node.
	b.mu.Lock()
	defer b.mu.Unlock()

	// Use XPath to find the element. (Requires careful escaping if ID contains quotes).
	xpath := fmt.Sprintf("//*[@id='%s']", id)
	node := htmlquery.FindOne(b.document, xpath)
	if node == nil {
		return goja.Null()
	}

	return b.runtime.ToValue(b.wrapNode(node))
}

// jsQuerySelector implements Element.querySelector() and Document.querySelector(). (Assumes XPath input).
func (b *DOMBridge) jsQuerySelector(call goja.FunctionCall) goja.Value {
	selector := call.Argument(0).String()

	// Lock is required for thread safety during DOM traversal, context determination (unwrapNode), and node wrapping.
	b.mu.Lock()
	defer b.mu.Unlock()

	// Determine the context node based on the 'this' value of the call.
	contextNode := b.determineContextNode(call.This)

	// W3C Compliance: We must find the first element in tree order that matches the selector AND is a descendant of the context node.
	// Because the underlying XPath engine might return results outside the context (e.g., for absolute paths),
	// we must use QueryAll and iterate to find the first valid descendant.
	nodes, err := htmlquery.QueryAll(contextNode, selector)
	if err != nil {
		b.logger.Warn("Error evaluating XPath selector in querySelector", zap.String("selector", selector), zap.Error(err))
		return goja.Null()
	}

	// Determine if we need to enforce the descendant check.
	// If the context is the document root, the check is implicit.
	isRootContext := (contextNode == b.document)

	for _, node := range nodes {
		if isRootContext || isDescendant(contextNode, node) {
			// Found the first valid descendant.
			return b.runtime.ToValue(b.wrapNode(node))
		}
	}

	return goja.Null()
}

// jsQuerySelectorAll implements Element.querySelectorAll() and Document.querySelectorAll().
func (b *DOMBridge) jsQuerySelectorAll(call goja.FunctionCall) goja.Value {
	selector := call.Argument(0).String()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Determine the context node.
	contextNode := b.determineContextNode(call.This)

	nodes, err := htmlquery.QueryAll(contextNode, selector)
	if err != nil {
		b.logger.Warn("Error evaluating XPath selector in querySelectorAll", zap.String("selector", selector), zap.Error(err))
		// Return an empty NodeList (represented as an array) on error.
		return b.runtime.ToValue([]interface{}{})
	}

	// Wrap the results into an array of Goja objects, filtering for W3C compliance.
	var results []*goja.Object
	isRootContext := (contextNode == b.document)

	for _, node := range nodes {
		// W3C Compliance Check: Only include descendants of the context node.
		if isRootContext || isDescendant(contextNode, node) {
			results = append(results, b.wrapNode(node))
		}
	}

	return b.runtime.ToValue(results)
}

// jsCreateElement implements document.createElement().
func (b *DOMBridge) jsCreateElement(call goja.FunctionCall) goja.Value {
	tagName := call.Argument(0).String()

	b.mu.Lock()
	defer b.mu.Unlock()

	node := &html.Node{
		Type: html.ElementNode,
		Data: strings.ToLower(tagName),
	}

	return b.runtime.ToValue(b.wrapNode(node))
}

// jsDocumentWrite implements document.write() (Basic implementation).
func (b *DOMBridge) jsDocumentWrite(call goja.FunctionCall) goja.Value {
	content := call.Argument(0).String()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Append to the body (simplified behavior).
	body := htmlquery.FindOne(b.document, "//body")
	if body == nil {
		return goja.Undefined()
	}

	nodes, err := html.ParseFragment(strings.NewReader(content), body)
	if err != nil {
		return goja.Undefined()
	}

	for _, node := range nodes {
		body.AppendChild(node)
	}

	return goja.Undefined()
}

// -- Event Handling --

// addEventListener registers a JavaScript function as an event listener, respecting the useCapture flag.
// Must be called within the bridge lock (b.mu) and on the event loop thread.
func (b *DOMBridge) addEventListener(node *html.Node, eventType string, listenerVal goja.Value, useCapture bool) {
	// 1. Ensure the map structure is initialized for the node.
	if b.eventListeners == nil {
		// Defensive initialization.
		b.eventListeners = make(map[*html.Node]map[string]*listenerGroup)
	}

	nodeListeners, exists := b.eventListeners[node]
	if !exists {
		nodeListeners = make(map[string]*listenerGroup)
		b.eventListeners[node] = nodeListeners
	}

	// 2. Ensure the listener group for the event type exists.
	group, exists := nodeListeners[eventType]
	if !exists {
		group = &listenerGroup{
			Capturing: make([]goja.Value, 0),
			Bubbling:  make([]goja.Value, 0),
		}
		nodeListeners[eventType] = group
	}

	// 3. W3C Spec Requirement (DOM Living Standard): Prevent duplicate listeners.
	// A listener is uniquely identified by the tuple (target, type, callback, capture).
	var targetList *[]goja.Value
	if useCapture {
		targetList = &group.Capturing
	} else {
		targetList = &group.Bubbling
	}

	for _, existingListener := range *targetList {
		// In Go, functions are not directly comparable. We use Goja's SameAs method
		// to check if two goja.Value objects reference the same JS function.
		if existingListener.SameAs(listenerVal) {
			// Listener already exists in this phase, discard the addition.
			return
		}
	}

	// 4. Add the new listener to the appropriate phase list.
	*targetList = append(*targetList, listenerVal)
}

// DispatchEventOnNode triggers an event on a specific node, implementing the W3C event propagation model.
// This includes Capturing, Target, and Bubbling phases, with full support for propagation control
// (stopPropagation, stopImmediatePropagation).
// This function must be executed on the JS thread (called via eventLoop.RunOnLoop from the Go side).
func (b *DOMBridge) DispatchEventOnNode(targetNode *html.Node, eventType string) {
	// Implementation adheres to the DOM Living Standard: https://dom.spec.whatwg.org/#dispatching-events

	// W3C Standard Event Phases (Event.eventPhase constants)
	const (
		EventPhaseNone      = 0
		EventPhaseCapturing = 1
		EventPhaseAtTarget  = 2
		EventPhaseBubbling  = 3
	)

	// --- 1. Synchronization and Initialization ---
	// The entire event dispatch process must be atomic regarding the DOM state and JS execution.
	// We hold the lock for the duration. This ensures thread safety while accessing the DOM structure
	// (parent pointers), the shared eventListeners map, and the Goja runtime (wrapNode, executing callbacks).
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.runtime == nil || targetNode == nil {
		return
	}

	// Determine event characteristics (simplified W3C heuristics).
	bubbles := true
	cancelable := true

	// Common exceptions: 'focus', 'blur', 'load' (on elements) generally do not bubble.
	switch eventType {
	case "focus", "blur", "load", "unload", "scroll", "mouseenter", "mouseleave":
		bubbles = false
	case "DOMContentLoaded":
		// DOMContentLoaded bubbles but is often not cancelable.
		cancelable = false
	}

	// State variables tracked during propagation. These are bound to the JS Event object via closures and getters.
	var (
		currentPhase             uint16     = EventPhaseNone
		currentTarget            *html.Node = nil // Node currently processing the event.
		stopPropagation          bool       = false
		stopImmediatePropagation bool       = false
		defaultPrevented         bool       = false
	)

	// --- 2. Propagation Path Calculation ---
	// Determine the path of ancestors from the target's parent up to the root.
	// This path is static once dispatch begins.
	var ancestors []*html.Node
	for n := targetNode.Parent; n != nil; n = n.Parent {
		ancestors = append(ancestors, n)
	}
	ancestorCount := len(ancestors)
	// The 'ancestors' slice is ordered [Parent, Grandparent, ..., Root].

	// --- 3. Event Object Creation (JavaScript) ---
	eventObj := b.runtime.NewObject()
	_ = eventObj.Set("type", eventType)
	_ = eventObj.Set("bubbles", bubbles)
	_ = eventObj.Set("cancelable", cancelable)

	// The 'target' property is constant throughout the event lifecycle.
	targetObj := b.wrapNode(targetNode)
	if targetObj == nil {
		// Should be exceedingly rare if the initial node exists, but defensive coding is required.
		b.logger.Error("Failed to wrap target node during event dispatch.", zap.String("type", eventType))
		return
	}
	_ = eventObj.Set("target", targetObj)

	// Define propagation control methods (Closures capturing the Go state).
	_ = eventObj.Set("stopPropagation", func(call goja.FunctionCall) goja.Value {
		stopPropagation = true
		return goja.Undefined()
	})
	_ = eventObj.Set("stopImmediatePropagation", func(call goja.FunctionCall) goja.Value {
		stopPropagation = true
		stopImmediatePropagation = true
		return goja.Undefined()
	})
	_ = eventObj.Set("preventDefault", func(call goja.FunctionCall) goja.Value {
		if cancelable {
			defaultPrevented = true
		}
		return goja.Undefined()
	})

	// Define dynamic properties using Getters. This is essential for W3C compliance as these values change during propagation.
	b.defineGetter(eventObj, "eventPhase", func(this goja.Value, args ...goja.Value) (goja.Value, error) {
		return b.runtime.ToValue(currentPhase), nil
	})

	b.defineGetter(eventObj, "currentTarget", func(this goja.Value, args ...goja.Value) (goja.Value, error) {
		if currentTarget == nil {
			// Per spec, currentTarget is null if the event is not being dispatched.
			return goja.Null(), nil
		}
		// wrapNode ensures we return the correct JS object representation. Safe as b.mu is held.
		return b.runtime.ToValue(b.wrapNode(currentTarget)), nil
	})

	b.defineGetter(eventObj, "defaultPrevented", func(this goja.Value, args ...goja.Value) (goja.Value, error) {
		return b.runtime.ToValue(defaultPrevented), nil
	})

	// --- 4. Listener Invocation Helper (DRY Principle) ---

	// invokeListeners executes listeners on the given node, handling propagation control and execution safety.
	// Returns true if propagation should continue, false if stopImmediatePropagation was called.
	invokeListeners := func(node *html.Node) bool {
		currentTarget = node // Update the currentTarget (affects the JS getter).

		group, exists := b.eventListeners[node][eventType]
		if !exists || group == nil {
			return true
		}

		var listeners []goja.Value
		if currentPhase == EventPhaseCapturing {
			listeners = group.Capturing
		} else {
			listeners = group.Bubbling
		}

		if len(listeners) == 0 {
			return true
		}

		// W3C Spec Requirement: The list of event listeners must be determined before dispatch begins on this target.
		// We iterate over a snapshot (clone) of the listeners.
		listenersCopy := make([]goja.Value, len(listeners))
		copy(listenersCopy, listeners)

		// Get the JS object representation of the currentTarget (used as 'this' context).
		thisObj := b.wrapNode(node)
		if thisObj == nil {
			return true // Defensive check.
		}

		for _, listenerVal := range listenersCopy {
			// W3C Spec Requirement (DOM Living Standard 2.7.3): Check if the listener was removed.
			// If removeEventListener was called by a previous listener in this phase, we must not execute it.
			isAttached := false
			// We must check the live map, not the copy, as it might have been modified.
			if currentGroup, ok := b.eventListeners[node][eventType]; ok {
				var currentListeners []goja.Value
				if currentPhase == EventPhaseCapturing {
					currentListeners = currentGroup.Capturing
				} else {
					currentListeners = currentGroup.Bubbling
				}
				for _, attachedListener := range currentListeners {
					if attachedListener.SameAs(listenerVal) {
						isAttached = true
						break
					}
				}
			}

			if !isAttached {
				continue
			}

			// Execute the listener robustly.
			func(lVal goja.Value) {
				// Assert the value to a callable function before execution.
				listener, ok := goja.AssertFunction(lVal)
				if !ok {
					// This should be exceedingly rare since we assert on add, but is a good safeguard.
					b.logger.Error("Stored event listener is not a function", zap.String("type", eventType))
					return
				}
				// Recover from potential panics within the Goja execution context (e.g., stack overflow or VM errors).
				defer func() {
					if r := recover(); r != nil {
						b.logger.Error("Panic recovered during JS event listener execution",
							zap.String("type", eventType),
							zap.Uint16("phase", currentPhase),
							zap.Any("panic_detail", r))
					}
				}()

				// Call the listener: function.call(this=currentTarget, eventObj)
				_, err := listener(thisObj, eventObj)
				if err != nil {
					// Log JavaScript exceptions but continue execution (standard browser behavior).
					b.logger.Warn("Error executing JS event listener (JS Exception)",
						zap.String("type", eventType),
						zap.Error(err))
					// In a production browser, this would trigger window.onerror.
				}
			}(listenerVal)

			// Check for immediate propagation stop immediately after execution.
			if stopImmediatePropagation {
				return false
			}
		}
		return true
	}

	b.logger.Debug("Dispatching event", zap.String("type", eventType), zap.String("target_tag", targetNode.Data), zap.Bool("bubbles", bubbles))

	// --- 5. Event Propagation Phases ---

	// 5.1 Capturing Phase (Root down to Target's parent)
	currentPhase = EventPhaseCapturing
	// Iterate backwards through the ancestors (Root -> Parent).
	for i := ancestorCount - 1; i >= 0; i-- {
		node := ancestors[i]
		if !invokeListeners(node) {
			goto DispatchEnd // stopImmediatePropagation called.
		}
		if stopPropagation {
			goto DispatchEnd // stopPropagation called.
		}
	}

	// 5.2 Target Phase (On the target node itself)
	// Only proceed if propagation wasn't stopped during Capturing.
	if !stopPropagation {
		currentPhase = EventPhaseAtTarget
		if !invokeListeners(targetNode) {
			goto DispatchEnd // stopImmediatePropagation called.
		}
	}

	// 5.3 Bubbling Phase (Target's parent up to Root)
	// Only proceed if the event bubbles and propagation wasn't stopped during Capturing or Target.
	if bubbles && !stopPropagation {
		currentPhase = EventPhaseBubbling
		// Iterate forwards through the ancestors (Parent -> Root).
		for i := 0; i < ancestorCount; i++ {
			node := ancestors[i]
			if !invokeListeners(node) {
				goto DispatchEnd // stopImmediatePropagation called.
			}
			if stopPropagation {
				break // stopPropagation called. Stop bubbling up further.
			}
		}
	}

DispatchEnd:
	// Reset state after dispatch is complete, per W3C specification.
	currentPhase = EventPhaseNone
	currentTarget = nil
}

// -- Bridge Utilities (Called from Go side) --

// QuerySelector finds an element using XPath against the synchronized DOM.
func (b *DOMBridge) QuerySelector(selector string) (*html.Node, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	node := htmlquery.FindOne(b.document, selector)
	if node == nil {
		return nil, fmt.Errorf("element not found matching selector '%s'", selector)
	}
	return node, nil
}

// GetOuterHTML serializes the current DOM state back to HTML.
func (b *DOMBridge) GetOuterHTML() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var buf bytes.Buffer
	if err := html.Render(&buf, b.document); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GetTitle retrieves the document title.
func (b *DOMBridge) GetTitle() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if titleNode := htmlquery.FindOne(b.document, "//title"); titleNode != nil {
		return strings.TrimSpace(htmlquery.InnerText(titleNode))
	}
	return ""
}

// GetStorage returns a copy of the LocalStorage and SessionStorage maps.
func (b *DOMBridge) GetStorage() (map[string]string, map[string]string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	lsCopy := make(map[string]string, len(b.localStorage))
	for k, v := range b.localStorage {
		lsCopy[k] = v
	}
	ssCopy := make(map[string]string, len(b.sessionStorage))
	for k, v := range b.sessionStorage {
		ssCopy[k] = v
	}
	return lsCopy, ssCopy
}

// --- Detailed DOMBridge Interaction Helpers ---

// SetElementValue updates the value of an input or textarea element.
func (b *DOMBridge) SetElementValue(element *html.Node, text string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	tagName := strings.ToLower(element.Data)
	if tagName == "textarea" {
		// Clear and replace child text node.
		for c := element.FirstChild; c != nil; {
			next := c.NextSibling
			element.RemoveChild(c)
			c = next
		}
		element.AppendChild(&html.Node{
			Type: html.TextNode,
			Data: text,
		})
	} else {
		// Set 'value' attribute.
		setAttr(element, "value", text)
	}
	return nil
}

// SetSelectValue updates the selected option(s) of a select element.
func (b *DOMBridge) SetSelectValue(element *html.Node, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	found := false
	options, err := htmlquery.QueryAll(element, ".//option")
	if err != nil {
		return err
	}

	// Assumes single select (multi-select logic is more complex).
	for _, opt := range options {
		optValue := htmlquery.SelectAttr(opt, "value")
		if optValue == "" {
			optValue = strings.TrimSpace(htmlquery.InnerText(opt))
		}

		isSelected := optValue == value
		if isSelected {
			found = true
			setAttr(opt, "selected", "selected")
		} else {
			removeAttr(opt, "selected")
		}
	}

	if !found {
		return fmt.Errorf("option with value '%s' not found", value)
	}
	return nil
}

// ToggleCheckbox toggles the 'checked' attribute.
func (b *DOMBridge) ToggleCheckbox(element *html.Node) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if htmlquery.SelectAttr(element, "checked") != "" {
		removeAttr(element, "checked")
	} else {
		setAttr(element, "checked", "checked")
	}
	return nil
}

// SelectRadio ensures the radio button is checked and others in the group are unchecked.
func (b *DOMBridge) SelectRadio(element *html.Node) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	name := htmlquery.SelectAttr(element, "name")
	if name == "" {
		setAttr(element, "checked", "checked")
		return nil
	}

	// Find the root context (form or document root).
	root := findParentForm(element)
	if root == nil {
		root = b.document
	}

	// Basic XPath escaping might be needed if name contains quotes.
	xpath := fmt.Sprintf(".//input[@type='radio' and @name='%s']", name)
	radios, err := htmlquery.QueryAll(root, xpath)
	if err != nil {
		return err
	}

	for _, radio := range radios {
		if radio == element {
			setAttr(radio, "checked", "checked")
		} else {
			removeAttr(radio, "checked")
		}
	}
	return nil
}

// SerializeForm collects data from form elements.
func (b *DOMBridge) SerializeForm(form *html.Node) (url.Values, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	formData := url.Values{}
	inputs, err := htmlquery.QueryAll(form, ".//input | .//textarea | .//select")
	if err != nil {
		return nil, err
	}

	for _, input := range inputs {
		name := htmlquery.SelectAttr(input, "name")
		if name == "" || htmlquery.SelectAttr(input, "disabled") != "" {
			continue
		}

		tagName := strings.ToLower(input.Data)
		inputType := strings.ToLower(htmlquery.SelectAttr(input, "type"))

		switch tagName {
		case "input":
			switch inputType {
			case "checkbox", "radio":
				if htmlquery.SelectAttr(input, "checked") != "" {
					value := htmlquery.SelectAttr(input, "value")
					if value == "" {
						value = "on"
					}
					formData.Add(name, value)
				}
			case "submit", "button", "image", "reset", "file":
				// Ignore.
			default:
				value := htmlquery.SelectAttr(input, "value")
				formData.Add(name, value)
			}
		case "textarea":
			value := htmlquery.InnerText(input)
			formData.Add(name, value)
		case "select":
			selectedOptions, _ := htmlquery.QueryAll(input, ".//option[@selected]")
			if len(selectedOptions) == 0 {
				// Default behavior: first option if none selected (and not multiple).
				isMultiple := htmlquery.SelectAttr(input, "multiple") != ""
				if !isMultiple {
					if firstOption := htmlquery.FindOne(input, ".//option"); firstOption != nil {
						value := htmlquery.SelectAttr(firstOption, "value")
						if value == "" {
							value = htmlquery.InnerText(firstOption)
						}
						formData.Add(name, value)
					}
				}
			} else {
				for _, opt := range selectedOptions {
					value := htmlquery.SelectAttr(opt, "value")
					if value == "" {
						value = htmlquery.InnerText(opt)
					}
					formData.Add(name, value)
				}
			}
		}
	}
	return formData, nil
}

// UpdateLocation updates the window.location object.
// Must be executed on the event loop thread.
func (b *DOMBridge) UpdateLocation(urlString string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.runtime == nil {
		return
	}

	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return
	}

	location := b.runtime.Get("location").ToObject(b.runtime)
	if location == nil {
		location = b.runtime.NewObject()
		_ = b.runtime.Set("location", location)
	}

	// Define properties (simplified implementation without navigation setters).
	_ = location.Set("href", parsedURL.String())
	_ = location.Set("protocol", parsedURL.Scheme+":")
	_ = location.Set("host", parsedURL.Host)
	_ = location.Set("hostname", parsedURL.Hostname())
	_ = location.Set("port", parsedURL.Port())
	_ = location.Set("pathname", parsedURL.Path)
	search := ""
	if parsedURL.RawQuery != "" {
		search = "?" + parsedURL.RawQuery
	}
	hash := ""
	if parsedURL.Fragment != "" {
		hash = "#" + parsedURL.Fragment
	}
	_ = location.Set("search", search)
	_ = location.Set("hash", hash)
	_ = location.Set("origin", parsedURL.Scheme+"://"+parsedURL.Host)
}

// bindStorageAPIs implements window.localStorage and window.sessionStorage.
// Must be executed on the event loop thread.
func (b *DOMBridge) bindStorageAPIs(vm *goja.Runtime) {
	// Implements the Storage interface.

	createStorageObject := func(storageMap map[string]string) *goja.Object {
		obj := vm.NewObject()

		_ = obj.Set("getItem", func(call goja.FunctionCall) goja.Value {
			key := call.Argument(0).String()
			// Access is synchronized by the event loop thread and the bridge lock.
			if val, exists := storageMap[key]; exists {
				return vm.ToValue(val)
			}
			return goja.Null()
		})

		_ = obj.Set("setItem", func(call goja.FunctionCall) goja.Value {
			key := call.Argument(0).String()
			value := call.Argument(1).String()
			storageMap[key] = value
			return goja.Undefined()
		})

		_ = obj.Set("removeItem", func(call goja.FunctionCall) goja.Value {
			key := call.Argument(0).String()
			delete(storageMap, key)
			return goja.Undefined()
		})

		_ = obj.Set("clear", func(call goja.FunctionCall) goja.Value {
			for k := range storageMap {
				delete(storageMap, k)
			}
			return goja.Undefined()
		})

		// Define 'length' as a getter property.
		b.defineGetter(obj, "length", func(this goja.Value, args ...goja.Value) (goja.Value, error) {
			return vm.ToValue(len(storageMap)), nil
		})

		return obj
	}

	_ = vm.Set("localStorage", createStorageObject(b.localStorage))
	_ = vm.Set("sessionStorage", createStorageObject(b.sessionStorage))
}

// bindScrollAPIs implements basic window scrolling functions.
// Must be executed on the event loop thread.
func (b *DOMBridge) bindScrollAPIs(window *goja.Object) {
	// Helper to update scrollX/scrollY properties and dispatch the 'scroll' event.
	updateScroll := func(x, y int64) {
		// Capture current values before update to determine if a change actually occurred.
		currentX := window.Get("scrollX").ToInteger()
		currentY := window.Get("scrollY").ToInteger()

		// Apply basic clamping (coordinates cannot be negative).
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}

		// Optimization: Only update properties and dispatch event if the position actually changed.
		if currentX == x && currentY == y {
			return
		}

		// Update the JS properties (Safe as we are on the single JS event loop thread).
		_ = window.Set("scrollX", x)
		_ = window.Set("scrollY", y)

		// Dispatch 'scroll' event.
		// W3C standard (UI Events): 'scroll' events for the viewport (window scrolling) are dispatched on the Document.
		if b.document != nil {
			// DispatchEventOnNode handles the necessary internal synchronization (b.mu).
			// It also correctly identifies that 'scroll' does not bubble.
			b.DispatchEventOnNode(b.document, "scroll")
		}
	}

	_ = window.Set("scrollTo", func(call goja.FunctionCall) goja.Value {
		// Basic implementation supporting (x, y) arguments.
		var x, y int64
		if len(call.Arguments) > 0 {
			x = call.Argument(0).ToInteger()
		}
		if len(call.Arguments) > 1 {
			y = call.Argument(1).ToInteger()
		}
		updateScroll(x, y)
		return goja.Undefined()
	})

	_ = window.Set("scroll", window.Get("scrollTo"))

	_ = window.Set("scrollBy", func(call goja.FunctionCall) goja.Value {
		var dx, dy int64
		if len(call.Arguments) > 0 {
			dx = call.Argument(0).ToInteger()
		}
		if len(call.Arguments) > 1 {
			dy = call.Argument(1).ToInteger()
		}

		currentX := window.Get("scrollX").ToInteger()
		currentY := window.Get("scrollY").ToInteger()
		updateScroll(currentX+dx, currentY+dy)
		return goja.Undefined()
	})
}

// -- Utility functions for DOM manipulation --

func removeAttr(n *html.Node, key string) {
	if n == nil {
		return
	}
	for i, attr := range n.Attr {
		if attr.Key == key {
			n.Attr = append(n.Attr[:i], n.Attr[i+1:]...)
			return
		}
	}
}

func setAttr(n *html.Node, key, val string) {
	if n == nil {
		return
	}
	for i, attr := range n.Attr {
		if attr.Key == key {
			n.Attr[i].Val = val
			return
		}
	}
	n.Attr = append(n.Attr, html.Attribute{Key: key, Val: val})
}



