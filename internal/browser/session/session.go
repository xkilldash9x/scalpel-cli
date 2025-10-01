// Package session implements a functional, headless browser engine in pure Go.
// It integrates a robust network stack, a Go-based DOM representation (golang.org/x/net/html),
// and the Goja JavaScript runtime, synchronized via an event loop and a custom DOM bridge (jsbind).
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
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

// Session represents a single, functional browsing context (equivalent to a tab).
// It implements schemas.SessionContext.
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
	humanoidController humanoid.Controller
	jsRegistry         *require.Registry

	// JavaScript Engine and Event Loop
	// Protected by 'mu' for safe access/shutdown.
	eventLoop *eventloop.EventLoop
	// jsInterrupt removed; we now use s.ctx.Done() as the default VM interrupt.

	// Humanoid configuration
	humanoidCfg *humanoid.Config

	// State management
	// mu protects the session state, including the JS engine components above and DOM/Navigation state.
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
	consoleLogsMu sync.Mutex // Specific mutex for high-frequency access.

	findingsChan chan<- schemas.Finding
	onClose      func()
	closeOnce    sync.Once
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

	// [Lifecycle Sovereignty] The Go context is the ultimate source of truth.
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
	s.humanoidController = humanoid.New(humanoidCfg, log.Named("humanoid"), s)

	if err := s.initializeNetworkStack(log); err != nil {
		// [DEF-PROG] Ensure the event loop is stopped if initialization fails later.
		if el := s.getEventLoop(); el != nil {
			el.Stop()
		}
		cancel()
		return nil, fmt.Errorf("failed to initialize network stack: %w", err)
	}

	stabilizeFn := func(ctx context.Context) error {
		return s.stabilize(ctx)
	}
	s.interactor = dom.NewInteractor(NewZapAdapter(log.Named("interactor")), domHCfg, stabilizeFn, s)
	s.initializeDOMBridge(log)

	// Initialize the state for the initial (empty) document.
	// We pass empty maps/slices as there is no prior state.
	s.resetStateForNewDocument(nil, log, make(map[string]interface{}), make([]string, 0))

	return s, nil
}

// [ACID] getEventLoop provides safe, read-locked access to the event loop.
func (s *Session) getEventLoop() *eventloop.EventLoop {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.eventLoop
}

// [ACID] getDOMBridge provides safe, read-locked access to the DOM bridge.
func (s *Session) getDOMBridge() *jsbind.DOMBridge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domBridge
}

func (s *Session) initializeDOMBridge(log *zap.Logger) {
	el := s.getEventLoop()
	if el == nil {
		// Should not happen during initialization sequence.
		log.Error("Critical error: Event loop missing during DOMBridge initialization.")
		return
	}
	bridge := jsbind.NewDOMBridge(log.Named("dombridge"), el, s)

	s.mu.Lock()
	s.domBridge = bridge
	s.mu.Unlock()
}

// initializeJSEngine starts the event loop and configures the VM interruption strategy.
func (s *Session) initializeJSEngine(log *zap.Logger) error {
	s.jsRegistry = new(require.Registry)
	printer := &sessionConsolePrinter{s: s}
	s.jsRegistry.RegisterNativeModule("console", console.RequireWithPrinter(printer))

	el := eventloop.NewEventLoop(eventloop.WithRegistry(s.jsRegistry))
	el.Start()

	// Initialize the VM within the event loop's goroutine.
	initDone := make(chan struct{})
	el.RunOnLoop(func(vm *goja.Runtime) {
		defer close(initDone)

		// [Innovation/Lifecycle Sovereignty] Tie the VM's default interrupt directly to the session context.
		// This ensures the VM stops immediately when the session closes, without needing a separate channel.
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

	s.consoleLogsMu.Lock()
	defer s.consoleLogsMu.Unlock()
	s.consoleLogs = append(s.consoleLogs, schemas.ConsoleLog{
		Type:      logLevel,
		Timestamp: time.Now(),
		Text:      message,
	})
}

// resetStateForNewDocument resets the DOM and JS context.
// CRITICAL: This function is called by updateState *without* holding s.mu to prevent deadlocks.
// It must only rely on arguments and thread-safe methods (like DOMBridge methods or getEventLoop).
func (s *Session) resetStateForNewDocument(doc *html.Node, log *zap.Logger, exposedFunctions map[string]interface{}, persistentScripts []string) {
	if doc == nil {
		var err error
		doc, err = html.Parse(strings.NewReader("<html><head></head><body></body></html>"))
		if err != nil {
			log.Error("Critical error: Failed to parse empty HTML document.", zap.Error(err))
			return
		}
	}

	// Safely get the current URL for the initial JS location state.
	s.mu.RLock()
	initialURL := ""
	if s.currentURL != nil {
		initialURL = s.currentURL.String()
	}
	s.mu.RUnlock()

	bridge := s.getDOMBridge()
	if bridge == nil {
		return // Session closed.
	}
	bridge.UpdateDOM(doc)

	loop := s.getEventLoop()
	if loop == nil {
		return // Session closed.
	}

	// We must perform the reset synchronously on the event loop to ensure the environment is ready.
	done := make(chan struct{})
	loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)

		// [DEF-PROG] Check context before starting significant work.
		if s.ctx.Err() != nil {
			return
		}

		bridge.BindToRuntime(vm, initialURL)

		// Apply persistent configurations passed as arguments.
		for name, function := range exposedFunctions {
			if err := vm.GlobalObject().Set(name, function); err != nil {
				log.Error("Failed to expose persistent function", zap.String("name", name), zap.Error(err))
			}
		}
		for i, script := range persistentScripts {
			log.Debug("Injecting persistent script", zap.Int("index", i))
			// Execution uses the currently active interrupt handler (default: s.ctx.Done()).
			if _, err := vm.RunString(script); err != nil {
				if _, ok := err.(*goja.InterruptedError); !ok {
					log.Warn("Error executing persistent script", zap.Error(err))
				}
			}
		}

		// [Modern Goja API Utilization] Use eventLoop.SetTimeout instead of manual goroutine/delay.
		// Schedule DOMContentLoaded and load events to fire after the current script block yields.
		loop.SetTimeout(func(vm *goja.Runtime) {
			// [DEF-PROG] Check context again before firing events.
			if s.ctx.Err() != nil {
				return
			}
			// Safely access bridge again inside the timeout callback.
			if b := s.getDOMBridge(); b != nil {
				docNode := b.GetDocumentNode()
				b.DispatchEventOnNode(docNode, "DOMContentLoaded")
				b.DispatchEventOnNode(docNode, "load")
			}
		}, 1*time.Millisecond) // Minimal delay to allow yielding.
	})
	// Wait for the reset to complete on the event loop.
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
	jar, _ := cookiejar.New(nil)
	netConfig.CookieJar = jar
	transport := network.NewHTTPTransport(netConfig)
	compressionTransport := network.NewCompressionMiddleware(transport)
	s.harvester = NewHarvester(compressionTransport, log.Named("harvester"), s.cfg.Network.CaptureResponseBodies)
	s.client = &http.Client{
		Transport: s.harvester,
		Timeout:   netConfig.RequestTimeout,
		Jar:       netConfig.CookieJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return nil
}

func (s *Session) ID() string { return s.id }

func (s *Session) GetContext() context.Context { return s.ctx }

// Close gracefully terminates the session, respecting the provided context deadline.
func (s *Session) Close(ctx context.Context) error {
	// Atomically check and set the flag from 0 (open) to 1 (closing).
	if !atomic.CompareAndSwapInt32(&s.closeStatus, 0, 1) {
		s.logger.Debug("Close called on an already closing session.", zap.String("stack", string(debug.Stack())))
		return nil
	}

	s.logger.Info("--- Close called for the FIRST time ---", zap.String("stack", string(debug.Stack())))

	var returnErr error

	s.closeOnce.Do(func() {
		s.logger.Info("Initiating session shutdown.")

		// 1. Atomically retrieve the event loop.
		s.mu.Lock()
		loop := s.eventLoop
		s.mu.Unlock()

		// 2. Stop the event loop first. This allows any running script to complete.
		if loop != nil {
			stopDone := make(chan struct{})
			go func() {
				loop.Stop()
				close(stopDone)
			}()

			select {
			case <-stopDone:
				s.logger.Debug("Event loop stopped gracefully.")
			case <-ctx.Done():
				s.logger.Warn("Timeout waiting for event loop to stop.", zap.Error(ctx.Err()))
				returnErr = fmt.Errorf("timeout waiting for session event loop to close: %w", ctx.Err())
			}
		}

		// 3. Now, cancel the master session context to signal other goroutines.
		s.cancel()

		// 4. Nullify session references.
		s.mu.Lock()
		s.eventLoop = nil
		s.domBridge = nil
		s.mu.Unlock()

		// 5. Cleanup network resources.
		if s.client != nil {
			s.client.CloseIdleConnections()
		}

		// 6. Notify the manager.
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

func (s *Session) stabilize(ctx context.Context) error {
	stabCtx, stabCancel := CombineContext(s.ctx, ctx)
	defer stabCancel()

	quietPeriod := 1500 * time.Millisecond
	if s.cfg.Network.PostLoadWait > 0 {
		quietPeriod = s.cfg.Network.PostLoadWait
	}

	if s.harvester != nil {
		if err := s.harvester.WaitNetworkIdle(stabCtx, quietPeriod); err != nil {
			s.logger.Debug("Network stabilization finished with potential pending requests.", zap.Error(err))
		}
	}

	select {
	case <-time.After(quietPeriod):
	case <-stabCtx.Done():
		return stabCtx.Err()
	}

	// Wait for the event loop to process pending tasks.
	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during stabilization")
	}

	done := make(chan struct{})
	// Queue a task and wait for it to execute, implying tasks before it are done.
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

func (s *Session) Navigate(ctx context.Context, targetURL string) error {
	navCtx, navCancel := CombineContext(s.ctx, ctx)
	defer navCancel()

	resolvedURL, err := s.ResolveURL(targetURL)
	if err != nil {
		return fmt.Errorf("failed to resolve URL '%s': %w", targetURL, err)
	}
	s.logger.Info("Navigating", zap.String("url", resolvedURL.String()))

	// Dispatch 'beforeunload' event.
	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed before navigation")
	}

	done := make(chan struct{})
	loop.RunOnLoop(func(vm *goja.Runtime) {
		// Safely access the bridge within the loop.
		if bridge := s.getDOMBridge(); bridge != nil {
			docNode := bridge.GetDocumentNode()
			bridge.DispatchEventOnNode(docNode, "beforeunload")
		}
		close(done)
	})
	// Wait for the event dispatch to complete, respecting the navigation context.
	select {
	case <-done:
	case <-navCtx.Done():
		return navCtx.Err()
	}

	req, err := http.NewRequestWithContext(navCtx, http.MethodGet, resolvedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s': %w", resolvedURL.String(), err)
	}
	s.prepareRequestHeaders(req)

	if err := s.executeRequest(navCtx, req); err != nil {
		return err
	}

	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		if err := hesitate(navCtx, 500*time.Millisecond+time.Duration(rand.Intn(1000))*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

// waitForEventLoop ensures that any tasks currently queued on the JS event loop are executed.
func (s *Session) waitForEventLoop(ctx context.Context) error {
	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed while waiting for event loop")
	}

	done := make(chan struct{})
	// Queue a no-op task. When it executes, all preceding tasks are complete.
	loop.RunOnLoop(func(vm *goja.Runtime) {
		close(done)
	})

	// Wait for our task to run or for the context to be canceled.
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

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
	// ... (Implementation remains the same, correctly utilizes context) ...
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

func (s *Session) processResponse(resp *http.Response) error {
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.logger.Warn("Request resulted in error status code", zap.Int("status", resp.StatusCode), zap.String("url", resp.Request.URL.String()))
	}

	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(strings.ToLower(contentType), "text/html")
	var doc *html.Node

	if isHTML {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		doc, err = htmlquery.Parse(bytes.NewReader(bodyBytes))
		if err != nil {
			s.logger.Error("Failed to parse HTML response.", zap.Error(err), zap.String("url", resp.Request.URL.String()))
		}
		s.extractAndParseCSS(doc, resp.Request.URL)
	} else {
		s.logger.Debug("Response is not HTML.", zap.String("content_type", contentType))
	}

	s.updateState(resp.Request.URL, doc, true)

	if isHTML && doc != nil {
		s.executePageScripts(doc)
	}
	return nil
}

func (s *Session) extractAndParseCSS(doc *html.Node, baseURL *url.URL) {
	// ... (Implementation remains the same, locking is appropriate) ...
	if doc == nil {
		return
	}
	s.mu.Lock()
	s.layoutEngine = layout.NewEngine()
	currentEngine := s.layoutEngine
	s.mu.Unlock()

	styleTags := htmlquery.Find(doc, "//style")
	for _, tag := range styleTags {
		p := parser.NewParser(htmlquery.InnerText(tag))
		currentEngine.AddStyleSheet(p.Parse())
	}

	linkTags := htmlquery.Find(doc, "//link[@rel='stylesheet' and @href]")
	if len(linkTags) == 0 {
		return
	}
	var wg sync.WaitGroup
	stylesheetChan := make(chan *parser.StyleSheet, len(linkTags))
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
		// Network I/O happens in a goroutine, respecting s.ctx.
		go func(url string) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(s.ctx, "GET", url, nil)
			s.prepareRequestHeaders(req)
			resp, err := s.client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			p := parser.NewParser(string(body))
			stylesheet := p.Parse()
			stylesheetChan <- &stylesheet
		}(cssURL.String())
	}
	go func() {
		wg.Wait()
		close(stylesheetChan)
	}()
	for stylesheet := range stylesheetChan {
		s.mu.Lock()
		// Ensure we are still using the current engine (it might have changed if a new navigation occurred).
		if s.layoutEngine == currentEngine {
			s.layoutEngine.AddStyleSheet(*stylesheet)
		}
		s.mu.Unlock()
	}
}

// updateState updates the session's Go state and synchronizes the VM state.
// [ACID/Deadlock Prevention] Refactored to prevent deadlocks by ensuring s.mu is not held during VM synchronization.
func (s *Session) updateState(newURL *url.URL, doc *html.Node, resetContext bool) {
	// Phase 1: Update Go state (URL, Layout, History). This requires locking.
	s.mu.Lock()

	s.currentURL = newURL

	// Update Layout Root based on the new document.
	if doc != nil {
		s.layoutRoot = s.layoutEngine.Render(doc, float64(s.persona.Width), float64(s.persona.Height))
	} else {
		s.layoutRoot = nil
	}

	// Determine the page title.
	title := ""
	if doc != nil {
		if titleNode := htmlquery.FindOne(doc, "//title"); titleNode != nil {
			title = strings.TrimSpace(htmlquery.InnerText(titleNode))
		}
	}

	// Prepare copies of persistent configuration for the VM reset (needed outside the lock).
	var exposedFunctionsCopy map[string]interface{}
	var persistentScriptsCopy []string

	if resetContext {
		// Handle History for navigation. A context reset implies a navigation that pushes history.
		newState := &schemas.HistoryState{
			State: nil,
			Title: title,
			URL:   newURL.String(),
		}
		s.pushHistoryInternal(newState)

		// Copy persistent data under lock.
		exposedFunctionsCopy = make(map[string]interface{})
		for k, v := range s.exposedFunctions {
			exposedFunctionsCopy[k] = v
		}
		persistentScriptsCopy = make([]string, len(s.persistentScripts))
		copy(persistentScriptsCopy, s.persistentScripts)

	} else {
		// If not resetting (e.g., minor update), just update the title of the current entry.
		if s.historyIndex >= 0 && s.historyIndex < len(s.historyStack) {
			s.historyStack[s.historyIndex].Title = title
		}
	}

	// CRITICAL: Release the lock before synchronizing with the VM.
	s.mu.Unlock()

	// Phase 2: Reset VM state and DOM Bridge (Synchronously).
	if resetContext {
		// This function waits for the event loop, which is now safe as s.mu is released.
		s.resetStateForNewDocument(doc, s.logger, exposedFunctionsCopy, persistentScriptsCopy)
	}

	s.logger.Debug("Session state updated", zap.String("url", newURL.String()), zap.String("title", title), zap.Bool("context_reset", resetContext))
}

func (s *Session) executePageScripts(doc *html.Node) {
	loop := s.getEventLoop()
	if loop == nil {
		return // Session closed.
	}

	gqDoc := goquery.NewDocumentFromNode(doc)
	gqDoc.Find("script").Each(func(i int, sel *goquery.Selection) {
		scriptType, _ := sel.Attr("type")
		normalizedType := strings.ToLower(strings.TrimSpace(scriptType))
		if normalizedType != "" && normalizedType != "text/javascript" && normalizedType != "application/javascript" && normalizedType != "module" {
			return
		}
		if src, exists := sel.Attr("src"); exists && src != "" {
			// External scripts are fetched asynchronously.
			s.fetchAndExecuteScript(src)
		} else {
			// Inline scripts are queued onto the event loop immediately.
			scriptContent := sel.Text()
			if scriptContent != "" {
				loop.RunOnLoop(func(vm *goja.Runtime) {
					// Execution uses the currently active interrupt handler (default: s.ctx.Done()).
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

func (s *Session) fetchAndExecuteScript(src string) {
	resolvedURL, err := s.ResolveURL(src)
	if err != nil {
		s.logger.Warn("Failed to resolve external script URL", zap.String("src", src), zap.Error(err))
		return
	}

	// Fetch asynchronously (non-blocking I/O).
	go func() {
		// Network request respects the session context (s.ctx).
		req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, resolvedURL.String(), nil)
		if err != nil {
			s.logger.Error("Failed to create request for external script", zap.Error(err), zap.String("url", resolvedURL.String()))
			return
		}

		s.prepareRequestHeaders(req)
		req.Header.Set("Accept", "*/*")

		resp, err := s.client.Do(req)
		if err != nil {
			// [DEF-PROG] Only log if the error wasn't due to the session closing.
			if s.ctx.Err() == nil {
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

		// [DEF-PROG] Check context and get event loop before queuing execution.
		if s.ctx.Err() != nil {
			return
		}
		loop := s.getEventLoop()
		if loop == nil {
			return
		}

		loop.RunOnLoop(func(vm *goja.Runtime) {
			// Execution uses the currently active interrupt handler.
			if _, err := vm.RunScript(resolvedURL.String(), string(body)); err != nil {
				if _, ok := err.(*goja.InterruptedError); !ok {
					s.logger.Warn("Error executing external script", zap.Error(err), zap.String("url", resolvedURL.String()))
				}
			}
		})
	}()
}

func (s *Session) GetDOMSnapshot(ctx context.Context) (io.Reader, error) {
	bridge := s.getDOMBridge()
	if bridge == nil {
		// Return empty if the session is closed.
		return bytes.NewBufferString("<html></html>"), nil
	}
	// GetOuterHTML handles its internal locking for the DOM structure.
	htmlContent, err := bridge.GetOuterHTML()
	if err != nil {
		return nil, err
	}
	return strings.NewReader(htmlContent), nil
}

func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	if s.interactor == nil {
		return fmt.Errorf("interactor not initialized")
	}
	domConfig := dom.InteractionConfig{
		MaxDepth:                config.MaxDepth,
		MaxInteractionsPerDepth: config.MaxInteractionsPerDepth,
		InteractionDelayMs:      config.InteractionDelayMs,
		PostInteractionWaitMs:   config.PostInteractionWaitMs,
	}
	return s.interactor.RecursiveInteract(ctx, domConfig)
}

func (s *Session) Click(ctx context.Context, selector string) error {
	minMs, maxMs := 0, 0
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		minMs = int(s.humanoidCfg.ClickHoldMinMs)
		maxMs = int(s.humanoidCfg.ClickHoldMaxMs)
	}
	if err := s.ExecuteClick(ctx, selector, minMs, maxMs); err != nil {
		return err
	}
	return s.stabilize(ctx)
}

func (s *Session) Type(ctx context.Context, selector string, text string) error {
	holdMeanMs := 0.0
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		holdMeanMs = s.humanoidCfg.KeyHoldMeanMs
	}
	if err := s.ExecuteType(ctx, selector, text, holdMeanMs); err != nil {
		return err
	}
	return s.stabilize(ctx)
}

func (s *Session) Submit(ctx context.Context, selector string) error {
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}
	form := findParentForm(element)
	if form == nil {
		return fmt.Errorf("element '%s' is not associated with a form", selector)
	}

	// Dispatch the submit event on the event loop.
	loop := s.getEventLoop()
	if loop != nil {
		loop.RunOnLoop(func(vm *goja.Runtime) {
			if bridge := s.getDOMBridge(); bridge != nil {
				bridge.DispatchEventOnNode(form, "submit")
			}
		})
	}

	if err := s.submitForm(ctx, form); err != nil {
		return err
	}
	return s.stabilize(ctx)
	}


func (s *Session) ScrollPage(ctx context.Context, direction string) error {
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
	// Uses the robust ExecuteScript implementation.
	_, err := s.ExecuteScript(ctx, script, nil)
	return err
}

func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	if milliseconds > 0 {
		return hesitate(ctx, time.Duration(milliseconds)*time.Millisecond)
	}
	return s.stabilize(ctx)
}

func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	// Update the persistent map (requires lock).
	s.mu.Lock()
	s.exposedFunctions[name] = function
	s.mu.Unlock()

	// Expose to the current runtime environment.
	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed or event loop not initialized")
	}

	errChan := make(chan error, 1)
	loop.RunOnLoop(func(vm *goja.Runtime) {
		vm.ClearInterrupt()	
		errChan <- vm.Set(name, function)
	})

	// Wait for completion, respecting the context.
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	// Update the persistent list (requires lock).
	s.mu.Lock()
	s.persistentScripts = append(s.persistentScripts, script)
	s.mu.Unlock()

	// Inject into the current environment immediately.
	_, err := s.ExecuteScript(ctx, script, nil)
	return err
}

func (s *Session) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	var result interface{}
	// The core logic is handled by the robustly refactored executeScriptInternal.
	err := s.executeScriptInternal(ctx, script, &result, args)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return json.RawMessage("null"), nil
	}
	return json.Marshal(result)
}

// executeScriptInternal is the core JS execution logic, refactored for robustness, context respect, and performance
// based on the "Handle Swapping" pattern for dedicated, long-lived VMs.
func (s *Session) executeScriptInternal(ctx context.Context, script string, res interface{}, args []interface{}) error {
	// 1. Create the execution context...
	execCtx, execCancel := CombineContext(s.ctx, ctx)
	defer execCancel()
	// 2. Check if the context is already cancelled before attempting to schedule.
	if execCtx.Err() != nil {
		return execCtx.Err()
	}

	// 3. Get the event loop.
	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed: event loop unavailable")
	}

	// 4. Prepare a channel for the result.
	resultChan := make(chan struct {
		Value goja.Value
		Error error
	}, 1)

	// 5. Schedule the execution on the event loop.
	loop.RunOnLoop(func(vm *goja.Runtime) {
		// This block executes within the event loop's single goroutine.
		vm.ClearInterrupt()

		// 5.1. Create a specific interrupt handle for this execution.
		execInterruptHandle := make(chan struct{})

		// 5.2. SWAP: Set the VM's interrupt to our specific handle.
		// Defer the restoration of the original session-wide handle (s.ctx.Done()).
		vm.Interrupt(execInterruptHandle)
		defer vm.Interrupt(s.ctx.Done())


		// 5.3. Create a channel to signal when execution is finished, to stop the watchdog.
		executionDone := make(chan struct{})

		// 5.4. LAUNCH WATCHDOG: This runs in a new goroutine.
		// It watches for the execution context to be done (e.g., timeout).
		go func() {
			select {
			case <-execCtx.Done():
				// Context timed out or was canceled. Interrupt the VM by closing the specific handle.
				close(execInterruptHandle)
			case <-executionDone:
				// Script finished normally. The watchdog's job is done.
			}
		}()

		// 5.5. Execute the script within a closure to manage the 'executionDone' signal.
		var val goja.Value
		var err error
		func() {
			// Signal the watchdog to stop monitoring when this function returns.
			defer close(executionDone)
			val, err = vm.RunString(script)
		}()

		// 5.6. Send the result back to the waiting caller.
		// Use a select to avoid blocking if the caller has already given up (execCtx.Done()).
		select {
		case resultChan <- struct {
			Value goja.Value
			Error error
		}{val, err}:
		case <-execCtx.Done():
		}
	})

    // 6. Wait for the result from the event loop... (rest of the function remains the same)
	select {
	case result := <-resultChan:
		// 7. Process the result (handle errors, export values).
		return s.processScriptResult(execCtx, result.Value, result.Error, res)
	case <-execCtx.Done():
		// The caller's context was canceled while waiting for the result.
		return execCtx.Err()
	}
}
// waitForPromise uses the event loop to wait for a promise to settle.
// waitForPromise uses the event loop to wait for a promise to settle.
func (s *Session) waitForPromise(ctx context.Context, promise *goja.Promise) (goja.Value, error) {
	loop := s.getEventLoop()
	if loop == nil {
		return nil, errors.New("session closed while waiting for promise")
	}

	resultChan := make(chan struct {
		Value goja.Value
		Error error
	}, 1)

	// 'check' is a function that will be scheduled on the event loop.
	var check func()

	check = func() {
		// Before doing anything, ensure the session/context is still active.
		if ctx.Err() != nil {
			// Non-blocking send, as the context done case will catch it below.
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
			// Wrap the rejection reason in a Go error.
			err := fmt.Errorf("javascript promise rejected: %v", promise.Result().Export())
			resultChan <- struct {
				Value goja.Value
				Error error
			}{nil, err}
		case goja.PromiseStatePending:
			// The promise is still pending, so we schedule another check.
			// FIX: The call to check() is now wrapped in a function with the correct signature.
			loop.SetTimeout(func(_ *goja.Runtime) {
				check()
			}, 10*time.Millisecond)
		}
	}

	// Schedule the first check on the event loop.
	// FIX: This call is also wrapped to provide the correct function signature.
	loop.RunOnLoop(func(_ *goja.Runtime) {
		check()
	})

	// Wait for the result from our channel or for the context to be canceled.
	select {
	case res := <-resultChan:
		return res.Value, res.Error
	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled while waiting for promise: %w", ctx.Err())
	}
}
// processScriptResult handles errors and exports the value from the VM. (DRY Principle)
func (s *Session) processScriptResult(ctx context.Context, value goja.Value, err error, res interface{}) error {
	// First, check for immediate errors from the script execution itself.
	if err != nil {
		var gojaException *goja.Exception
		var interruptedError *goja.InterruptedError

		// If the error is an interrupt, it's because the context was cancelled.
		// There can be a race where ctx.Err() is still nil for a moment after the interrupt fires.
		// We treat any interrupt as a context error.
		if errors.As(err, &interruptedError) {
			// If the context has an error, use it for a more descriptive message.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("javascript execution interrupted by context: %w", ctxErr)
			}
			// Otherwise, return a generic interrupt error based on the goja error.
			return fmt.Errorf("javascript execution interrupted (session closing): %w", err)
		} else if errors.As(err, &gojaException) {
			return fmt.Errorf("javascript exception: %s", gojaException.String())
		} else {
			return fmt.Errorf("javascript execution error: %w", err)
		}
	}

	// If the initial result is a promise, wait for it to settle.
	if promise, ok := value.Export().(*goja.Promise); ok {
		// The waitForPromise function returns the resolved value or the rejection error.
		value, err = s.waitForPromise(ctx, promise)
		if err != nil {
			// This error is from the promise settling (e.g., rejection or context timeout).
			return err
		}
	}

	// Handle exporting the final result value.
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
// -- dom.CorePagePrimitives implementation --

func (s *Session) GetCurrentURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentURL != nil {
		return s.currentURL.String()
	}
	return ""
}

func (s *Session) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		// Placeholder for humanoid timing simulation.
	}

	// Dispatch the click event on the event loop.
	loop := s.getEventLoop()
	if loop != nil {
		loop.RunOnLoop(func(vm *goja.Runtime) {
			if bridge := s.getDOMBridge(); bridge != nil {
				bridge.DispatchEventOnNode(element, "click")
			}
		})
	}

	return s.handleClickConsequence(ctx, element)
}

func (s *Session) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during interaction")
	}

	// Focus the element first.
	loop.RunOnLoop(func(vm *goja.Runtime) {
		if bridge := s.getDOMBridge(); bridge != nil {
			bridge.DispatchEventOnNode(element, "focus")
		}
	})

	// Get initial value using the robust ExecuteScript.
	escapedSelector := strings.ReplaceAll(selector, "'", "\\'")
	scriptToGetValue := fmt.Sprintf(`document.querySelector('%s').value || ''`, escapedSelector)

	var result json.RawMessage
	result, err = s.ExecuteScript(ctx, scriptToGetValue, nil)
	if err != nil {
		return fmt.Errorf("could not get initial value of element '%s': %w", selector, err)
	}
	var currentValue string
	if err := json.Unmarshal(result, &currentValue); err != nil {
		return fmt.Errorf("could not decode element value: %w", err)
	}

	for _, char := range text {
		if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
			if err := hesitate(ctx, 50*time.Millisecond); err != nil {
				return err
			}
		}

		currentValue += string(char)
		escapedValue := strings.ReplaceAll(currentValue, "'", "\\'")
		escapedValue = strings.ReplaceAll(escapedValue, `\`, `\\`)

		// Update value via script.
		scriptToSetValue := fmt.Sprintf(`document.querySelector('%s').value = '%s'`, escapedSelector, escapedValue)
		if _, err := s.ExecuteScript(ctx, scriptToSetValue, nil); err != nil {
			s.logger.Warn("Failed to update element value via script", zap.String("selector", selector), zap.Error(err))
		}

		// Dispatch keyboard events.
		// Need to check loop availability again inside the loop (DEF-PROG).
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

	// Blur the element after typing.
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

func (s *Session) ExecuteSelect(ctx context.Context, selector string, value string) error {
	selectNode, err := s.findElementNode(selector)
	if err != nil {
		return err
	}

	// Check if it's actually a <select> element. This requires synchronization.
	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during interaction")
	}

	isSelect := false
	// We need to wait for this check to complete before proceeding.
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

	script := fmt.Sprintf(`
        const select = document.querySelector('%s');
        if (!select) { return false; }
        const options = Array.from(select.options);
        let found = false;
        options.forEach(opt => {
            if (opt.value === '%s') {
                opt.selected = true;
                found = true;
            } else {
                opt.selected = false;
            }
        });
        if (found) { select.value = '%s'; }
        return found;
    `, escapedSelector, escapedValue, escapedValue)

	// Uses the robust ExecuteScript implementation.
	resultRaw, err := s.ExecuteScript(ctx, script, nil)
	if err != nil {
		return fmt.Errorf("script to set select value failed for '%s': %w", selector, err)
	}

	var found bool
	if err := json.Unmarshal(resultRaw, &found); err != nil || !found {
		return fmt.Errorf("option with value '%s' not found or script failed", value)
	}

	// Dispatch events.
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

func (s *Session) IsVisible(ctx context.Context, selector string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.layoutRoot == nil {
		return false
	}
	geo, err := s.layoutEngine.GetElementGeometry(s.layoutRoot, selector)
	return err == nil && geo != nil
}

// -- jsbind.BrowserEnvironment implementation --

// JSNavigate handles navigation initiated from JavaScript (e.g., location.href = ...).
func (s *Session) JSNavigate(targetURL string) {
	// Navigation involves network I/O and stabilization, which cannot happen synchronously
	// within the event loop (deadlock risk). It must be asynchronous.
	go func() {
		// Use the main session context (s.ctx).
		if err := s.Navigate(s.ctx, targetURL); err != nil {
			// [DEF-PROG] Only log if the error wasn't due to the session closing.
			if s.ctx.Err() == nil {
				s.logger.Error("JS-initiated navigation failed", zap.Error(err))
			}
		}
	}()
}

func (s *Session) NotifyURLChange(targetURL string) {
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

func (s *Session) ExecuteFetch(ctx context.Context, reqData schemas.FetchRequest) (*schemas.FetchResponse, error) {
	// ... (Implementation remains the same, correctly uses CombineContext) ...
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

	fetchClient := *s.client
	fetchClient.CheckRedirect = nil // Fetch API handles redirects differently than navigation.
	if reqData.Credentials == "omit" {
		fetchClient.Jar = nil
	}

	httpResp, err := fetchClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

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

func (s *Session) AddCookieFromString(cookieStr string) error {
	// ... (Implementation remains the same, correctly uses RLock) ...
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
		s.client.Jar.SetCookies(currentURL, cookies)
	}
	return nil
}

func (s *Session) GetCookieString() (string, error) {
	// ... (Implementation remains the same, correctly uses RLock) ...
	if s.client.Jar == nil {
		return "", nil
	}
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	if currentURL == nil {
		return "", nil
	}
	cookies := s.client.Jar.Cookies(currentURL)
	var cookieStrings []string
	for _, c := range cookies {
		if !c.HttpOnly {
			cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
	}
	return strings.Join(cookieStrings, "; "), nil
}

func (s *Session) PushHistory(state *schemas.HistoryState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushHistoryInternal(state)
	return nil
}

// pushHistoryInternal must be called under write lock (s.mu).
func (s *Session) pushHistoryInternal(state *schemas.HistoryState) {
	// Truncate the forward history.
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
		// If history is empty, replace acts like push.
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

// -- humanoid.Executor implementation --

func (s *Session) Sleep(ctx context.Context, d time.Duration) error {
	return hesitate(ctx, d)
}

func (s *Session) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	s.logger.Debug("Dispatching mouse event", zap.Any("data", data))
	// Implementation required to map this to DOM events on the event loop.
	return nil
}

func (s *Session) SendKeys(ctx context.Context, keys string) error {
	s.logger.Debug("Sending keys", zap.String("keys", keys))
	// Implementation required.
	return nil
}

func (s *Session) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.layoutRoot == nil {
		return nil, fmt.Errorf("layout tree not available")
	}
	return s.layoutEngine.GetElementGeometry(s.layoutRoot, selector)
}

// -- Artifact Collection and Findings --

func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
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

	domSnapshot, _ := s.GetDOMSnapshot(ctx)
	if domSnapshot != nil {
		snapshotBytes, _ := io.ReadAll(domSnapshot)
		artifacts.DOM = string(snapshotBytes)
	}

	// Storage state collection needs implementation (e.g., via DOMBridge).
	artifacts.Storage = schemas.StorageState{}

	return artifacts, nil
}

func (s *Session) AddFinding(finding schemas.Finding) error {
	if s.findingsChan != nil {
		if finding.Timestamp.IsZero() {
			finding.Timestamp = time.Now()
		}
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

// -- Helper Functions --

func (s *Session) prepareRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", s.persona.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", strings.Join(s.persona.Languages, ","))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	// Safely get the current URL for the Referer header.
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	if currentURL != nil {
		req.Header.Set("Referer", currentURL.String())
	}
}

func (s *Session) findElementNode(selector string) (*html.Node, error) {
	bridge := s.getDOMBridge()
	if bridge == nil {
		return nil, fmt.Errorf("DOM bridge is not initialized or session is closed")
	}
	// QuerySelector handles its internal DOM locking.
	return bridge.QuerySelector(selector)
}

func (s *Session) handleClickConsequence(ctx context.Context, element *html.Node) error {
	// Basic handling for <a> tag clicks.
	if strings.ToLower(element.Data) == "a" {
		if href := htmlquery.SelectAttr(element, "href"); href != "" {
			// Initiate navigation. This happens outside the event loop.
			return s.Navigate(ctx, href)
		}
	}
	return nil
}

func (s *Session) submitForm(ctx context.Context, form *html.Node) error {
	// Form submission requires gathering data from the DOM, which must happen on the event loop.
	var action, method, enctype string
	var formData url.Values

	loop := s.getEventLoop()
	if loop == nil {
		return errors.New("session closed during form submission preparation")
	}

	// [ACID] We must gather form data synchronously on the event loop as it accesses the DOM state.
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

	// Wait for data gathering, respecting the context.
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
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // Use the standard type
	} else { // GET request
		targetURL.RawQuery = formData.Encode()
		req, err = http.NewRequestWithContext(ctx, method, targetURL.String(), nil)
		if err != nil {
			return err
		}
	}

	s.prepareRequestHeaders(req)
	// Execute the resulting network request.
	return s.executeRequest(ctx, req)
}

func getAttr(n *html.Node, key string) (string, bool) {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}
	return "", false
}

func findParentForm(element *html.Node) *html.Node {
	for p := element.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && strings.ToLower(p.Data) == "form" {
			return p
		}
	}
	return nil
}

// CombineContext creates a new context that is canceled if either the parentCtx or secondaryCtx is canceled.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	// If the secondary context is already done, we can return it immediately.
	// This also handles the case where secondaryCtx is nil.
	if secondaryCtx.Err() != nil {
		return secondaryCtx, func() {}
	}
	// If the parent is already done, return it.
	if parentCtx.Err() != nil {
		return parentCtx, func() {}
	}

	combinedCtx, cancel := context.WithCancel(parentCtx)

	// Stop is a flag to prevent the cancel function from being called more than once.
	// This is good practice when dealing with multiple context cancellations.
	stop := make(chan struct{})

	// This single goroutine will handle the cancellation from the secondary context.
	go func() {
		select {
		case <-secondaryCtx.Done():
			// If the secondary context is done, cancel the combined context.
			cancel()
		case <-combinedCtx.Done():
			// If the combined context is done for any other reason, just exit.
		case <-stop:
			// The cancel function has been called, so we can exit.
		}
	}()

	// Return a custom cancel function that also stops our monitoring goroutine.
	return combinedCtx, func() {
		// We use a non-blocking send to the stop channel to prevent a deadlock
		// if the goroutine has already exited.
		select {
		case stop <- struct{}{}:
		default:
		}
		cancel()
	}
}