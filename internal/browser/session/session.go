// Package session implements a functional, headless browser engine in pure Go.
// It integrates a robust network stack, a Go-based DOM representation (golang.org/x/net/html),
// and the Goja JavaScript runtime, synchronized via an event loop and a custom DOM bridge (jsbind).
package session

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/xkilldash9x/scalpel-cli/internal/browser/jsbind"
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
The 'jsbind.DOMBridge' structure is the synchronization layer. It exposes W3C DOM APIs
to the JS runtime, backed by the *html.Node structure, ensuring a live, interactive environment.

Layout Engine Integration:
After parsing an HTML document and its associated CSS, the `layout.Engine` computes a `LayoutTree`. This
tree contains the geometry (size and position) of every rendered element, enabling accurate visibility checks
and coordinate based interactions.
*/

// Session represents a single, functional browsing context (equivalent to a tab).
// It implements schemas.SessionContext.
type Session struct {
	id     string
	ctx    context.Context
	cancel context.CancelFunc
	logger *zap.Logger
	cfg    *config.Config
	persona schemas.Persona

	// Core functional components
	client             *http.Client
	interactor         *dom.Interactor
	harvester          *Harvester
	layoutEngine       *layout.Engine
	humanoidController humanoid.Controller

	// JavaScript Engine and Event Loop
	eventLoop  *eventloop.EventLoop
	jsRegistry *require.Registry

	// Humanoid configuration
	humanoidCfg *humanoid.Config

	// State management
	mu sync.RWMutex

	currentURL *url.URL
	// The root of the rendered layout tree, containing element geometry.
	layoutRoot *layout.LayoutBox
	// DOMBridge holds the synchronized DOM representation and manages interaction with the JS runtime.
	domBridge *jsbind.DOMBridge

	// History stack implementation
	historyStack []*schemas.HistoryState
	historyIndex int // Points to the current entry in the stack

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

// sessionConsolePrinter implements the console.Printer interface required by goja_nodejs.
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
var _ jsbind.APICallbacks = (*Session)(nil)
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
			//nolint:gosec
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
		s.eventLoop.Stop()
		cancel()
		return nil, fmt.Errorf("failed to initialize network stack: %w", err)
	}

	stabilizeFn := func(ctx context.Context) error {
		return s.stabilize(ctx)
	}
	s.interactor = dom.NewInteractor(NewZapAdapter(log.Named("interactor")), domHCfg, stabilizeFn, s)
	s.initializeDOMBridge(log, s)

	s.mu.Lock()
	s.resetStateForNewDocument(nil, log)
	s.mu.Unlock()

	return s, nil
}

// initializeDOMBridge sets up the jsbind.DOMBridge.
func (s *Session) initializeDOMBridge(log *zap.Logger, callbacks jsbind.APICallbacks) {
	s.domBridge = jsbind.NewDOMBridge(log.Named("dombridge"), s.eventLoop, callbacks)
}

// initializeJSEngine sets up the Goja runtime, the event loop, and global configurations.
func (s *Session) initializeJSEngine(log *zap.Logger) error {
	s.jsRegistry = new(require.Registry)
	printer := &sessionConsolePrinter{s: s}
	s.jsRegistry.RegisterNativeModule("console", console.RequireWithPrinter(printer))
	s.eventLoop = eventloop.NewEventLoop(eventloop.WithRegistry(s.jsRegistry))
	s.eventLoop.Start()

	initDone := make(chan struct{})
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(initDone)
		s.jsRegistry.Enable(vm)
		navigator := vm.NewObject()
		_ = navigator.Set("userAgent", s.persona.UserAgent)
		_ = navigator.Set("platform", s.persona.Platform)
		_ = navigator.Set("languages", s.persona.Languages)
		_ = vm.Set("navigator", navigator)
	})
	<-initDone

	log.Info("JavaScript engine (Goja) and event loop initialized.")
	return nil
}

// captureConsoleLog handles messages from the JS console.
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

// resetStateForNewDocument prepares the session state for a new page load.
func (s *Session) resetStateForNewDocument(doc *html.Node, log *zap.Logger) {
	if doc == nil {
		var err error
		doc, err = html.Parse(strings.NewReader("<html><head></head><body></body></html>"))
		if err != nil {
			log.Error("Critical error: Failed to parse empty HTML document.", zap.Error(err))
			return
		}
	}

	initialURL := ""
	if s.currentURL != nil {
		initialURL = s.currentURL.String()
	}
	s.domBridge.UpdateDOM(doc, initialURL)

	done := make(chan struct{})
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)
		s.domBridge.BindToRuntime(vm)
		for name, function := range s.exposedFunctions {
			if err := vm.GlobalObject().Set(name, function); err != nil {
				log.Error("Failed to expose persistent function", zap.String("name", name), zap.Error(err))
			}
		}
		for i, script := range s.persistentScripts {
			log.Debug("Injecting persistent script", zap.Int("index", i))
			if _, err := vm.RunString(script); err != nil {
				log.Warn("Error executing persistent script", zap.Error(err))
			}
		}
		go func() {
			time.Sleep(10 * time.Millisecond)
			s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				docNode := s.domBridge.GetDocumentNode()
				s.domBridge.DispatchEventOnNode(docNode, "DOMContentLoaded")
				s.domBridge.DispatchEventOnNode(docNode, "load")
			})
		}()
	})
	<-done

	if s.currentURL != nil {
		initialState := &schemas.HistoryState{
			State: nil,
			Title: "",
			URL:   s.currentURL.String(),
		}
		s.pushHistoryInternal(initialState)
	}
}

// initializeNetworkStack sets up the http.Client and Harvester middleware.
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

// ID returns the session ID.
func (s *Session) ID() string { return s.id }

// GetContext returns the session's lifecycle context.
func (s *Session) GetContext() context.Context { return s.ctx }

// Close terminates the session and stops the event loop.
func (s *Session) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.logger.Info("Closing session.")
		if s.eventLoop != nil {
			s.eventLoop.Stop()
		}
		s.cancel()
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

	done := make(chan struct{})
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
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

// -- Navigation and Execution --

// Navigate loads a URL and updates the session state.
func (s *Session) Navigate(ctx context.Context, targetURL string) error {
	navCtx, navCancel := CombineContext(s.ctx, ctx)
	defer navCancel()

	resolvedURL, err := s.resolveURL(targetURL)
	if err != nil {
		return fmt.Errorf("failed to resolve URL '%s': %w", targetURL, err)
	}
	s.logger.Info("Navigating", zap.String("url", resolvedURL.String()))

	done := make(chan struct{})
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.domBridge != nil {
			docNode := s.domBridge.GetDocumentNode()
			s.domBridge.DispatchEventOnNode(docNode, "beforeunload")
		}
		close(done)
	})
	<-done

	req, err := http.NewRequestWithContext(navCtx, http.MethodGet, resolvedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s': %w", resolvedURL.String(), err)
	}
	s.prepareRequestHeaders(req)

	if err := s.executeRequest(navCtx, req); err != nil {
		return err
	}

	if err := s.stabilize(navCtx); err != nil {
		if navCtx.Err() != nil {
			return navCtx.Err()
		}
		s.logger.Debug("Stabilization finished with potential issues after navigation.", zap.Error(err))
	}

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

// handleRedirect processes a redirect response.
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

// processResponse parses the DOM, updates state, and executes scripts.
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

// extractAndParseCSS finds, fetches, and parses CSS.
func (s *Session) extractAndParseCSS(doc *html.Node, baseURL *url.URL) {
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
		if s.layoutEngine == currentEngine {
			s.layoutEngine.AddStyleSheet(*stylesheet)
		}
		s.mu.Unlock()
	}
}

// updateState updates the session's current URL and resets the DOM/JS environment.
func (s *Session) updateState(newURL *url.URL, doc *html.Node, resetContext bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.currentURL = newURL
	if doc != nil {
		s.layoutRoot = s.layoutEngine.Render(doc, float64(s.persona.Width), float64(s.persona.Height))
	} else {
		s.layoutRoot = nil
	}
	if resetContext {
		s.resetStateForNewDocument(doc, s.logger)
	}
	title := ""
	if doc != nil {
		if titleNode := htmlquery.FindOne(doc, "//title"); titleNode != nil {
			title = strings.TrimSpace(htmlquery.InnerText(titleNode))
		}
	}
	if resetContext && s.historyIndex >= 0 && s.historyIndex < len(s.historyStack) {
		s.historyStack[s.historyIndex].Title = title
	}
	s.logger.Debug("Session state updated", zap.String("url", newURL.String()), zap.String("title", title), zap.Bool("context_reset", resetContext))
}

// executePageScripts finds and executes <script> tags.
func (s *Session) executePageScripts(doc *html.Node) {
	gqDoc := goquery.NewDocumentFromNode(doc)
	gqDoc.Find("script").Each(func(i int, sel *goquery.Selection) {
		scriptType, _ := sel.Attr("type")
		normalizedType := strings.ToLower(strings.TrimSpace(scriptType))
		if normalizedType != "" && normalizedType != "text/javascript" && normalizedType != "application/javascript" && normalizedType != "module" {
			return
		}
		if src, exists := sel.Attr("src"); exists && src != "" {
			s.fetchAndExecuteScript(src)
		} else {
			scriptContent := sel.Text()
			if scriptContent != "" {
				s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
					if _, err := vm.RunString(scriptContent); err != nil {
						s.logger.Warn("Error executing inline script", zap.Error(err))
					}
				})
			}
		}
	})
}

// fetchAndExecuteScript handles downloading and executing external JavaScript files.
func (s *Session) fetchAndExecuteScript(src string) {
	resolvedURL, err := s.resolveURL(src)
	if err != nil {
		s.logger.Warn("Failed to resolve external script URL", zap.String("src", src), zap.Error(err))
		return
	}
	go func() {
		req, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, resolvedURL.String(), nil)
		s.prepareRequestHeaders(req)
		req.Header.Set("Accept", "*/*")
		resp, err := s.client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return
		}
		body, _ := io.ReadAll(resp.Body)
		s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
			if _, err := vm.RunScript(resolvedURL.String(), string(body)); err != nil {
				s.logger.Warn("Error executing external script", zap.Error(err), zap.String("url", resolvedURL.String()))
			}
		})
	}()
}

// -- Implementation of dom.CorePagePrimitives --

func (s *Session) GetCurrentURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentURL != nil {
		return s.currentURL.String()
	}
	return ""
}

func (s *Session) GetDOMSnapshot(ctx context.Context) (io.Reader, error) {
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()
	if bridge == nil {
		return bytes.NewBufferString(""), nil
	}
	htmlContent, err := bridge.GetOuterHTML()
	if err != nil {
		return nil, err
	}
	return strings.NewReader(htmlContent), nil
}

func (s *Session) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		if err := simulateClickTiming(ctx, minMs, maxMs); err != nil {
			return err
		}
	}
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		s.domBridge.DispatchEventOnNode(element, "click")
	})
	return s.handleClickConsequence(ctx, element)
}

func (s *Session) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	element, err := s.findElementNode(selector)
	if err != nil {
		return err
	}
	// Simplified: A real implementation would need to update the DOM via the bridge.
	s.logger.Warn("ExecuteType is a simplified implementation.", zap.String("selector", selector))
	return nil
}

func (s *Session) ExecuteSelect(ctx context.Context, selector string, value string) error {
	// Simplified: A real implementation would need to update the DOM via the bridge.
	s.logger.Warn("ExecuteSelect is a simplified implementation.", zap.String("selector", selector))
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

// -- High-Level Interaction Methods (implementing schemas.SessionContext) --

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
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		s.domBridge.DispatchEventOnNode(form, "submit")
	})
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
	_, err := s.ExecuteScript(ctx, script, nil)
	return err
}

func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	if milliseconds > 0 {
		return hesitate(ctx, time.Duration(milliseconds)*time.Millisecond)
	}
	return s.stabilize(ctx)
}

// -- JavaScript Integration --

func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	s.mu.Lock()
	s.exposedFunctions[name] = function
	s.mu.Unlock()

	errChan := make(chan error, 1)
	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		errChan <- vm.Set(name, function)
	})
	return <-errChan
}

func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	s.mu.Lock()
	s.persistentScripts = append(s.persistentScripts, script)
	s.mu.Unlock()
	_, err := s.ExecuteScript(ctx, script, nil)
	return err
}

func (s *Session) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	var result interface{}
	err := s.executeScriptInternal(ctx, script, &result)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return json.RawMessage("null"), nil
	}
	return json.Marshal(result)
}

func (s *Session) executeScriptInternal(ctx context.Context, script string, res interface{}) error {
	execCtx, execCancel := CombineContext(s.ctx, ctx)
	defer execCancel()
	resultChan := make(chan struct {
		Value goja.Value
		Error error
	}, 1)

	s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		interrupt := make(chan struct{})
		vm.Interrupt(interrupt)
		go func() {
			select {
			case <-execCtx.Done():
				close(interrupt)
			case <-resultChan:
			}
		}()
		val, err := vm.RunString(script)
		select {
		case resultChan <- struct {
			Value goja.Value
			Error error
		}{val, err}:
		default:
		}
	})

	select {
	case result := <-resultChan:
		if result.Error != nil {
			return fmt.Errorf("javascript execution error: %w", result.Error)
		}
		if res != nil && result.Value != nil && !goja.IsUndefined(result.Value) && !goja.IsNull(result.Value) {
			exportErrChan := make(chan error, 1)
			s.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				exportErrChan <- vm.ExportTo(result.Value, res)
			})
			select {
			case exportErr := <-exportErrChan:
				return exportErr
			case <-execCtx.Done():
				return execCtx.Err()
			}
		}
		return nil
	case <-execCtx.Done():
		return execCtx.Err()
	}
}

// -- Implementation of jsbind.APICallbacks --

func (s *Session) ExecuteFetch(ctx context.Context, reqData schemas.FetchRequest) (*schemas.FetchResponse, error) {
	fetchCtx, fetchCancel := CombineContext(s.ctx, ctx)
	defer fetchCancel()
	resolvedURL, err := s.resolveURL(reqData.URL)
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
	fetchClient.CheckRedirect = nil
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
	cookies := header.Cookies()
	if len(cookies) > 0 {
		s.client.Jar.SetCookies(currentURL, cookies[:1])
	}
	return nil
}

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

func (s *Session) Navigate(targetURL string) {
	go func() {
		if err := s.Navigate(s.ctx, targetURL); err != nil {
			s.logger.Error("JS-initiated navigation failed", zap.Error(err))
		}
	}()
}

func (s *Session) NotifyURLChange(targetURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newURL, err := url.Parse(targetURL)
	if err == nil {
		s.currentURL = newURL
	}
}

func (s *Session) ResolveURL(targetURL string) (*url.URL, error) {
	resolvedURL, err := s.resolveURL(targetURL)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()
	if currentURL != nil && currentURL.String() != "about:blank" {
		currentOrigin := fmt.Sprintf("%s://%s", currentURL.Scheme, currentURL.Host)
		newOrigin := fmt.Sprintf("%s://%s", resolvedURL.Scheme, resolvedURL.Host)
		if currentOrigin != newOrigin {
			return nil, fmt.Errorf("SecurityError: history state URL must be same-origin")
		}
	}
	return resolvedURL, nil
}

// -- humanoid.Executor implementation --

func (s *Session) Sleep(ctx context.Context, d time.Duration) error {
	return hesitate(ctx, d)
}

func (s *Session) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	s.logger.Debug("Dispatching mouse event", zap.Any("data", data))
	return nil
}

func (s *Session) SendKeys(ctx context.Context, keys string) error {
	s.logger.Debug("Sending keys", zap.String("keys", keys))
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

	// Simplified storage collection.
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

func (s *Session) resolveURL(targetURL string) (*url.URL, error) {
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

func (s *Session) prepareRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", s.persona.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", strings.Join(s.persona.Languages, ","))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	if s.currentURL != nil {
		req.Header.Set("Referer", s.currentURL.String())
	}
}

func (s *Session) findElementNode(selector string) (*html.Node, error) {
	s.mu.RLock()
	bridge := s.domBridge
	s.mu.RUnlock()
	if bridge == nil {
		return nil, fmt.Errorf("DOM bridge is not initialized")
	}
	return bridge.QuerySelector(selector)
}

func (s *Session) handleClickConsequence(ctx context.Context, element *html.Node) error {
	if strings.ToLower(element.Data) == "a" {
		if href := htmlquery.SelectAttr(element, "href"); href != "" {
			return s.Navigate(ctx, href)
		}
	}
	// Add other consequences (form submission, etc.) here.
	return nil
}

func (s *Session) submitForm(ctx context.Context, form *html.Node) error {
	// A full implementation would serialize form data and make an HTTP request.
	s.logger.Info("Form submission triggered.", zap.String("action", htmlquery.SelectAttr(form, "action")))
	return nil
}

func findParentForm(element *html.Node) *html.Node {
	for p := element.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && strings.ToLower(p.Data) == "form" {
			return p
		}
	}
	return nil
}

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

func hesitate(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func simulateClickTiming(ctx context.Context, minMs, maxMs int) error {
	if maxMs <= minMs {
		return hesitate(ctx, time.Duration(minMs)*time.Millisecond)
	}
	delay := rand.Intn(maxMs-minMs) + minMs
	return hesitate(ctx, time.Duration(delay)*time.Millisecond)
}

