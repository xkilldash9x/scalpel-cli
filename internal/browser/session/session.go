// Package session implements a functional, headless browser engine in pure Go.
// It integrates a robust network stack, a Go based DOM representation (golang.org/x/net/html),
// and the Goja JavaScript runtime.
//
// CONCURRENCY MODEL:
// This implementation adopts a high-performance, high-concurrency model by managing
// JavaScript runtimes using a sync.Pool. This is the definitive architectural pattern
// for use cases involving frequent, short-lived, and stateless tasks, as it amortizes
// the high cost of VM initialization across many requests.
//
// A new vmManager struct encapsulates the sync.Pool and, critically, a robust Reset
// function. Before any runtime is returned to the pool, this function scrubs it of
// any state from its previous use, preventing data leakage between unrelated operations.
// This reset logic is non-negotiable for security and stability.
//
// The Session struct still serializes high-level, state-altering operations
// (e.g., Navigate, Click) with a mutex (opMu) to ensure logical consistency of the
// session's state (like the current URL). However, individual JavaScript executions
// borrow a runtime from the pool, execute, and return it, allowing for much greater
// parallelism than the previous single-event-loop model.
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

// -- Start of Robust CombineContext implementation --

// combinedContext implements context.Context by wrapping two contexts.
// It is designed to propagate the specific cancellation reason (e.g., DeadlineExceeded)
// from whichever context is canceled first.
type combinedContext struct {
	parentCtx    context.Context
	secondaryCtx context.Context
	done         chan struct{}
	err          error
	mu           sync.Mutex
}

func (c *combinedContext) Deadline() (time.Time, bool) {
	d1, ok1 := c.parentCtx.Deadline()
	d2, ok2 := c.secondaryCtx.Deadline()
	if !ok1 && !ok2 {
		return time.Time{}, false
	}
	if !ok1 {
		return d2, true
	}
	if !ok2 {
		return d1, true
	}
	if d1.Before(d2) {
		return d1, true
	}
	return d2, true
}

func (c *combinedContext) Done() <-chan struct{} {
	return c.done
}

func (c *combinedContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *combinedContext) Value(key interface{}) interface{} {
	if val := c.secondaryCtx.Value(key); val != nil {
		return val
	}
	return c.parentCtx.Value(key)
}

// CombineContext creates a new context that is canceled when either the parent or secondary context is canceled.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	if parentCtx == secondaryCtx || secondaryCtx == context.Background() || secondaryCtx == context.TODO() {
		return context.WithCancel(parentCtx)
	}
	c := &combinedContext{
		parentCtx:    parentCtx,
		secondaryCtx: secondaryCtx,
		done:         make(chan struct{}),
	}
	if err := parentCtx.Err(); err != nil {
		c.err = err
		close(c.done)
		return c, func() {}
	}
	if err := secondaryCtx.Err(); err != nil {
		c.err = err
		close(c.done)
		return c, func() {}
	}
	stop := make(chan struct{}, 1)
	go func() {
		var err error
		select {
		case <-parentCtx.Done():
			err = parentCtx.Err()
		case <-secondaryCtx.Done():
			err = secondaryCtx.Err()
		case <-stop:
			err = context.Canceled
		}
		c.mu.Lock()
		if c.err == nil {
			c.err = err
			close(c.done)
		}
		c.mu.Unlock()
	}()
	cancel := func() {
		select {
		case stop <- struct{}{}:
		case <-c.done:
		}
	}
	return c, cancel
}

// -- End of Robust CombineContext implementation --

// goDebug provides a "breakpoint" that can be called from JavaScript.
// When debugging with Delve, a breakpoint can be set on the first line of this function.
// It allows inspection of JavaScript values from the Go debugger.
func goDebug(call goja.FunctionCall) goja.Value {
	fmt.Println("-- JS DEBUG BREAKPOINT --")
	for i, arg := range call.Arguments {
		// .Export() converts the Goja value to its Go equivalent (map[string]interface{}, etc.)
		fmt.Printf("Arg %d: %#v\n", i, arg.Export())
	}
	// The Go program will pause here if a breakpoint is set.
	// We return `nil` which becomes `undefined` in JavaScript.
	return nil
}

// -- Start of VM Pool Manager --

// PooledRuntime encapsulates a Goja runtime and its dedicated interrupt channel.
// This structure is essential for safe, concurrent execution using context cancellation.
type PooledRuntime struct {
	vm          *goja.Runtime
	interruptCh chan struct{}
}

// vmManager encapsulates a sync.Pool of PooledRuntime instances.
// This is the definitive architectural pattern for high-concurrency, stateless
// JavaScript execution, providing both safety and performance.
type vmManager struct {
	pool       sync.Pool
	logger     *zap.Logger
	baseConfig vmConfig
}

// vmConfig holds the necessary data to initialize or reset a VM.
type vmConfig struct {
	s         *Session // Reference back to the session for console logging etc.
	persona   schemas.Persona
	bindings  map[string]interface{}
	scripts   []string
	domBridge *jsbind.DOMBridge
}

// newVMManager creates a new pool of Goja runtimes.
func newVMManager(logger *zap.Logger, baseConfig vmConfig) *vmManager {
	manager := &vmManager{
		logger:     logger,
		baseConfig: baseConfig,
	}

	manager.pool.New = func() interface{} {
		logger.Debug("Creating new goja.Runtime for pool.")
		vm := goja.New()

		// FIX: Create a dedicated, buffered interrupt channel for this VM.
		// This channel persists for the VM's lifetime. The buffer prevents the watcher
		// goroutine (in executeScriptOnPooledVM) from blocking if the VM isn't currently running.
		// We use this dedicated channel instead of passing ctx.Done() directly to Goja,
		// preventing stale interrupts caused by Goja watching old context channels across pool boundaries.
		interruptCh := make(chan struct{}, 1)
		vm.Interrupt(interruptCh)

		// Perform one-time, expensive initialization.
		manager.initializeVM(vm, baseConfig)

		return &PooledRuntime{
			vm:          vm,
			interruptCh: interruptCh,
		}
	}
	return manager
}

// initializeVM sets up a new Goja runtime with the base environment.
func (m *vmManager) initializeVM(vm *goja.Runtime, cfg vmConfig) {
	// Expose console.log, which will be routed to the session's logger.
	printer := &sessionConsolePrinter{s: cfg.s}
	registry := new(require.Registry) // Corrected type
	registry.RegisterNativeModule("console", console.RequireWithPrinter(printer))
	registry.Enable(vm)

	// Expose our Go "breakpoint" function to the JavaScript environment.
	vm.Set("goDebug", goDebug)

	// Expose browser-like APIs.
	navigator := vm.NewObject()
	_ = navigator.Set("userAgent", cfg.persona.UserAgent)
	_ = navigator.Set("platform", cfg.persona.Platform)
	_ = navigator.Set("languages", cfg.persona.Languages)
	_ = vm.Set("navigator", navigator)

	// Bind the DOM. This must be done for every VM.
	if cfg.domBridge != nil {
		currentURL := cfg.s.GetCurrentURL()
		cfg.domBridge.BindToRuntime(vm, currentURL)
	}

	// Apply persistent functions and scripts.
	for name, function := range cfg.bindings {
		if err := vm.GlobalObject().Set(name, function); err != nil {
			m.logger.Error("Failed to expose persistent function during init", zap.String("name", name), zap.Error(err))
		}
	}
	for _, script := range cfg.scripts {
		if _, err := vm.RunString(script); err != nil {
			m.logger.Warn("Error executing persistent script during init", zap.Error(err))
		}
	}
}

// resetVM is the most critical part of the sync.Pool pattern. It scrubs a runtime
// of state from its previous execution before it can be reused.
func (m *vmManager) resetVM(pr *PooledRuntime, cfg vmConfig) {
	// A failure to clear the interrupt flag is a common source of bugs, rendering
	// the VM unusable for subsequent executions. This is mandatory.
	pr.vm.ClearInterrupt()

	// FIX: Robustly drain the dedicated interrupt channel to ensure no stale signals remain
	// from the previous execution, which could cause spurious interrupts. A simple
	// non-blocking select is not sufficient for all race conditions.
DrainLoop:
	for {
		select {
		case <-pr.interruptCh:
			m.logger.Debug("Drained stale interrupt signal from channel during reset.")
		default:
			// Channel is now empty.
			break DrainLoop
		}
	}

	// After wiping the global scope, we must re-initialize the base environment.
	m.initializeVM(pr.vm, cfg)
}

// Get retrieves a PooledRuntime from the pool.
func (m *vmManager) Get() *PooledRuntime {
	return m.pool.Get().(*PooledRuntime)
}

// Put resets a PooledRuntime and returns it to the pool.
func (m *vmManager) Put(pr *PooledRuntime) {
	// Re-fetch the latest config (e.g., if domBridge was updated) to ensure
	// the reset VM has the most current bindings.
	latestConfig := m.baseConfig
	latestConfig.domBridge = latestConfig.s.getDOMBridge()
	m.resetVM(pr, latestConfig)
	m.pool.Put(pr)
}

// UpdateConfig allows updating the base configuration used to reset VMs.
func (m *vmManager) UpdateConfig(cfg vmConfig) {
	m.baseConfig = cfg
}

// -- End of VM Pool Manager --

// Session represents a single, functional browsing context, equivalent to a tab.
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

	// JavaScript Engine Pool
	vmPool *vmManager

	// Humanoid configuration (Set only if enabled)
	humanoidCfg *humanoid.Config

	// opMu serializes high-level operations (Navigation, Interactions)
	// to ensure logical state consistency.
	opMu sync.Mutex

	// mu protects the internal state variables (fine-grained locking).
	mu         sync.RWMutex
	currentURL *url.URL
	layoutRoot *layout.LayoutBox
	domBridge  *jsbind.DOMBridge

	// History stack implementation
	historyStack []*schemas.HistoryState
	historyIndex int

	// Persistent configuration across navigations
	persistentScripts []string
	exposedFunctions  map[string]interface{}

	// Artifacts
	consoleLogs   []schemas.ConsoleLog
	consoleLogsMu sync.Mutex // Specific mutex for high-frequency access.

	findingsChan chan<- schemas.Finding
	onClose      func()
	closeOnce    sync.Once
}

func (s *Session) acquireOpLock(ctx context.Context) (context.Context, func()) {
	if ctx.Value(operationLockKey) != nil {
		return ctx, func() {}
	}
	select {
	case <-s.ctx.Done():
		return s.ctx, func() {}
	case <-ctx.Done():
		return ctx, func() {}
	default:
	}
	s.opMu.Lock()
	if s.ctx.Err() != nil {
		s.opMu.Unlock()
		return s.ctx, func() {}
	}
	combinedCtx, cancelCombined := CombineContext(s.ctx, ctx)
	lockedCtx := context.WithValue(combinedCtx, operationLockKey, true)
	return lockedCtx, func() {
		cancelCombined()
		s.opMu.Unlock()
	}
}

type sessionConsolePrinter struct {
	s *Session
}

func (p *sessionConsolePrinter) Log(msg string)   { p.s.captureConsoleLog("log", msg) }
func (p *sessionConsolePrinter) Warn(msg string)  { p.s.captureConsoleLog("warn", msg) }
func (p *sessionConsolePrinter) Error(msg string) { p.s.captureConsoleLog("error", msg) }

// Ensure Session implements the required interfaces.
var _ schemas.SessionContext = (*Session)(nil)
var _ jsbind.BrowserEnvironment = (*Session)(nil)
var _ dom.CorePagePrimitives = (*Session)(nil)
var _ humanoid.Executor = (*Session)(nil)

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
		shadowEngine:      &shadowdom.Engine{},
		styleEngine:       style.NewEngine(&shadowdom.Engine{}),
		layoutEngine:      layout.NewEngine(float64(persona.Width), float64(persona.Height)),
		historyStack:      make([]*schemas.HistoryState, 0),
		historyIndex:      -1,
		persistentScripts: make([]string, 0),
		exposedFunctions:  make(map[string]interface{}),
		consoleLogs:       make([]schemas.ConsoleLog, 0),
	}

	// The DOMBridge uses 's' as the BrowserEnvironment.
	s.domBridge = jsbind.NewDOMBridge(log.Named("dom_bridge"), s, s.persona)

	// Initialize the VM pool with the initial session configuration.
	vmCfg := vmConfig{
		s:         s,
		persona:   s.persona,
		bindings:  s.exposedFunctions,
		scripts:   s.persistentScripts,
		domBridge: s.domBridge,
	}
	s.vmPool = newVMManager(log.Named("vm_pool"), vmCfg)

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
		cancel()
		return nil, fmt.Errorf("failed to initialize network stack: %w", err)
	}

	stabilizeFn := func(ctx context.Context) error {
		return s.stabilize(ctx)
	}
	s.interactor = dom.NewInteractor(NewZapAdapter(log.Named("interactor")), domHCfg, stabilizeFn, s)

	// Initialize the state for the initial (empty) document.
	if err := s.resetStateForNewDocument(s.ctx, nil, nil); err != nil {
		s.Close(context.Background())
		return nil, fmt.Errorf("failed to reset state for initial document: %w", err)
	}
	return s, nil
}

func (s *Session) getDOMBridge() *jsbind.DOMBridge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domBridge
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

// resetStateForNewDocument prepares the session for a new page load.
// It assumes the operation lock (s.opMu) is held.
func (s *Session) resetStateForNewDocument(ctx context.Context, doc *html.Node, layoutRoot *layout.LayoutBox) error {
	if doc == nil {
		var err error
		doc, err = html.Parse(strings.NewReader("<html><head></head><body></body></html>"))
		if err != nil {
			s.logger.Error("Critical error: Failed to parse empty HTML document.", zap.Error(err))
			return err
		}
	}

	s.mu.Lock()
	s.layoutRoot = layoutRoot
	s.mu.Unlock()

	// Update the DOM for the DOM bridge.
	if bridge := s.getDOMBridge(); bridge != nil {
		bridge.UpdateDOM(doc)
	}

	// Update the base configuration for the VM pool. Any new or reset VMs
	// will now be initialized with this latest DOM state.
	s.mu.RLock()
	vmCfg := vmConfig{
		s:         s,
		persona:   s.persona,
		bindings:  s.exposedFunctions,
		scripts:   s.persistentScripts,
		domBridge: s.domBridge,
	}
	s.mu.RUnlock()
	s.vmPool.UpdateConfig(vmCfg)

	// Dispatch DOMContentLoaded and load events.
	pr := s.vmPool.Get()
	defer s.vmPool.Put(pr)

	if bridge := s.getDOMBridge(); bridge != nil {
		docNode := bridge.GetDocumentNode()
		bridge.DispatchEventOnNode(docNode, "DOMContentLoaded")
		bridge.DispatchEventOnNode(docNode, "load")
	}

	return nil
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

func (s *Session) Close(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&s.closeStatus, 0, 1) {
		s.logger.Debug("Close called on an already closing session.")
		return nil
	}
	s.logger.Debug("-- Close initiated --")
	s.closeOnce.Do(func() {
		s.logger.Info("Initiating session shutdown.")
		s.cancel()
		s.opMu.Lock()
		defer s.opMu.Unlock()

		// The vmPool itself doesn't need explicit closing, as it's managed by the GC.
		// Nullifying resources is good practice.
		s.mu.Lock()
		s.domBridge = nil
		s.layoutRoot = nil
		s.vmPool = nil
		s.mu.Unlock()

		if s.client != nil {
			s.client.CloseIdleConnections()
		}
		if s.onClose != nil {
			s.onClose()
		}
		s.logger.Info("Session closed.")
	})
	return nil
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
			s.logger.Debug("Network stabilization interrupted.", zap.Error(err))
			return err
		}
	}

	// In a pooled model, there isn't a single event loop to "drain".
	// The short settle time after network idle serves to let any final,
	// brief JS timers (from setTimeout) execute.
	jsSettleTime := 100 * time.Millisecond
	select {
	case <-time.After(jsSettleTime):
	case <-stabCtx.Done():
		return stabCtx.Err()
	}

	s.logger.Debug("Stabilization complete.")
	return nil
}

func (s *Session) Navigate(ctx context.Context, targetURL string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}
	return s.navigateInternal(lockedCtx, targetURL)
}

func (s *Session) navigateInternal(ctx context.Context, targetURL string) error {
	baseNavCtx := ctx

	timeout := s.cfg.Network.NavigationTimeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	requestCtx, requestCancel := context.WithTimeout(baseNavCtx, timeout)
	defer requestCancel()

	resolvedURL, err := s.ResolveURL(targetURL)
	if err != nil {
		return fmt.Errorf("failed to resolve URL '%s': %w", targetURL, err)
	}
	s.logger.Info("Navigating", zap.String("url", resolvedURL.String()))

	// Dispatch 'beforeunload' event.
	s.dispatchEventOnDocument("beforeunload")

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, resolvedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s': %w", resolvedURL.String(), err)
	}
	s.prepareRequestHeaders(req)

	if err := s.executeRequest(requestCtx, req); err != nil {
		return err
	}

	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		if err := s.Sleep(baseNavCtx, 500*time.Millisecond+time.Duration(rand.Intn(1000))*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
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
		return s.processResponse(ctx, resp)
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

func (s *Session) processResponse(ctx context.Context, resp *http.Response) error {
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		s.logger.Warn("Request resulted in error status code", zap.Int("status", resp.StatusCode), zap.String("url", resp.Request.URL.String()))
	}
	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(strings.ToLower(contentType), "text/html")
	var doc *html.Node
	var layoutRoot *layout.LayoutBox
	if isHTML {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		doc, err = htmlquery.Parse(bytes.NewReader(bodyBytes))
		if err != nil {
			s.logger.Error("Failed to parse HTML response.", zap.Error(err), zap.String("url", resp.Request.URL.String()))
			if updateErr := s.updateState(ctx, resp.Request.URL, nil, nil, true); updateErr != nil {
				return fmt.Errorf("failed to update state after parse error: %w", updateErr)
			}
			return nil
		}
		styleEngine := style.NewEngine(s.shadowEngine)
		styleEngine.SetViewport(float64(s.persona.Width), float64(s.persona.Height))
		s.buildAndAddStylesheets(ctx, styleEngine, doc, resp.Request.URL)
		styleTree := styleEngine.BuildTree(doc, nil)
		layoutRoot = s.layoutEngine.BuildAndLayoutTree(styleTree)
	} else {
		s.logger.Debug("Response is not HTML.", zap.String("content_type", contentType))
	}
	if err := s.updateState(ctx, resp.Request.URL, doc, layoutRoot, true); err != nil {
		return fmt.Errorf("failed to update session state: %w", err)
	}
	if isHTML && doc != nil {
		s.executePageScripts(doc)
	}
	return nil
}

func (s *Session) buildAndAddStylesheets(ctx context.Context, styleEngine *style.Engine, doc *html.Node, baseURL *url.URL) {
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
	fetchCtx, fetchCancel := CombineContext(s.ctx, ctx)
	defer fetchCancel()
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
			req, err := http.NewRequestWithContext(fetchCtx, "GET", url, nil)
			if err != nil {
				return
			}
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

func (s *Session) reRender(ctx context.Context) error {
	s.logger.Debug("Initiating re-render.")
	bridge := s.getDOMBridge()
	if bridge == nil {
		return errors.New("session closed: DOM bridge unavailable during re-render")
	}
	htmlContent, err := bridge.GetOuterHTML()
	if err != nil {
		return fmt.Errorf("failed to get outer HTML for re-render: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	doc, err := htmlquery.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return fmt.Errorf("failed to parse HTML during re-render: %w", err)
	}
	s.mu.RLock()
	currentURL := s.currentURL
	persona := s.persona
	s.mu.RUnlock()
	styleEngine := style.NewEngine(s.shadowEngine)
	styleEngine.SetViewport(float64(persona.Width), float64(persona.Height))
	if currentURL != nil {
		s.buildAndAddStylesheets(ctx, styleEngine, doc, currentURL)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	styleTree := styleEngine.BuildTree(doc, nil)
	layoutRoot := s.layoutEngine.BuildAndLayoutTree(styleTree)
	s.mu.Lock()
	s.layoutRoot = layoutRoot
	s.mu.Unlock()
	s.logger.Debug("Re-render complete.")
	return nil
}

func (s *Session) updateState(ctx context.Context, newURL *url.URL, doc *html.Node, layoutRoot *layout.LayoutBox, resetContext bool) error {
	s.mu.Lock()
	s.currentURL = newURL
	title := ""
	if doc != nil {
		if titleNode := htmlquery.FindOne(doc, "//title"); titleNode != nil {
			title = strings.TrimSpace(htmlquery.InnerText(titleNode))
		}
	}
	if resetContext {
		newState := &schemas.HistoryState{
			State: nil,
			Title: title,
			URL:   newURL.String(),
		}
		s.pushHistoryInternal(newState)
	} else {
		if s.historyIndex >= 0 && s.historyIndex < len(s.historyStack) {
			s.historyStack[s.historyIndex].Title = title
		}
	}
	s.mu.Unlock()

	if resetContext {
		if err := s.resetStateForNewDocument(ctx, doc, layoutRoot); err != nil {
			return err
		}
	}

	s.logger.Debug("Session state updated", zap.String("url", newURL.String()), zap.String("title", title), zap.Bool("context_reset", resetContext))
	return nil
}

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
				// We must use a context for script execution, but since this is
				// part of the page load, we use the session's master context.
				_, err := s.executeScriptInternal(s.ctx, scriptContent, nil)
				if err != nil {
					// Check specifically for context interruption, which is expected if the session closes during page load.
					// We no longer check for goja.InterruptedError directly here, as it's wrapped by processScriptResult.
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						s.logger.Debug("Inline script execution interrupted by context.", zap.Error(err))
					} else {
						s.logger.Warn("Error executing inline script", zap.Error(err))
					}
				}
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
		_, execErr := s.executeScriptInternal(s.ctx, string(body), nil)
		if execErr != nil {
			// Check specifically for context interruption.
			if errors.Is(execErr, context.Canceled) || errors.Is(execErr, context.DeadlineExceeded) {
				s.logger.Debug("External script execution interrupted by context.", zap.Error(execErr))
			} else {
				s.logger.Warn("Error executing external script", zap.Error(execErr), zap.String("url", resolvedURL.String()))
			}
		}
	}()
}

func (s *Session) GetDOMSnapshot(ctx context.Context) (io.Reader, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return nil, lockedCtx.Err()
	}
	bridge := s.getDOMBridge()
	if bridge == nil {
		if s.ctx.Err() != nil {
			return nil, s.ctx.Err()
		}
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

func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}
	if len(config.Steps) > 0 {
		return s.executeStepsInternal(lockedCtx, config.Steps)
	}
	if config.MaxDepth <= 0 && config.MaxInteractionsPerDepth <= 0 {
		config = dom.NewDefaultInteractionConfig()
	}
	if config.MaxDepth > 0 {
		return s.recursiveInteractInternal(lockedCtx, config)
	}
	return nil
}

func (s *Session) executeStepsInternal(ctx context.Context, steps []schemas.InteractionStep) error {
	for _, step := range steps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.logger.Info("Executing interaction step", zap.String("action", string(step.Action)), zap.String("selector", step.Selector))

		needsStabilization := true
		needsRendering := true
		useHumanoid := s.humanoidCfg != nil

		switch step.Action {
		case schemas.ActionClick:
			if useHumanoid {
				if err := s.humanoidController.IntelligentClick(ctx, step.Selector, nil); err != nil {
					return fmt.Errorf("failed to execute click on '%s': %w", step.Selector, err)
				}
			} else {
				if err := s.executeClickInternal(ctx, step.Selector, 0, 0); err != nil {
					return fmt.Errorf("failed to execute click on '%s': %w", step.Selector, err)
				}
			}
		case schemas.ActionType:
			if useHumanoid {
				if err := s.humanoidController.Type(ctx, step.Selector, step.Value, nil); err != nil {
					return fmt.Errorf("failed to execute type on '%s': %w", step.Selector, err)
				}
			} else {
				if err := s.executeTypeInternal(ctx, step.Selector, step.Value, 0); err != nil {
					return fmt.Errorf("failed to execute type on '%s': %w", step.Selector, err)
				}
			}
		case schemas.ActionNavigate:
			if err := s.navigateInternal(ctx, step.Value); err != nil {
				return fmt.Errorf("failed to navigate to '%s': %w", step.Value, err)
			}
			needsRendering = false
		case schemas.ActionWait:
			if step.Milliseconds > 0 {
				if err := s.Sleep(ctx, time.Duration(step.Milliseconds)*time.Millisecond); err != nil {
					return err
				}
				needsStabilization = false
			} else {
				if err := s.stabilize(ctx); err != nil {
					return err
				}
				needsStabilization = false
			}
		case schemas.ActionSelect:
			if err := s.executeSelectInternal(ctx, step.Selector, step.Value); err != nil {
				return fmt.Errorf("failed to execute select on '%s': %w", step.Selector, err)
			}
		case schemas.ActionSubmit:
			if useHumanoid {
				if err := s.humanoidController.IntelligentClick(ctx, step.Selector, nil); err != nil {
					return fmt.Errorf("failed to execute submit (via click) on '%s': %w", step.Selector, err)
				}
			} else {
				if err := s.executeClickInternal(ctx, step.Selector, 0, 0); err != nil {
					return fmt.Errorf("failed to execute submit (via click) on '%s': %w", step.Selector, err)
				}
			}
			needsRendering = false
		default:
			return fmt.Errorf("unsupported interaction action: %s", step.Action)
		}
		if needsStabilization {
			if err := s.stabilize(ctx); err != nil {
				return err
			}
		}
		if needsRendering {
			if err := s.reRender(ctx); err != nil {
				s.logger.Warn("Failed to re-render after interaction step, proceeding with potentially stale layout.", zap.Error(err))
			}
		}
	}
	return nil
}

func (s *Session) recursiveInteractInternal(ctx context.Context, config schemas.InteractionConfig) error {
	s.logger.Info("Starting recursive interaction loop.", zap.Int("MaxDepth", config.MaxDepth), zap.Int("MaxInteractionsPerDepth", config.MaxInteractionsPerDepth))
	interactedElements := make(map[string]bool)
	maxTotalInteractions := config.MaxDepth * config.MaxInteractionsPerDepth
	if maxTotalInteractions <= 0 {
		maxTotalInteractions = config.MaxDepth
		if config.MaxInteractionsPerDepth > 0 {
			maxTotalInteractions = config.MaxInteractionsPerDepth
		}
	}
	interactionsCount := 0
	for interactionsCount < maxTotalInteractions {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.mu.RLock()
		layoutRoot := s.layoutRoot
		s.mu.RUnlock()
		if layoutRoot == nil {
			s.logger.Warn("Layout root is nil before exploration step, stopping.")
			break
		}
		interacted, err := s.interactor.ExploreStep(ctx, config, layoutRoot, interactedElements)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return err
			}
			s.logger.Warn("Error during exploration step, stopping.", zap.Error(err))
			break
		}
		if !interacted {
			s.logger.Info("No new interactions found, stopping exploration.")
			break
		}
		interactionsCount++
		s.logger.Debug("Interaction successful, proceeding to stabilization and re-render.", zap.Int("count", interactionsCount))
		if err := s.stabilize(ctx); err != nil {
			return err
		}
		if err := s.reRender(ctx); err != nil {
			s.logger.Warn("Failed to re-render during recursive interaction, stopping.", zap.Error(err))
			break
		}
	}
	s.logger.Info("Recursive interaction loop finished.", zap.Int("total_interactions", interactionsCount))
	return nil
}

func (s *Session) Click(ctx context.Context, selector string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}
	if s.humanoidCfg != nil {
		if err := s.humanoidController.IntelligentClick(lockedCtx, selector, nil); err != nil {
			return err
		}
	} else {
		if err := s.executeClickInternal(lockedCtx, selector, 0, 0); err != nil {
			return err
		}
	}
	if err := s.stabilize(lockedCtx); err != nil {
		return err
	}
	return s.reRender(lockedCtx)
}

func (s *Session) Type(ctx context.Context, selector string, text string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}
	if s.humanoidCfg != nil {
		if err := s.humanoidController.Type(lockedCtx, selector, text, nil); err != nil {
			return err
		}
	} else {
		if err := s.executeTypeInternal(lockedCtx, selector, text, 0); err != nil {
			return err
		}
	}
	if err := s.stabilize(lockedCtx); err != nil {
		return err
	}
	return s.reRender(lockedCtx)
}

func (s *Session) Submit(ctx context.Context, selector string) error {
	return s.Click(ctx, selector)
}

func (s *Session) ScrollPage(ctx context.Context, direction string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}

	// If humanoid mode is enabled, delegate to the humanoid controller
	// for realistic scrolling by moving to a target at the page ends.
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		s.logger.Debug("Executing humanoid scroll", zap.String("direction", direction))
		var targetSelector string
		switch strings.ToLower(direction) {
		case "down", "bottom":
			// Select the last element in the body as the scroll target.
			targetSelector = "(//body//*[not(self::script or self::style or self::noscript or self::meta or self::link)])[last()]"
		case "up", "top":
			// Select the first element in the body as the scroll target.
			targetSelector = "(//body//*[not(self::script or self::style or self::noscript or self::meta or self::link)])[1]"
		default:
			return fmt.Errorf("unsupported scroll direction for humanoid mode: %s", direction)
		}
		// Use MoveTo to trigger the intelligent scrolling logic within the humanoid package.
		// Passing nil for options uses the default behavior, which includes ensuring the element is visible.
		return s.humanoidController.MoveTo(lockedCtx, targetSelector, nil)
	}

	// Fallback to programmatic scrolling if humanoid is disabled.
	s.logger.Debug("Executing programmatic scroll", zap.String("direction", direction))
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

func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.waitForAsyncInternal(lockedCtx, milliseconds)
}

func (s *Session) waitForAsyncInternal(ctx context.Context, milliseconds int) error {
	if milliseconds > 0 {
		return s.Sleep(ctx, time.Duration(milliseconds)*time.Millisecond)
	}
	return s.stabilize(ctx)
}

func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.exposeFunctionInternal(lockedCtx, name, function)
}

func (s *Session) exposeFunctionInternal(ctx context.Context, name string, function interface{}) error {
	s.mu.Lock()
	s.exposedFunctions[name] = function
	s.mu.Unlock()

	// Update the base config for the pool so new/reset VMs get the function.
	s.mu.RLock()
	vmCfg := s.vmPool.baseConfig
	vmCfg.bindings = s.exposedFunctions
	s.mu.RUnlock()
	s.vmPool.UpdateConfig(vmCfg)

	// We don't need to inject into a "current" VM anymore, as there isn't one.
	// The next VM taken from the pool will have it.
	return nil
}

func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.injectScriptPersistentlyInternal(lockedCtx, script)
}

func (s *Session) injectScriptPersistentlyInternal(ctx context.Context, script string) error {
	s.mu.Lock()
	s.persistentScripts = append(s.persistentScripts, script)
	s.mu.Unlock()

	// Update the base config for the pool.
	s.mu.RLock()
	vmCfg := s.vmPool.baseConfig
	vmCfg.scripts = s.persistentScripts
	s.mu.RUnlock()
	s.vmPool.UpdateConfig(vmCfg)

	// Execute immediately in a temporary VM to validate it and apply to current state.
	_, err := s.executeScriptInternal(ctx, script, nil)
	return err
}

func (s *Session) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return nil, lockedCtx.Err()
	}
	return s.executeScriptInternal(lockedCtx, script, args)
}

func (s *Session) executeScriptInternal(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	var result interface{}
	err := s.executeScriptOnPooledVM(ctx, script, &result, args)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return json.RawMessage("null"), nil
	}
	jsonData, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal javascript result: %w", err)
	}
	return json.RawMessage(jsonData), nil
}

// executeScriptOnPooledVM handles the full lifecycle of borrowing, using, and
// returning a VM from the pool for a single script execution.
func (s *Session) executeScriptOnPooledVM(ctx context.Context, script string, res interface{}, args []interface{}) (err error) {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	if s.vmPool == nil {
		return errors.New("session closed: vmPool unavailable")
	}

	// Get the PooledRuntime (VM + dedicated interrupt channel)
	pr := s.vmPool.Get()
	vm := pr.vm
	interruptCh := pr.interruptCh

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in javascript execution: %v", r)
			s.logger.Error("Recovered from panic in javascript execution", zap.Error(err), zap.String("stack", string(debug.Stack())))
		}
		// The defer ensures the VM is always returned to the pool.
		// vmPool.Put handles resetVM (ClearInterrupt and draining the channel).
		s.vmPool.Put(pr)
	}()

	// Combine the session context and the specific execution context.
	execCtx, cancelExec := CombineContext(s.ctx, ctx)

	// FIX: Start a watcher goroutine to bridge the context cancellation to the VM's dedicated interrupt channel.
	// This pattern prevents stale interrupts by ensuring the context monitoring stops as soon as the execution finishes.
	executionFinished := make(chan struct{})
	go func() {
		select {
		case <-execCtx.Done():
			// Context cancelled externally (timeout, session close, etc.). Signal the interrupt.
			select {
			case interruptCh <- struct{}{}:
			// Signalled successfully.
			default:
				// Channel full (buffer size 1), interrupt already pending.
			}
		case <-executionFinished:
			// Execution finished normally. Do nothing, do not signal interrupt.
		}
	}()

	// Ensure the watcher goroutine stops and the combined context is cancelled when finished.
	defer func() {
		close(executionFinished)
		cancelExec()
	}()

	// Expose arguments for this specific execution.
	if err := vm.Set("arguments", args); err != nil {
		return fmt.Errorf("failed to set script arguments: %w", err)
	}

	val, err := vm.RunString(script)

	// Use the execution context (execCtx) when processing the result, as this
	// is the context that would have triggered the interrupt if one occurred due to cancellation.
	if err != nil {
		// processScriptResult handles wrapping Goja errors into Go errors.
		return s.processScriptResult(execCtx, val, err, res)
	}

	return s.processScriptResult(execCtx, val, nil, res)
}

func (s *Session) waitForPromise(ctx context.Context, promise *goja.Promise) (goja.Value, error) {
	// Polling is a viable strategy for waiting on promises when there's no event loop.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			switch promise.State() {
			case goja.PromiseStateFulfilled:
				return promise.Result(), nil
			case goja.PromiseStateRejected:
				err := fmt.Errorf("javascript promise rejected: %v", promise.Result().Export())
				return nil, err
			case goja.PromiseStatePending:
				// Continue polling
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("context canceled while waiting for promise: %w", ctx.Err())
		}
	}
}

func (s *Session) processScriptResult(ctx context.Context, value goja.Value, err error, res interface{}) error {
	if err != nil {
		var gojaException *goja.Exception
		var interruptedError *goja.InterruptedError

		// Check for interruption first.
		if errors.As(err, &interruptedError) {
			// FIX: Use a non-blocking select to verify the cause of the interrupt.
			// This resolves the original panic (race condition on ctx.Err() population)
			// and the subsequent deadlock (blocking wait on ctx.Done()).
			select {
			case <-ctx.Done():
				// Context is cancelled. This is the expected path for timeouts/cancellations.
				// The receive operation ensures synchronization, so ctx.Err() should be populated.
				ctxErr := ctx.Err()
				if ctxErr == nil {
					// Highly unlikely if <-ctx.Done() returned, but defensively handle it.
					s.logger.Warn("Context is done but Err() is nil after interrupt.")
					ctxErr = context.Canceled
				}
				return fmt.Errorf("javascript execution interrupted by context: %w", ctxErr)
			default:
				// Context is not cancelled. This indicates an unexpected interrupt.
				// With the dedicated channel fix, this should ideally not happen.
				s.logger.Error("CRITICAL: Javascript execution interrupted, but context is not cancelled. Unexpected interrupt detected.", zap.Error(interruptedError))
				return fmt.Errorf("javascript execution interrupted unexpectedly: %w", interruptedError)
			}
		}

		// Check for a standard JS exception.
		if errors.As(err, &gojaException) {
			return fmt.Errorf("javascript exception: %s", gojaException.String())
		}
		// Fallback for other errors.
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
		// Using a throwaway VM for export is a safe way to avoid any potential
		// state conflicts on the original VM, which is about to be returned to the pool.
		return goja.New().ExportTo(value, res)
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

func (s *Session) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeClickInternal(lockedCtx, selector, minMs, maxMs)
}

func (s *Session) executeClickInternal(ctx context.Context, selector string, minMs, maxMs int) error {
	element, err := s.findElementNode(ctx, selector)
	if err != nil {
		return err
	}
	if minMs > 0 || maxMs > 0 {
		if err := simulateClickTiming(ctx, minMs, maxMs); err != nil {
			return err
		}
	}
	err = s.handleClickConsequenceInternal(ctx, element)
	s.dispatchEventOnNode(element, "click")
	return err
}

func (s *Session) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeTypeInternal(lockedCtx, selector, text, holdMeanMs)
}

func (s *Session) executeTypeInternal(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	element, err := s.findElementNode(ctx, selector)
	if err != nil {
		return err
	}
	s.dispatchEventOnNode(element, "focus")

	// FIX: Get the initial value by reading the attribute directly from the Go html.Node.
	// This avoids using document.querySelector, which doesn't support XPath.
	currentValue, _ := getAttr(element, "value")

	holdVariance := 15.0
	interKeyMeanMs := 100.0
	interKeyVariance := 40.0
	var rng *rand.Rand
	if holdMeanMs > 0 {
		rng = getRNG()
		defer putRNG(rng)
	}
	for i, char := range text {
		if holdMeanMs > 0 {
			holdMs := rng.NormFloat64()*holdVariance + holdMeanMs
			if holdMs < 20 {
				holdMs = 20
			}
			if err := hesitate(ctx, time.Duration(holdMs)*time.Millisecond); err != nil {
				return err
			}
		}
		currentValue += string(char)

		// FIX: Set the new value by modifying the attribute directly on the Go html.Node.
		// This is selector-agnostic and avoids the incorrect document.querySelector call.
		addAttr(element, "value", currentValue)

		s.dispatchEventOnNode(element, "keydown")
		s.dispatchEventOnNode(element, "keypress")
		s.dispatchEventOnNode(element, "input")
		s.dispatchEventOnNode(element, "keyup")

		if holdMeanMs > 0 && i < len(text)-1 {
			interKeyMs := rng.NormFloat64()*interKeyVariance + interKeyMeanMs
			if interKeyMs < 30 {
				interKeyMs = 30
			}
			if err := hesitate(ctx, time.Duration(interKeyMs)*time.Millisecond); err != nil {
				return err
			}
		}
	}
	s.dispatchEventOnNode(element, "blur")
	return nil
}

func (s *Session) ExecuteSelect(ctx context.Context, selector string, value string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeSelectInternal(lockedCtx, selector, value)
}

func (s *Session) executeSelectInternal(ctx context.Context, selector string, value string) error {
	selectNode, err := s.findElementNode(ctx, selector)
	if err != nil {
		return err
	}
	if strings.ToLower(selectNode.Data) != "select" {
		return fmt.Errorf("element '%s' is not a select element", selector)
	}

	// This action is complex to achieve by manipulating Go nodes alone,
	// as it involves finding the correct option and updating the 'selected'
	// property on potentially multiple nodes. Falling back to a script is
	// a pragmatic and reliable choice here, but it requires a CSS selector.
	// We will attempt to use a script and if it fails, it indicates an XPath selector was likely used.
	// NOTE: This highlights a limitation when mixing selector strategies.
	escapedSelector := strings.ReplaceAll(selector, "'", "\\'")
	escapedValue := strings.ReplaceAll(strings.ReplaceAll(value, "'", "\\'"), `\`, `\\`)
	script := fmt.Sprintf(`
        (function() {
            try {
                const select = document.querySelector('%s');
                if (!select) { return false; }
                select.value = '%s';
                // Trigger events after setting value
                select.dispatchEvent(new Event('input', { bubbles: true }));
                select.dispatchEvent(new Event('change', { bubbles: true }));
                return select.value === '%s';
            } catch (e) {
                // This will catch syntax errors if an XPath is passed.
                return false;
            }
        })()
    `, escapedSelector, escapedValue, escapedValue)

	resultRaw, err := s.executeScriptInternal(ctx, script, nil)
	if err != nil {
		return fmt.Errorf("script to set select value failed for '%s': %w", selector, err)
	}

	var scriptSuccess bool
	if err := json.Unmarshal(resultRaw, &scriptSuccess); err != nil || !scriptSuccess {
		// If the script fails, fall back to direct DOM manipulation,
		// which works better with XPath but is more complex.
		s.logger.Debug("JS select failed, falling back to DOM manipulation", zap.String("selector", selector))
		var matched bool
		for option := selectNode.FirstChild; option != nil; option = option.NextSibling {
			if strings.ToLower(option.Data) == "option" {
				if val, _ := getAttr(option, "value"); val == value {
					addAttr(option, "selected", "")
					matched = true
				} else {
					removeAttr(option, "selected")
				}
			}
		}
		if !matched {
			return fmt.Errorf("option with value '%s' not found for selector '%s'", value, selector)
		}
	}

	s.dispatchEventOnNode(selectNode, "input")
	s.dispatchEventOnNode(selectNode, "change")
	return nil
}

func (s *Session) IsVisible(ctx context.Context, selector string) bool {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.isVisibleInternal(lockedCtx, selector)
}

func (s *Session) isVisibleInternal(_ context.Context, selector string) bool {
	s.mu.RLock()
	currentLayoutRoot := s.layoutRoot
	s.mu.RUnlock()
	if currentLayoutRoot == nil {
		return false
	}
	geo, err := s.layoutEngine.GetElementGeometry(currentLayoutRoot, selector)
	return err == nil && geo != nil
}

func (s *Session) JSNavigate(targetURL string) {
	go func() {
		if err := s.Navigate(s.ctx, targetURL); err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				s.logger.Error("JS initiated navigation failed", zap.Error(err))
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
	res := http.Response{Header: header}
	cookies := res.Cookies()
	if len(cookies) > 0 {
		s.client.Jar.SetCookies(currentURL, cookies)
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
		if targetURL == "" {
			return nil, nil
		}
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

func (s *Session) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	if data.Type == schemas.MouseRelease {
		lockedCtx, unlock := s.acquireOpLock(ctx)
		defer unlock()
		if lockedCtx.Err() != nil {
			return lockedCtx.Err()
		}
		bridge := s.getDOMBridge()
		if bridge == nil {
			return errors.New("session is closed, DOM bridge unavailable")
		}
		hitNode := bridge.FindNodeAtPoint(data.X, data.Y)
		if hitNode != nil {
			err := s.handleClickConsequenceInternal(lockedCtx, hitNode)
			s.dispatchEventOnNode(hitNode, "click")
			return err
		}
	}
	return nil
}

func (s *Session) SendKeys(ctx context.Context, keys string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}
	// To send keys to the page without a specific target, we can target the 'body'.
	// The browser will route the key events to the currently focused element (document.activeElement).
	// This simulates a user typing without first clicking on an input.
	if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
		// The humanoid 'Type' action first focuses the element, which isn't quite what SendKeys does.
		// For now, we fall back to the direct execution, which is a closer match.
		// A future improvement could be a dedicated Humanoid.SendKeys method.
		return s.executeTypeInternal(lockedCtx, "body", keys, s.humanoidCfg.KeyHoldMeanMs)
	}
	return s.executeTypeInternal(lockedCtx, "body", keys, 0)
}

func (s *Session) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.getElementGeometryInternal(lockedCtx, selector)
}

func (s *Session) getElementGeometryInternal(_ context.Context, selector string) (*schemas.ElementGeometry, error) {
	s.mu.RLock()
	currentLayoutRoot := s.layoutRoot
	s.mu.RUnlock()
	if currentLayoutRoot == nil {
		return nil, fmt.Errorf("layout tree not available")
	}
	return s.layoutEngine.GetElementGeometry(currentLayoutRoot, selector)
}

func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.collectArtifactsInternal(lockedCtx)
}

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
	bridge := s.getDOMBridge()
	if bridge != nil {
		htmlContent, err := bridge.GetOuterHTML()
		if err == nil {
			artifacts.DOM = htmlContent
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	artifacts.Storage = schemas.StorageState{}
	return artifacts, nil
}

func (s *Session) AddFinding(ctx context.Context, finding schemas.Finding) error {
	if s.findingsChan != nil {
		if finding.Timestamp.IsZero() {
			finding.Timestamp = time.Now()
		}
		select {
		case s.findingsChan <- finding:
			return nil
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
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
	if req.Header.Get("Referer") == "" {
		s.mu.RLock()
		currentURL := s.currentURL
		s.mu.RUnlock()
		if currentURL != nil {
			req.Header.Set("Referer", currentURL.String())
		}
	}
}

// findElementNode queries the DOM to find a specific element.
// It borrows a VM from the pool just to access the DOM bridge's query functionality.
func (s *Session) findElementNode(ctx context.Context, selector string) (*html.Node, error) {
	bridge := s.getDOMBridge()
	if bridge == nil {
		return nil, fmt.Errorf("DOM bridge is not initialized or session is closed")
	}

	// The QuerySelector is thread safe on the bridge itself as it only reads
	// from the *html.Node tree, which is protected by the higher level opMu.
	// Therefore, we do not need to borrow a VM just for this read operation.
	node, err := bridge.QuerySelector(selector)
	if err != nil {
		return nil, fmt.Errorf("failed to find element '%s': %w", selector, err)
	}
	if node == nil {
		return nil, fmt.Errorf("element not found for selector: %s", selector)
	}
	return node, nil
}

// dispatchEventOnNode is a helper to dispatch a simple event on a node.
func (s *Session) dispatchEventOnNode(node *html.Node, eventType string) {
	// Updated to use PooledRuntime
	pr := s.vmPool.Get()
	defer s.vmPool.Put(pr)
	if bridge := s.getDOMBridge(); bridge != nil {
		bridge.DispatchEventOnNode(node, eventType)
	}
}

// dispatchEventOnDocument is a helper for document-level events.
func (s *Session) dispatchEventOnDocument(eventType string) {
	// Updated to use PooledRuntime
	pr := s.vmPool.Get()
	defer s.vmPool.Put(pr)
	if bridge := s.getDOMBridge(); bridge != nil {
		docNode := bridge.GetDocumentNode()
		bridge.DispatchEventOnNode(docNode, eventType)
	}
}

func (s *Session) handleClickConsequenceInternal(ctx context.Context, element *html.Node) error {
	bridge := s.getDOMBridge()
	if bridge == nil {
		return errors.New("session closed")
	}
	tagName := strings.ToLower(element.Data)

	if tagName == "input" {
		inputType := strings.ToLower(htmlquery.SelectAttr(element, "type"))
		if inputType == "checkbox" {
			bridge.Lock()
			if _, isChecked := getAttr(element, "checked"); isChecked {
				removeAttr(element, "checked")
			} else {
				addAttr(element, "checked", "checked")
			}
			bridge.Unlock()
			return nil
		}
		if inputType == "radio" {
			bridge.Lock()
			radioName := htmlquery.SelectAttr(element, "name")
			if radioName != "" {
				root := element
				for root.Parent != nil {
					root = root.Parent
				}
				radios := htmlquery.Find(root, fmt.Sprintf(`//input[@type='radio' and @name='%s']`, radioName))
				for _, radio := range radios {
					removeAttr(radio, "checked")
				}
			}
			addAttr(element, "checked", "checked")
			bridge.Unlock()
			return nil
		}
	}

	anchor := element
	for anchor != nil && strings.ToLower(anchor.Data) != "a" {
		anchor = anchor.Parent
	}
	if anchor != nil {
		if href := htmlquery.SelectAttr(anchor, "href"); href != "" {
			return s.navigateInternal(ctx, href)
		}
	}

	form := findParentForm(element)
	if form != nil {
		isSubmitButton := false
		if tagName == "button" {
			btnType := strings.ToLower(htmlquery.SelectAttr(element, "type"))
			if btnType == "submit" || btnType == "" {
				isSubmitButton = true
			}
		}
		if tagName == "input" && strings.ToLower(htmlquery.SelectAttr(element, "type")) == "submit" {
			isSubmitButton = true
		}
		if isSubmitButton {
			return s.submitFormInternal(ctx, form)
		}
	}
	return nil
}

func (s *Session) submitFormInternal(ctx context.Context, form *html.Node) error {
	action := htmlquery.SelectAttr(form, "action")
	method := strings.ToUpper(htmlquery.SelectAttr(form, "method"))
	enctype := htmlquery.SelectAttr(form, "enctype")
	if method == "" {
		method = http.MethodGet
	}
	if enctype == "" {
		enctype = "application/x-www-form-urlencoded"
	}
	formData := url.Values{}

	// Since we are just reading attributes from the DOM, this part is safe
	// to do without borrowing a VM, as opMu protects the DOM structure.
	inputs := htmlquery.Find(form, ".//input | .//textarea | .//select")
	for _, input := range inputs {
		name := htmlquery.SelectAttr(input, "name")
		if name == "" {
			continue
		}
		if _, disabled := getAttr(input, "disabled"); disabled {
			continue
		}
		tagName := strings.ToLower(input.Data)
		switch tagName {
		case "input":
			inputType := strings.ToLower(htmlquery.SelectAttr(input, "type"))
			if inputType == "checkbox" || inputType == "radio" {
				if _, checked := getAttr(input, "checked"); checked {
					value, exists := getAttr(input, "value")
					if !exists {
						value = "on"
					}
					formData.Add(name, value)
				}
			} else if inputType != "submit" && inputType != "reset" && inputType != "button" && inputType != "image" {
				formData.Add(name, htmlquery.SelectAttr(input, "value"))
			}
		case "textarea":
			formData.Add(name, htmlquery.InnerText(input))
		case "select":
			// For select, we need the JS property, which requires a VM.
			var selectedValue string
			var found bool
			options := htmlquery.Find(input, ".//option")
			for _, opt := range options {
				if _, selected := getAttr(opt, "selected"); selected {
					selectedValue = htmlquery.SelectAttr(opt, "value")
					found = true
					break
				}
			}
			if found {
				formData.Add(name, selectedValue)
			}
		}
	}

	targetURL, err := s.ResolveURL(action)
	if err != nil || targetURL == nil {
		targetURL, _ = s.ResolveURL("")
		if targetURL == nil {
			return fmt.Errorf("failed to resolve form action URL (%s) and no current URL available: %w", action, err)
		}
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
	} else {
		submitURL := *targetURL
		q := submitURL.Query()
		for key, values := range formData {
			for _, value := range values {
				q.Add(key, value)
			}
		}
		submitURL.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, method, submitURL.String(), nil)
		if err != nil {
			return err
		}
	}
	s.prepareRequestHeaders(req)
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

func addAttr(n *html.Node, key, val string) {
	if n == nil {
		return
	}
	for i := range n.Attr {
		if n.Attr[i].Key == key {
			n.Attr[i].Val = val
			return
		}
	}
	n.Attr = append(n.Attr, html.Attribute{Key: key, Val: val})
}

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
	if formID := htmlquery.SelectAttr(element, "form"); formID != "" {
		root := element
		for root.Parent != nil {
			root = root.Parent
		}
		if form := htmlquery.FindOne(root, fmt.Sprintf("//form[@id='%s']", formID)); form != nil {
			return form
		}
	}
	for p := element.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && strings.ToLower(p.Data) == "form" {
			return p
		}
	}
	return nil
}

