// Package session implements a functional, headless browser engine in pure Go.
// It integrates a robust network stack, a Go based DOM representation (golang.org/x/net/html),
// and the Goja JavaScript runtime.
//
// CONCURRENCY MODEL:
// This implementation adopts a high performance, high concurrency model by managing
// JavaScript runtimes using a buffered channel pool. This is a robust
// architectural pattern as Goja runtimes are not goroutine safe, and this
// pattern allows for context aware acquisition, preventing resource exhaustion deadlocks.
//
// The vmManager encapsulates the pool and ensures that each VM is reset (Reset on Get) to the current
// session state upon acquisition, guaranteeing isolation and preventing state leakage.
//
// Script execution uses the Synchronized Interrupt Pattern in executeScriptOnPooledVM
// to ensure that cancellations (via context.Context) are handled safely without causing race conditions
// or "poisoning" VMs in the pool.
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
	"runtime"
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

// opLockKey is a context key for managing operation lock re entrancy.
type opLockKey struct{}

var operationLockKey = opLockKey{}

// Defines a default size for the VM pool if not configured.
// Using a multiple of NumCPU is a reasonable starting point for I/O bound tasks.
var defaultVMPoolSize = runtime.NumCPU() * 4

// -- Robust CombineContext implementation --

// combinedContext implements context.Context by wrapping two contexts.
// It is designed to propagate the specific cancellation reason (e.g., DeadlineExceeded)
// from whichever context is canceled first. This is more robust than a simple
// select, which can lose the specific error.
type combinedContext struct {
	parentCtx    context.Context
	secondaryCtx context.Context
	done         chan struct{}
	err          error
	mu           sync.Mutex
}

// Deadline returns the earlier deadline of the two wrapped contexts.
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

// Done returns a channel that is closed when either of the wrapped contexts is canceled.
func (c *combinedContext) Done() <-chan struct{} {
	return c.done
}

// Err returns the cancellation error from the first context that was canceled.
func (c *combinedContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Value retrieves a value from the contexts, prioritizing the secondary context.
func (c *combinedContext) Value(key interface{}) interface{} {
	if val := c.secondaryCtx.Value(key); val != nil {
		return val
	}
	return c.parentCtx.Value(key)
}

// CombineContext creates a new context that is canceled when either the parent or secondary context is canceled.
// It returns the combined context and a cancel function that can be used to explicitly cancel it.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	if parentCtx == secondaryCtx || secondaryCtx == context.Background() || secondaryCtx == context.TODO() {
		return context.WithCancel(parentCtx)
	}
	c := &combinedContext{
		parentCtx:    parentCtx,
		secondaryCtx: secondaryCtx,
		done:         make(chan struct{}),
	}

	// Preemptively check if either context is already canceled.
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

// -- VM Pool Manager --

// vmManager manages a pool of goja.Runtime instances using a buffered channel.
// This approach avoids the overhead of creating new VMs for each script execution and
// ensures that VMs are not used concurrently, as Goja runtimes are not goroutine safe.
type vmManager struct {
	vms      chan *goja.Runtime
	logger   *zap.Logger
	configMu sync.RWMutex
	// baseConfig holds the configuration used to initialize or reset VMs.
	baseConfig vmConfig
}

// vmConfig holds the necessary data to initialize or reset a VM's state.
// This ensures that when a VM is retrieved from the pool, it reflects the
// current state of the browser session (e.g., current DOM, exposed functions).
type vmConfig struct {
	s        *Session // Reference back to the session for console logging etc.
	persona  schemas.Persona
	bindings map[string]interface{}
	scripts  []string
	// NOTE: domBridge is not stored here directly as it changes frequently. It's fetched during reset/Get.
}

// newVMManager creates and initializes a new pool of Goja runtimes.
// It pre warms the pool by creating all VMs upfront, making subsequent acquisitions faster.
func newVMManager(logger *zap.Logger, baseConfig vmConfig, poolSize int) (*vmManager, error) {
	if poolSize <= 0 {
		poolSize = defaultVMPoolSize
	}

	manager := &vmManager{
		vms:        make(chan *goja.Runtime, poolSize),
		logger:     logger,
		baseConfig: baseConfig,
	}

	// Initialize the pool synchronously.
	for i := 0; i < poolSize; i++ {
		logger.Debug("Creating new goja.Runtime for pool.", zap.Int("vm_id", i))
		vm := goja.New()
		// Perform initial setup using the baseConfig and the initial DOM bridge.
		initialDomBridge := baseConfig.s.getDOMBridge()
		if err := manager.initializeVM(vm, baseConfig, initialDomBridge); err != nil {
			manager.Close() // Clean up already created VMs.
			return nil, fmt.Errorf("failed to initialize VM %d: %w", i, err)
		}
		manager.vms <- vm
	}

	return manager, nil
}

// initializeVM sets up a Goja runtime with the specified environment configuration.
// This is the core of the "Reset-on-Get" pattern, called during both initial
// creation and on every subsequent Get() to ensure a clean, up to date state.
func (m *vmManager) initializeVM(vm *goja.Runtime, cfg vmConfig, domBridge *jsbind.DOMBridge) error {
	// Expose console.log, .warn, etc.
	if cfg.s != nil {
		printer := &sessionConsolePrinter{s: cfg.s}
		registry := new(require.Registry)
		registry.RegisterNativeModule("console", console.RequireWithPrinter(printer))
		registry.Enable(vm)
	}

	// Expose browser like APIs (e.g., Navigator).
	navigator := vm.NewObject()
	_ = navigator.Set("userAgent", cfg.persona.UserAgent)
	_ = navigator.Set("platform", cfg.persona.Platform)
	_ = navigator.Set("languages", cfg.persona.Languages)
	_ = vm.Set("navigator", navigator)

	// Bind the DOM. This must reflect the current DOMBridge for the session.
	if domBridge != nil && cfg.s != nil {
		currentURL := cfg.s.GetCurrentURL()
		domBridge.BindToRuntime(vm, currentURL)
	}

	// Apply persistent functions and scripts.
	for name, function := range cfg.bindings {
		if err := vm.GlobalObject().Set(name, function); err != nil {
			m.logger.Error("Failed to expose persistent function during init/reset", zap.String("name", name), zap.Error(err))
			return fmt.Errorf("failed to set binding '%s': %w", name, err)
		}
	}
	for _, script := range cfg.scripts {
		// We run these scripts without interruption control as they are part of initialization.
		if _, err := vm.RunString(script); err != nil {
			m.logger.Warn("Error executing persistent script during init/reset", zap.Error(err))
		}
	}
	return nil
}

// Get acquires a VM from the pool, blocking until one is available or the context is canceled.
// It implements the "Reset on Get" pattern by re initializing the VM to the session's
// current state before returning it.
func (m *vmManager) Get(ctx context.Context) (*goja.Runtime, error) {
	select {
	case vm, ok := <-m.vms:
		if !ok {
			return nil, errors.New("vm pool closed")
		}
		// --- Start of Critical Reset Logic (Reset-on-Get) ---

		// CRITICAL: Clear the interrupt flag immediately upon retrieval.
		// This prevents contamination from previous interrupted executions.
		vm.ClearInterrupt()

		// Acquire the current configuration and the latest DOM bridge.
		m.configMu.RLock()
		cfg := m.baseConfig
		var domBridge *jsbind.DOMBridge
		if cfg.s != nil {
			domBridge = cfg.s.getDOMBridge()
		}
		m.configMu.RUnlock()

		// Re initialize the VM with the current configuration.
		if err := m.initializeVM(vm, cfg, domBridge); err != nil {
			// If initialization fails, the VM is potentially broken. We discard it.
			m.logger.Error("Failed to reset VM upon acquisition. Discarding VM.", zap.Error(err))
			return nil, fmt.Errorf("failed to reset VM: %w", err)
		}

		// --- End of Critical Reset Logic ---

		return vm, nil
	case <-ctx.Done():
		// Acquisition was cancelled.
		return nil, ctx.Err()
	}
}

// Put returns a VM to the pool for reuse.
func (m *vmManager) Put(vm *goja.Runtime) {
	if vm == nil {
		return
	}
	// Reset logic is handled in Get(). We simply return the VM to the channel.
	select {
	case m.vms <- vm:
	// Success
	default:
		// This should not happen if Get/Put are balanced in a fixed size pool.
		m.logger.Error("VM Pool overflow on Put. This indicates a logic error. Discarding VM.")
	}
}

// UpdateConfig allows thread safe updating of the base configuration used to reset VMs.
// This is called when the session state changes, e.g., after a navigation.
func (m *vmManager) UpdateConfig(cfg vmConfig) {
	m.configMu.Lock()
	m.baseConfig = cfg
	m.configMu.Unlock()
}

// Close drains the pool. This should be called during graceful shutdown to allow
// existing VMs to be garbage collected.
func (m *vmManager) Close() {
	if m.vms != nil {
		close(m.vms)
		// Drain the channel so VMs can be garbage collected.
		for range m.vms {
			// Discard VMs.
		}
		m.vms = nil
	}
}

// -- Session --

// Session represents a single, functional browsing context, equivalent to a browser tab.
// It manages its own state, including the current URL, DOM, JavaScript environment,
// and network stack. All high level operations are serialized to ensure logical consistency.
type Session struct {
	id          string
	ctx         context.Context // Master context for the session's lifecycle.
	cancel      context.CancelFunc
	logger      *zap.Logger
	cfg         config.Interface
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

	// opMu serializes high level operations (Navigation, Interactions)
	// to ensure logical state consistency.
	opMu sync.Mutex
	// mu protects the internal state variables (fine grained locking).
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
	consoleLogsMu sync.Mutex // Specific mutex for high frequency access.

	findingsChan chan<- schemas.Finding
	onClose      func()
	closeOnce    sync.Once
}

// acquireOpLock obtains the session's operation lock, ensuring that high level
// actions like navigation or multi step interactions do not run concurrently.
// It handles re entrancy by checking if the lock is already held in the current context.
func (s *Session) acquireOpLock(ctx context.Context) (context.Context, func()) {
	// If the lock is already held in this context chain, do nothing.
	if ctx.Value(operationLockKey) != nil {
		return ctx, func() {}
	}
	// Before waiting for the lock, check if the session or the operation is already done.
	select {
	case <-s.ctx.Done():
		return s.ctx, func() {}
	case <-ctx.Done():
		return ctx, func() {}
	default:
	}
	s.opMu.Lock()
	// Check again after acquiring lock in case session closed while waiting.
	if s.ctx.Err() != nil {
		s.opMu.Unlock()
		return s.ctx, func() {}
	}
	// Create a combined context that cancels when either the original or the session context does.
	combinedCtx, cancelCombined := CombineContext(s.ctx, ctx)
	lockedCtx := context.WithValue(combinedCtx, operationLockKey, true)
	return lockedCtx, func() {
		cancelCombined()
		s.opMu.Unlock()
	}
}

// sessionConsolePrinter acts as a bridge, funneling messages from the Goja
// console module to the session's internal log capture mechanism.
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

// NewSession creates and initializes a new browser session.
func NewSession(
	parentCtx context.Context,
	cfg config.Interface,
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
		s:        s,
		persona:  s.persona,
		bindings: s.exposedFunctions,
		scripts:  s.persistentScripts,
	}

	poolSize := cfg.Browser().Concurrency
	if poolSize <= 0 {
		poolSize = defaultVMPoolSize
	}

	var err error
	s.vmPool, err = newVMManager(log.Named("vm_pool"), vmCfg, poolSize)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize VM pool: %w", err)
	}

	// Configure humanoid interaction.
	browserCfg := cfg.Browser()
	s.humanoidController = humanoid.New(browserCfg.Humanoid, log.Named("humanoid"), s)

	// Set up the network stack with appropriate middleware.
	if err := s.initializeNetworkStack(log); err != nil {
		s.Close(context.Background()) // Ensure resources (like vmPool) are cleaned up.
		return nil, fmt.Errorf("failed to initialize network stack: %w", err)
	}

	// The DOM interactor needs a callback to stabilize the page after actions.
	stabilizeFn := func(ctx context.Context) error {
		return s.stabilize(ctx)
	}

	// The DOM interactor uses the humanoid configuration to inform its behavior.
	s.interactor = dom.NewInteractor(
		NewZapAdapter(log.Named("interactor")),
		browserCfg.Humanoid,
		stabilizeFn,
		s,
	)

	// Initialize the state for the initial (empty) document.
	if err := s.resetStateForNewDocument(s.ctx, nil, nil); err != nil {
		s.Close(context.Background())
		return nil, fmt.Errorf("failed to reset state for initial document: %w", err)
	}
	return s, nil
}

// getDOMBridge provides thread safe access to the domBridge.
func (s *Session) getDOMBridge() *jsbind.DOMBridge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domBridge
}

// captureConsoleLog receives messages from the JS console and stores them as artifacts.
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
// It updates the DOM bridge, informs the VM pool of the new state, and dispatches
// initial DOM events like DOMContentLoaded and load. It assumes the operation lock is held.
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

	// Update the base configuration for the VM pool.
	s.mu.RLock()
	vmCfg := vmConfig{
		s:        s,
		persona:  s.persona,
		bindings: s.exposedFunctions,
		scripts:  s.persistentScripts,
	}
	s.mu.RUnlock()

	s.mu.RLock()
	pool := s.vmPool
	s.mu.RUnlock()

	if pool == nil {
		if s.ctx.Err() == nil {
			return errors.New("session error: vmPool unavailable during resetStateForNewDocument")
		}
		return s.ctx.Err() // Session is closing.
	}

	pool.UpdateConfig(vmCfg)

	// Dispatch DOMContentLoaded and load events.
	vm, err := pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire VM for document initialization: %w", err)
	}
	defer pool.Put(vm)

	if bridge := s.getDOMBridge(); bridge != nil {
		docNode := bridge.GetDocumentNode()
		bridge.DispatchEventOnNode(docNode, "DOMContentLoaded")
		bridge.DispatchEventOnNode(docNode, "load")
	}

	return nil
}

// initializeNetworkStack configures the HTTP client, cookie jar, and transport layers,
// including middleware for HAR generation and content decompression.
func (s *Session) initializeNetworkStack(log *zap.Logger) error {
	netConfig := network.NewBrowserClientConfig()
	netConfig.Logger = NewZapAdapter(log.Named("network"))
	netConfig.InsecureSkipVerify = s.cfg.Browser().IgnoreTLSErrors || s.cfg.Network().IgnoreTLSErrors
	netConfig.RequestTimeout = s.cfg.Network().NavigationTimeout
	if netConfig.RequestTimeout == 0 {
		netConfig.RequestTimeout = 60 * time.Second
	}
	jar, _ := cookiejar.New(nil)
	netConfig.CookieJar = jar
	transport := network.NewHTTPTransport(netConfig)
	compressionTransport := network.NewCompressionMiddleware(transport)
	s.harvester = NewHarvester(compressionTransport, log.Named("harvester"), s.cfg.Network().CaptureResponseBodies)
	s.client = &http.Client{
		Transport: s.harvester,
		Timeout:   netConfig.RequestTimeout,
		Jar:       netConfig.CookieJar,
		// Disable automatic redirects so we can handle them manually.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return nil
}

// ID returns the unique identifier for the session.
func (s *Session) ID() string { return s.id }

// Close gracefully shuts down the session, canceling its master context and cleaning up resources.
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

		s.mu.Lock()
		pool := s.vmPool
		s.mu.Unlock()

		if pool != nil {
			pool.Close()
		}

		// Nullify references to major components to aid garbage collection.
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

// SetOnClose registers a callback function to be executed when the session is closed.
func (s *Session) SetOnClose(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onClose = fn
}

// stabilize waits for the page to become quiescent after an action.
// It waits for network activity to cease and then for a short period to allow
// any final JavaScript timers (like setTimeout) to execute.
func (s *Session) stabilize(ctx context.Context) error {
	stabCtx, stabCancel := CombineContext(s.ctx, ctx)
	defer stabCancel()

	quietPeriod := 1500 * time.Millisecond
	if s.cfg.Network().PostLoadWait > 0 {
		quietPeriod = s.cfg.Network().PostLoadWait
	}

	// Wait for all in flight network requests to complete.
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

// Navigate loads a new page in the session. This is a high level operation that
// acquires the operation lock.
func (s *Session) Navigate(ctx context.Context, targetURL string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}
	return s.navigateInternal(lockedCtx, targetURL)
}

// navigateInternal performs the core logic of a page navigation.
func (s *Session) navigateInternal(ctx context.Context, targetURL string) error {
	baseNavCtx := ctx

	timeout := s.cfg.Network().NavigationTimeout
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

	// Dispatch 'beforeunload' event on the current document.
	s.dispatchEventOnDocument("beforeunload")

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, resolvedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s': %w", resolvedURL.String(), err)
	}
	s.prepareRequestHeaders(req)

	if err := s.executeRequest(requestCtx, req); err != nil {
		return err
	}

	// If humanoid mode is on, pause briefly to mimic human reading time.
	if s.cfg.Browser().Humanoid.Enabled {
		if err := s.Sleep(baseNavCtx, 500*time.Millisecond+time.Duration(rand.Intn(1000))*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

// executeRequest sends an HTTP request and follows redirects up to a limit.
func (s *Session) executeRequest(ctx context.Context, req *http.Request) error {
	const maxRedirects = 10
	currentReq := req
	for i := 0; i < maxRedirects; i++ {
		s.logger.Debug("Executing request", zap.String("method", currentReq.Method), zap.String("url", currentReq.URL.String()))
		resp, err := s.client.Do(currentReq)
		if err != nil {
			return fmt.Errorf("request for '%s' failed: %w", currentReq.URL.String(), err)
		}

		// Handle redirects manually.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			nextReq, err := s.handleRedirect(ctx, resp, currentReq)
			_ = resp.Body.Close()
			if err != nil {
				return fmt.Errorf("failed to handle redirect: %w", err)
			}
			currentReq = nextReq
			continue
		}

		// Process the final non redirect response.
		return s.processResponse(ctx, resp)
	}
	return fmt.Errorf("maximum number of redirects (%d) exceeded", maxRedirects)
}

// handleRedirect processes a redirect response and creates the next request in the chain.
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

	// As per RFC 7231, change method to GET for 301, 302, 303.
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		if method != http.MethodHead {
			method = http.MethodGet
		}
		body = nil
	} else if originalReq.GetBody != nil {
		// For other redirects (e.g., 307, 308), reuse the original method and body.
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

// processResponse handles the response from a network request. If it's HTML,
// it parses the content, builds the style and layout trees, updates the session
// state, and executes any scripts on the page.
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
			// Still update state with the new URL even if parsing fails.
			if updateErr := s.updateState(ctx, resp.Request.URL, nil, nil, true); updateErr != nil {
				return fmt.Errorf("failed to update state after parse error: %w", updateErr)
			}
			return nil
		}
		// Build the render tree.
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

// buildAndAddStylesheets finds all <style> and <link rel="stylesheet"> tags,
// then fetches and parses their content concurrently to build the CSSOM.
func (s *Session) buildAndAddStylesheets(ctx context.Context, styleEngine *style.Engine, doc *html.Node, baseURL *url.URL) {
	// Process inline <style> tags.
	styleTags := htmlquery.Find(doc, "//style")
	for _, tag := range styleTags {
		p := parser.NewParser(htmlquery.InnerText(tag))
		styleEngine.AddAuthorSheet(p.Parse())
	}

	// Process external <link> tags.
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

	// Wait for all fetches to complete and then add the parsed sheets.
	go func() {
		wg.Wait()
		close(stylesheetChan)
	}()
	for ss := range stylesheetChan {
		styleEngine.AddAuthorSheet(ss)
	}
}

// reRender recalculates the style and layout trees for the current DOM.
// This is necessary after JavaScript modifies the DOM structure or styles.
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

// updateState modifies the session's core state, such as the current URL and history.
// If resetContext is true, it triggers a full reset of the DOM and JS environment.
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
		// This was a navigation, so push a new state to the history stack.
		newState := &schemas.HistoryState{
			State: nil,
			Title: title,
			URL:   newURL.String(),
		}
		s.pushHistoryInternal(newState)
	} else {
		// This was a pushState/replaceState, just update the current history entry.
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

// executePageScripts finds all <script> tags in the document and executes them.
// External scripts are fetched and executed asynchronously.
func (s *Session) executePageScripts(doc *html.Node) {
	gqDoc := goquery.NewDocumentFromNode(doc)
	gqDoc.Find("script").Each(func(i int, sel *goquery.Selection) {
		scriptType, _ := sel.Attr("type")
		normalizedType := strings.ToLower(strings.TrimSpace(scriptType))
		// Ignore scripts with non standard types.
		if normalizedType != "" && normalizedType != "text/javascript" && normalizedType != "application/javascript" && normalizedType != "module" {
			return
		}
		if src, exists := sel.Attr("src"); exists && src != "" {
			s.fetchAndExecuteScript(src)
		} else {
			scriptContent := sel.Text()
			if scriptContent != "" {
				_, err := s.executeScriptInternal(s.ctx, scriptContent, nil)
				if err != nil {
					// Don't spam logs for interruptions, which are expected on navigations.
					if _, ok := err.(*goja.InterruptedError); !ok {
						s.logger.Warn("Error executing inline script", zap.Error(err))
					}
				}
			}
		}
	})
}

// fetchAndExecuteScript handles fetching an external script and running it.
// This is done in a new goroutine to avoid blocking the main processing pipeline.
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
			if _, ok := execErr.(*goja.InterruptedError); !ok {
				s.logger.Warn("Error executing external script", zap.Error(execErr), zap.String("url", resolvedURL.String()))
			}
		}
	}()
}

// GetDOMSnapshot returns the current state of the DOM as a serialized HTML string.
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
		// If session is open but bridge is gone, return empty doc.
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

// Interact performs a series of interactions with the page, either from a predefined
// list of steps or by autonomously exploring the page.
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

// executeStepsInternal processes a predefined sequence of interaction steps.
func (s *Session) executeStepsInternal(ctx context.Context, steps []schemas.InteractionStep) error {
	for _, step := range steps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.logger.Info("Executing interaction step", zap.String("action", string(step.Action)), zap.String("selector", step.Selector))

		needsStabilization := true
		needsRendering := true
		useHumanoid := s.cfg.Browser().Humanoid.Enabled

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
			needsRendering = false // Navigation handles its own rendering.
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
			// Treat submit as a click on the submit button.
			if useHumanoid {
				if err := s.humanoidController.IntelligentClick(ctx, step.Selector, nil); err != nil {
					return fmt.Errorf("failed to execute submit (via click) on '%s': %w", step.Selector, err)
				}
			} else {
				if err := s.executeClickInternal(ctx, step.Selector, 0, 0); err != nil {
					return fmt.Errorf("failed to execute submit (via click) on '%s': %w", step.Selector, err)
				}
			}
			needsRendering = false // Form submission causes navigation.
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
				// A failed re render is not ideal but not always fatal.
				s.logger.Warn("Failed to re-render after interaction step, proceeding with potentially stale layout.", zap.Error(err))
			}
		}
	}
	return nil
}

// recursiveInteractInternal autonomously explores and interacts with elements on the page.
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
				return err // Normal context cancellation.
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

// Click finds an element and simulates a click on it.
func (s *Session) Click(ctx context.Context, selector string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}

	if s.cfg.Browser().Humanoid.Enabled {
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

// Type finds an element and simulates typing text into it.
func (s *Session) Type(ctx context.Context, selector string, text string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}

	if s.cfg.Browser().Humanoid.Enabled {
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

// Submit is a convenience method that is an alias for Click.
// It is intended for clicking on form submission buttons.
func (s *Session) Submit(ctx context.Context, selector string) error {
	return s.Click(ctx, selector)
}

// ScrollPage simulates scrolling the window.
func (s *Session) ScrollPage(ctx context.Context, direction string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}

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

// WaitForAsync waits for a specified duration or for the page to stabilize.
func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.waitForAsyncInternal(lockedCtx, milliseconds)
}

// waitForAsyncInternal contains the core logic for waiting.
func (s *Session) waitForAsyncInternal(ctx context.Context, milliseconds int) error {
	if milliseconds > 0 {
		return s.Sleep(ctx, time.Duration(milliseconds)*time.Millisecond)
	}
	return s.stabilize(ctx)
}

// ExposeFunction makes a Go function available to be called from JavaScript within the page.
func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.exposeFunctionInternal(lockedCtx, name, function)
}

// exposeFunctionInternal adds the function to the persistent bindings and updates the VM pool config.
func (s *Session) exposeFunctionInternal(_ context.Context, name string, function interface{}) error {
	s.mu.Lock()
	s.exposedFunctions[name] = function
	s.mu.Unlock()

	// Update the VM pool's base configuration so all future VMs get this binding.
	s.mu.RLock()
	vmCfg := s.vmPool.baseConfig
	vmCfg.bindings = s.exposedFunctions
	s.mu.RUnlock()
	s.vmPool.UpdateConfig(vmCfg)

	return nil
}

// InjectScriptPersistently adds a JavaScript snippet that will be executed on all subsequent
// page loads within this session.
func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.injectScriptPersistentlyInternal(lockedCtx, script)
}

// injectScriptPersistentlyInternal adds the script to the persistent list and executes it on the current page.
func (s *Session) injectScriptPersistentlyInternal(ctx context.Context, script string) error {
	s.mu.Lock()
	s.persistentScripts = append(s.persistentScripts, script)
	s.mu.Unlock()

	// Update the VM pool's base configuration so all future VMs get this script.
	s.mu.RLock()
	vmCfg := s.vmPool.baseConfig
	vmCfg.scripts = s.persistentScripts
	s.mu.RUnlock()
	s.vmPool.UpdateConfig(vmCfg)

	// Also execute it on the current page.
	_, err := s.executeScriptInternal(ctx, script, nil)
	return err
}

// ExecuteScript runs a snippet of JavaScript in the context of the current page.
func (s *Session) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return nil, lockedCtx.Err()
	}
	return s.executeScriptInternal(lockedCtx, script, args)
}

// executeScriptInternal manages the process of running a script on a pooled VM.
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

// executionResult is used for channel communication between the script runner and the waiting goroutine.
type executionResult struct {
	Value goja.Value
	Err   error
}

// executeScriptOnPooledVM handles the full lifecycle of borrowing, using, and
// returning a VM from the pool for a single script execution. It implements the
// Synchronized Interrupt Pattern to safely handle context cancellation.
func (s *Session) executeScriptOnPooledVM(ctx context.Context, script string, res interface{}, args []interface{}) (err error) {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}

	s.mu.RLock()
	pool := s.vmPool
	s.mu.RUnlock()

	if pool == nil {
		return errors.New("session closed: vmPool unavailable")
	}

	// Acquire a VM from the pool.
	vm, err := pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get vm from pool: %w", err)
	}

	// Ensure the VM is returned to the pool, and recover from any panics.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic before javascript execution: %v", r)
			s.logger.Error("Recovered from panic before javascript execution", zap.Error(err), zap.String("stack", string(debug.Stack())))
		}
		pool.Put(vm)
	}()

	if err := vm.Set("arguments", args); err != nil {
		return fmt.Errorf("failed to set script arguments: %w", err)
	}

	resultChan := make(chan executionResult, 1)

	// Execute the script in a separate goroutine.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("Panic during script execution", zap.Any("panic_value", r), zap.String("stack", string(debug.Stack())))
				select {
				case resultChan <- executionResult{Err: fmt.Errorf("panic during script execution: %v", r)}:
				default:
				}
			}
		}()

		val, err := vm.RunString(script)

		select {
		case resultChan <- executionResult{Value: val, Err: err}:
		default:
		}
	}()

	var finalValue goja.Value
	var executionErr error

	// Wait for either the script to finish or the context to be canceled.
	select {
	case result := <-resultChan:
		// Script finished normally.
		executionErr = result.Err
		finalValue = result.Value

	case <-ctx.Done():
		// Context was canceled. Interrupt the script.
		vm.Interrupt(ctx.Err())

		// Wait for the script to acknowledge the interrupt and return.
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()

		select {
		case result := <-resultChan:
			executionErr = ctx.Err() // The primary error is the context cancellation.
			finalValue = result.Value

			// Log if the script returned a different error than the expected interrupt.
			var interrupted *goja.InterruptedError
			if result.Err != nil && !errors.As(result.Err, &interrupted) {
				s.logger.Debug("Script returned non-interrupt error during cancellation.", zap.Error(result.Err))
			}

		case <-timeout.C:
			// The script is stuck and did not respond to the interrupt.
			s.logger.Error("Script execution did not stop after interrupt within timeout. VM might be stuck.")
			return fmt.Errorf("script execution timed out after interrupt")
		}
	}

	return s.processScriptResult(ctx, finalValue, executionErr, res)
}

// waitForPromise polls a Goja promise until it is resolved or rejected, or the context is canceled.
func (s *Session) waitForPromise(ctx context.Context, promise *goja.Promise) (goja.Value, error) {
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
			return nil, ctx.Err()
		}
	}
}

// processScriptResult handles error interpretation, promise resolution, and value exporting from a script.
func (s *Session) processScriptResult(ctx context.Context, value goja.Value, err error, res interface{}) error {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("javascript execution interrupted by context: %w", err)
		}

		var gojaException *goja.Exception
		var interruptedError *goja.InterruptedError

		if errors.As(err, &interruptedError) {
			// This should ideally be caught by the cancellation logic, but as a safeguard...
			s.logger.Error("Unexpected InterruptedError detected. Possible VM poisoning.", zap.Error(err))
			if interruptedError.Value() != nil {
				return fmt.Errorf("javascript execution interrupted unexpectedly: %v", interruptedError.Value())
			}
			return fmt.Errorf("javascript execution interrupted unexpectedly")
		}

		if errors.As(err, &gojaException) {
			return fmt.Errorf("javascript exception: %s", gojaException.String())
		}
		return fmt.Errorf("javascript execution error: %w", err)
	}

	// If the script returned a promise, wait for it to resolve.
	if promise, ok := value.Export().(*goja.Promise); ok && promise != nil {
		var promiseErr error
		value, promiseErr = s.waitForPromise(ctx, promise)
		if promiseErr != nil {
			if errors.Is(promiseErr, context.Canceled) || errors.Is(promiseErr, context.DeadlineExceeded) {
				return fmt.Errorf("javascript promise resolution interrupted by context: %w", promiseErr)
			}
			return promiseErr
		}
	}

	// Export the final value to the provided result interface.
	if res != nil && value != nil && !goja.IsUndefined(value) && !goja.IsNull(value) {
		// Use a fresh Goja runtime just for exporting, to avoid any state pollution.
		return goja.New().ExportTo(value, res)
	}
	return nil
}

// GetCurrentURL returns the current URL of the session.
func (s *Session) GetCurrentURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentURL != nil {
		return s.currentURL.String()
	}
	return ""
}

// ExecuteClick is part of the dom.CorePagePrimitives interface.
func (s *Session) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeClickInternal(lockedCtx, selector, minMs, maxMs)
}

// executeClickInternal finds an element, simulates click timing, and handles the consequences.
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
	// Determine what the click does (e.g., navigation, form submission).
	err = s.handleClickConsequenceInternal(ctx, element)
	// Dispatch the 'click' event for any JS listeners.
	s.dispatchEventOnNode(element, "click")
	return err
}

// ExecuteType is part of the dom.CorePagePrimitives interface.
func (s *Session) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeTypeInternal(lockedCtx, selector, text, holdMeanMs)
}

// executeTypeInternal simulates typing text into an element, character by character.
func (s *Session) executeTypeInternal(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	element, err := s.findElementNode(ctx, selector)
	if err != nil {
		return err
	}
	s.dispatchEventOnNode(element, "focus")
	escapedSelector := strings.ReplaceAll(selector, "'", "\\'")

	// --- START OF FIX ---

	// The original code read the element's current value here.
	// We will now start with a fresh, empty string to ensure we replace the content.
	var currentValue string

	// This also requires clearing the value in the browser's JS runtime before we begin.
	clearScript := fmt.Sprintf(`
        const el = document.querySelector('%s');
        if (el) {
            if (typeof el.value !== 'undefined') {
                el.value = '';
            } else if (typeof el.textContent !== 'undefined') {
                // This helps with contenteditable elements, though not strictly required for textarea/input
                el.textContent = '';
            }
        }
    `, escapedSelector)
	if _, err := s.executeScriptInternal(ctx, clearScript, nil); err != nil {
		// Log a warning but continue; the simulation can still proceed.
		s.logger.Warn("Failed to clear element before typing", zap.String("selector", selector), zap.Error(err))
	}

	// --- END OF FIX ---

	holdVariance := 15.0
	interKeyMeanMs := 100.0
	interKeyVariance := 40.0
	var rng *rand.Rand
	if holdMeanMs > 0 {
		rng = getRNG()
		defer putRNG(rng)
	}

	// Type each character with simulated delays and dispatch relevant events.
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
		escapedValue := strings.ReplaceAll(strings.ReplaceAll(currentValue, "'", "\\'"), `\`, `\\`)
		scriptToSetValue := fmt.Sprintf(`document.querySelector('%s').value = '%s'`, escapedSelector, escapedValue)
		if _, err := s.executeScriptInternal(ctx, scriptToSetValue, nil); err != nil {
			s.logger.Warn("Failed to update element value via script during typing", zap.String("selector", selector), zap.Error(err))
		}

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

// ExecuteSelect is part of the dom.CorePagePrimitives interface.
func (s *Session) ExecuteSelect(ctx context.Context, selector string, value string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.executeSelectInternal(lockedCtx, selector, value)
}

// executeSelectInternal changes the selected option of a <select> element.
func (s *Session) executeSelectInternal(ctx context.Context, selector string, value string) error {
	selectNode, err := s.findElementNode(ctx, selector)
	if err != nil {
		return err
	}
	if strings.ToLower(selectNode.Data) != "select" {
		return fmt.Errorf("element '%s' is not a select element", selector)
	}

	escapedSelector := strings.ReplaceAll(selector, "'", "\\'")
	escapedValue := strings.ReplaceAll(strings.ReplaceAll(value, "'", "\\'"), `\`, `\\`)

	// Use a script to set the value and verify it was set correctly.
	script := fmt.Sprintf(`
        (function() {
            const select = document.querySelector('%s');
            if (!select) { return false; }
            select.value = '%s';
            return select.value === '%s';
        })()
    `, escapedSelector, escapedValue, escapedValue)

	resultRaw, err := s.executeScriptInternal(ctx, script, nil)
	if err != nil {
		return fmt.Errorf("script to set select value failed for '%s': %w", selector, err)
	}

	var found bool
	if err := json.Unmarshal(resultRaw, &found); err != nil || !found {
		return fmt.Errorf("option with value '%s' not found or script failed", value)
	}

	// Dispatch events to notify listeners of the change.
	s.dispatchEventOnNode(selectNode, "input")
	s.dispatchEventOnNode(selectNode, "change")
	return nil
}

// IsVisible checks if an element is present in the layout tree.
func (s *Session) IsVisible(ctx context.Context, selector string) bool {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.isVisibleInternal(lockedCtx, selector)
}

// isVisibleInternal performs the actual check against the layout tree.
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

// JSNavigate is a callback for the JS environment (e.g., from `location.href = ...`) to trigger navigation.
func (s *Session) JSNavigate(targetURL string) {
	go func() {
		if err := s.Navigate(s.ctx, targetURL); err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				s.logger.Error("JS initiated navigation failed", zap.Error(err))
			}
		}
	}()
}

// NotifyURLChange is a callback for the JS environment to report URL changes that don't
// trigger a full navigation, like fragment (#) changes.
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

// ExecuteFetch is a callback for the JS environment to implement the `fetch` API.
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

	// Create a temporary client to handle fetch specific options.
	fetchClient := *s.client
	fetchClient.CheckRedirect = nil // Allow fetch to handle redirects itself.
	if reqData.Credentials == "omit" {
		fetchClient.Jar = nil // Omit cookies.
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

// AddCookieFromString parses a cookie from a string and adds it to the session's cookie jar.
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

// GetCookieString retrieves all non HttpOnly cookies for the current URL as a single string.
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

// PushHistory adds a new state to the session's history stack.
func (s *Session) PushHistory(state *schemas.HistoryState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushHistoryInternal(state)
	return nil
}

// pushHistoryInternal appends a state, trimming any forward history that might exist.
func (s *Session) pushHistoryInternal(state *schemas.HistoryState) {
	s.historyStack = s.historyStack[:s.historyIndex+1]
	s.historyStack = append(s.historyStack, state)
	s.historyIndex++
}

// ReplaceHistory replaces the current state in the session's history stack.
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

// GetHistoryLength returns the number of entries in the history stack.
func (s *Session) GetHistoryLength() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.historyStack)
}

// GetCurrentHistoryState returns the state object for the current history entry.
func (s *Session) GetCurrentHistoryState() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.historyIndex >= 0 && s.historyIndex < len(s.historyStack) {
		return s.historyStack[s.historyIndex].State
	}
	return nil
}

// ResolveURL resolves a relative URL against the session's current URL.
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
			return nil, nil // Empty URL with no base is just nil.
		}
		return nil, fmt.Errorf("must be an absolute URL for initial navigation: %s", targetURL)
	}
	return parsedURL, nil
}

// Sleep pauses execution for a duration, respecting context cancellation.
func (s *Session) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DispatchMouseEvent is part of the humanoid.Executor interface, handling mouse events.
func (s *Session) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	// We only care about the final 'release' event to trigger a click.
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

// SendKeys is part of the humanoid.Executor interface (currently a placeholder).
func (s *Session) SendKeys(ctx context.Context, keys string) error {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	if lockedCtx.Err() != nil {
		return lockedCtx.Err()
	}
	s.logger.Debug("Sending keys (TODO: implement key dispatch)", zap.String("keys", keys))
	return nil
}

// GetElementGeometry retrieves the layout geometry (position and dimensions) of an element.
func (s *Session) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.getElementGeometryInternal(lockedCtx, selector)
}

// getElementGeometryInternal queries the layout engine for an element's geometry.
func (s *Session) getElementGeometryInternal(_ context.Context, selector string) (*schemas.ElementGeometry, error) {
	s.mu.RLock()
	currentLayoutRoot := s.layoutRoot
	s.mu.RUnlock()
	if currentLayoutRoot == nil {
		return nil, fmt.Errorf("layout tree not available")
	}
	return s.layoutEngine.GetElementGeometry(currentLayoutRoot, selector)
}

// CollectArtifacts gathers all collected data from the session, such as logs, network traffic, and the final DOM.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	lockedCtx, unlock := s.acquireOpLock(ctx)
	defer unlock()
	return s.collectArtifactsInternal(lockedCtx)
}

// collectArtifactsInternal performs the actual collection.
func (s *Session) collectArtifactsInternal(ctx context.Context) (*schemas.Artifacts, error) {
	artifacts := &schemas.Artifacts{}

	// Collect console logs.
	s.consoleLogsMu.Lock()
	artifacts.ConsoleLogs = make([]schemas.ConsoleLog, len(s.consoleLogs))
	copy(artifacts.ConsoleLogs, s.consoleLogs)
	s.consoleLogsMu.Unlock()

	// Collect HAR data.
	if s.harvester != nil {
		harData := s.harvester.GenerateHAR()
		rawHar, _ := json.Marshal(harData)
		artifacts.HAR = (*json.RawMessage)(&rawHar)
	}

	// Collect final DOM state.
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

// AddFinding sends a finding to the central findings channel for processing.
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

// prepareRequestHeaders adds standard browser-like headers to an outgoing request.
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

// findElementNode uses the DOM bridge to find a single element node matching a CSS selector.
func (s *Session) findElementNode(_ context.Context, selector string) (*html.Node, error) {
	bridge := s.getDOMBridge()
	if bridge == nil {
		return nil, fmt.Errorf("DOM bridge is not initialized or session is closed")
	}

	node, err := bridge.QuerySelector(selector)
	if err != nil {
		return nil, fmt.Errorf("failed to find element '%s': %w", selector, err)
	}
	if node == nil {
		return nil, fmt.Errorf("element not found for selector: %s", selector)
	}
	return node, nil
}

// dispatchEventOnNode is a helper to dispatch a simple event on a specific DOM node.
func (s *Session) dispatchEventOnNode(node *html.Node, eventType string) {
	vm, err := s.vmPool.Get(s.ctx)
	if err != nil {
		s.logger.Warn("Failed to get VM to dispatch event", zap.String("event", eventType), zap.Error(err))
		return
	}
	defer s.vmPool.Put(vm)
	if bridge := s.getDOMBridge(); bridge != nil {
		bridge.DispatchEventOnNode(node, eventType)
	}
}

// dispatchEventOnDocument is a helper for dispatching events on the document object.
func (s *Session) dispatchEventOnDocument(eventType string) {
	vm, err := s.vmPool.Get(s.ctx)
	if err != nil {
		s.logger.Warn("Failed to get VM to dispatch document event", zap.String("event", eventType), zap.Error(err))
		return
	}
	defer s.vmPool.Put(vm)
	if bridge := s.getDOMBridge(); bridge != nil {
		docNode := bridge.GetDocumentNode()
		bridge.DispatchEventOnNode(docNode, eventType)
	}
}

// handleClickConsequenceInternal determines the browser's native action for a click,
// such as following a link, submitting a form, or toggling a checkbox.
func (s *Session) handleClickConsequenceInternal(ctx context.Context, element *html.Node) error {
	bridge := s.getDOMBridge()
	if bridge == nil {
		return errors.New("session closed")
	}
	tagName := strings.ToLower(element.Data)

	// Handle special input types.
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
			// Uncheck other radio buttons in the same group.
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

	// Check if the click was on a link.
	anchor := element
	for anchor != nil && strings.ToLower(anchor.Data) != "a" {
		anchor = anchor.Parent
	}
	if anchor != nil {
		if href := htmlquery.SelectAttr(anchor, "href"); href != "" {
			return s.navigateInternal(ctx, href)
		}
	}

	// Check if the click submits a form.
	form := findParentForm(element)
	if form != nil {
		isSubmitButton := false
		if tagName == "button" {
			btnType := strings.ToLower(htmlquery.SelectAttr(element, "type"))
			if btnType == "submit" || btnType == "" { // Default type for button is submit.
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

// submitFormInternal gathers all serializable data from a form and submits it.
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

	// Find all form control elements.
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
						value = "on" // Default value for checked boxes without a value.
					}
					formData.Add(name, value)
				}
			} else if inputType != "submit" && inputType != "reset" && inputType != "button" && inputType != "image" {
				formData.Add(name, htmlquery.SelectAttr(input, "value"))
			}
		case "textarea":
			formData.Add(name, htmlquery.InnerText(input))
		case "select":
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
		targetURL, _ = s.ResolveURL("") // Fallback to current URL.
		if targetURL == nil {
			return fmt.Errorf("failed to resolve form action URL (%s) and no current URL available: %w", action, err)
		}
	}

	var req *http.Request
	if method == http.MethodPost {
		if enctype != "application/x-www-form-urlencoded" {
			// NOTE: multipart/form-data is not currently supported.
			s.logger.Warn("Unsupported form enctype, submitting as urlencoded", zap.String("enctype", enctype))
		}
		body := strings.NewReader(formData.Encode())
		req, err = http.NewRequestWithContext(ctx, method, targetURL.String(), body)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else { // Default to GET
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

// getAttr is a helper to safely get an attribute from a node.
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
	for i := range n.Attr {
		if n.Attr[i].Key == key {
			n.Attr[i].Val = val
			return
		}
	}
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

// findParentForm finds the <form> element that a given element belongs to,
// respecting the `form` attribute.
func findParentForm(element *html.Node) *html.Node {
	if element == nil {
		return nil
	}
	// Check for explicit form attribute.
	if formID := htmlquery.SelectAttr(element, "form"); formID != "" {
		root := element
		for root.Parent != nil {
			root = root.Parent
		}
		if form := htmlquery.FindOne(root, fmt.Sprintf("//form[@id='%s']", formID)); form != nil {
			return form
		}
	}
	// Traverse up the tree to find an ancestor form.
	for p := element.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && strings.ToLower(p.Data) == "form" {
			return p
		}
	}
	return nil
}
