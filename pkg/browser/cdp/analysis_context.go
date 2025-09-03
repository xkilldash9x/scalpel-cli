// pkg/browser/cdp/analysis_context.go
package cdp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser/shim"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/humanoid"
)

// ensure AnalysisContext implements the interface
var _ browser.SessionContext = (*AnalysisContext)(nil)

// AnalysisContext manages a single, isolated browser tab (session) using CDP.
type AnalysisContext struct {
	id               string
	globalConfig     *config.Config
	logger           *zap.Logger
	persona          stealth.Persona
	allocatorContext context.Context // Context of the main browser process

	// Session specific resources
	sessionContext context.Context
	sessionCancel  context.CancelFunc
	humanoid       *humanoid.Humanoid
	harvester      *Harvester
	interactor     *Interactor // Helper for complex interactions

	// Instrumentation configuration
	taintShimTemplate string
	taintConfigJSON   string

	isClosed bool
	mu       sync.Mutex
}

// NewAnalysisContext creates a new context structure. Initialize must be called next.
func NewAnalysisContext(
	allocCtx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	persona stealth.Persona,
	taintTemplate string,
	taintConfig string,
) *AnalysisContext {
	id := uuid.New().String()
	l := logger.With(zap.String("session_id", id[:8]))

	return &AnalysisContext{
		id:                  id,
		allocatorContext:    allocCtx,
		globalConfig:        cfg,
		logger:              l,
		persona:             persona,
		taintShimTemplate:   taintTemplate,
		taintConfigJSON:     taintConfig,
	}
}

// Initialize creates the browser tab and applies all necessary instrumentation.
func (ac *AnalysisContext) Initialize(ctx context.Context) error {
	ac.mu.Lock()

	if ac.sessionContext != nil {
		ac.mu.Unlock()
		return fmt.Errorf("session already initialized")
	}

	// Critical Section: Initialize fields
	sessionCtx, cancel := chromedp.NewContext(ac.allocatorContext)
	ac.sessionContext = sessionCtx
	ac.sessionCancel = cancel
	ac.humanoid = humanoid.New(ac.globalConfig.Humanoid)
	ac.harvester = NewHarvester(ac.sessionContext, ac.logger)
	ac.interactor = NewInteractor(ac.logger, ac.humanoid)

	// Unlock here. Fields are initialized and safe for concurrent access by other methods.
	ac.mu.Unlock()

	// Apply instrumentation and stealth.
	if err := ac.applyStealth(); err != nil {
		// Safe to call Close now without holding the lock.
		ac.Close(ctx)
		return fmt.Errorf("failed to apply stealth: %w", err)
	}

	if err := ac.applyInstrumentation(); err != nil {
		// Log the error but allow the session to continue without IAST if it fails.
		ac.logger.Error("Failed to apply IAST instrumentation.", zap.Error(err))
	}

	// Start the harvester.
	ac.harvester.Start()

	ac.logger.Info("Browser session initialized and instrumented.")
	return nil
}

func (ac *AnalysisContext) applyStealth() error {
	// Apply persona settings (UserAgent, Platform, Screen resolution, JS evasions).
	if err := chromedp.Run(ac.sessionContext, stealth.Apply(ac.persona, ac.logger)); err != nil {
		return fmt.Errorf("failed to apply stealth persona: %w", err)
	}
	return nil
}

func (ac *AnalysisContext) applyInstrumentation() error {
	// 1. Build the Taint Shim (Pinnacle Runtime)
	if ac.taintShimTemplate == "" {
		return nil // IAST disabled or template missing.
	}

	script, err := shim.BuildTaintShim(ac.taintShimTemplate, ac.taintConfigJSON)
	if err != nil {
		return fmt.Errorf("failed to build taint shim: %w", err)
	}

	// 2. Expose the callback function BEFORE injecting the script.
	// We use chromedp.Expose which handles the unmarshalling automatically.
	err = ac.ExposeFunction("__scalpel_sink_event", ac.handleTaintEvent)
	if err != nil {
		return fmt.Errorf("failed to expose taint callback: %w", err)
	}

	// 3. Inject the script to run on every new document load.
	err = ac.InjectScriptPersistently(script)
	if err != nil {
		return fmt.Errorf("failed to inject taint shim: %w", err)
	}

	return nil
}

// handleTaintEvent is the callback invoked by the JavaScript shim.
// Chromedp automatically unmarshals the JS object into a map[string]interface{}.
func (ac *AnalysisContext) handleTaintEvent(event map[string]interface{}) {
	// In a real implementation, this event would be processed by the analysis engine.
	ac.logger.Info("Taint Sink Triggered",
		zap.String("type", fmt.Sprintf("%v", event["type"])),
		zap.String("detail", fmt.Sprintf("%v", event["detail"])),
	)
}

// ID returns the unique identifier for this session.
func (ac *AnalysisContext) ID() string {
	return ac.id
}

// GetContext returns the underlying session context.
func (ac *AnalysisContext) GetContext() context.Context {
	return ac.sessionContext
}

// InjectScriptPersistently ensures a script is executed on every new document load.
func (ac *AnalysisContext) InjectScriptPersistently(script string) error {
	// Use the CDP command directly.
	action := chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(script).Do(ctx)
		return err
	})
	return chromedp.Run(ac.sessionContext, action)
}

// ExposeFunction makes a Go function callable from the browser's JavaScript context.
func (ac *AnalysisContext) ExposeFunction(name string, function interface{}) error {
	return chromedp.Run(ac.sessionContext,
		chromedp.Expose(name, function),
	)
}

// Navigate loads a URL and waits for the page to be ready.
func (ac *AnalysisContext) Navigate(url string) error {
	ac.logger.Debug("Navigating", zap.String("url", url))
	return chromedp.Run(ac.sessionContext,
		// Clear cache if configured.
		chromedp.ActionFunc(func(ctx context.Context) error {
			if ac.globalConfig.Browser.DisableCache {
				return network.SetCacheDisabled(true).Do(ctx)
			}
			return nil
		}),
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		// Wait for async operations to settle.
		chromedp.Sleep(ac.globalConfig.Network.PostLoadWait),
	)
}

// WaitForAsync waits for a specified duration, respecting the session context.
func (ac *AnalysisContext) WaitForAsync(milliseconds int) error {
	select {
	case <-time.After(time.Duration(milliseconds) * time.Millisecond):
		return nil
	case <-ac.sessionContext.Done():
		return ac.sessionContext.Err()
	}
}

// Click performs a human-like click.
func (ac *AnalysisContext) Click(selector string) error {
	return chromedp.Run(ac.sessionContext,
		ac.humanoid.IntelligentClick(selector, humanoid.NewPotentialField()),
	)
}

// Type performs human-like typing.
func (ac *AnalysisContext) Type(selector, text string) error {
	return chromedp.Run(ac.sessionContext,
		ac.humanoid.Type(selector, text),
	)
}

// Submit simulates submitting a form.
func (ac *AnalysisContext) Submit(selector string) error {
	return chromedp.Run(ac.sessionContext,
		chromedp.Submit(selector),
	)
}

// ScrollPage scrolls the page 'up' or 'down' using humanoid behavior.
func (ac *AnalysisContext) ScrollPage(direction string) error {
	if direction == "down" {
		return chromedp.Run(ac.sessionContext, ac.humanoid.ScrollToBottom())
	}
	return chromedp.Run(ac.sessionContext, ac.humanoid.ScrollToTop())
}

// Interact uses the Interactor helper to explore the page.
func (ac *AnalysisContext) Interact(config browser.InteractionConfig) error {
	ac.logger.Debug("Starting automated humanoid interaction phase", zap.Int("max_depth", config.MaxDepth))

	// The Interactor handles the complexity of finding, prioritizing, and clicking elements recursively.
	return ac.interactor.RecursiveInteract(ac.sessionContext, config)
}

// CollectArtifacts gathers data from the session.
func (ac *AnalysisContext) CollectArtifacts(ctx context.Context) (*browser.Artifacts, error) {
	ac.mu.Lock()
	if ac.isClosed {
		ac.mu.Unlock()
		return nil, fmt.Errorf("session is already closed")
	}
	harvester := ac.harvester
	sessionContext := ac.sessionContext
	ac.mu.Unlock()

	artifacts := &browser.Artifacts{}
	ac.logger.Debug("Collecting browser artifacts.")

	// Use a timeout derived from the caller's context (ctx).
	collectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// 1. Stop the harvester and get its data
	if harvester != nil {
		artifacts.HAR, artifacts.ConsoleLogs = harvester.Stop(collectCtx)
	}

	// Create a new derived context for CDP operations that respects the collection timeout.
	runCtx, cancelRunCtx := context.WithTimeout(sessionContext, 20*time.Second)
	defer cancelRunCtx()

	// 2. Get DOM content (Snapshot)
	var domContent string
	if err := chromedp.Run(runCtx, chromedp.OuterHTML("html", &domContent)); err != nil {
		ac.logger.Warn("Could not retrieve final DOM content", zap.Error(err))
	}
	artifacts.DOM = domContent

	// 3. Get storage state
	var storageResult browser.StorageState
	var cookies []*network.Cookie
	err := chromedp.Run(runCtx,
		// Evaluate JavaScript to extract storage maps.
		chromedp.Evaluate(
			`({
                localStorage: {...localStorage},
                sessionStorage: {...sessionStorage}
            })`, &storageResult),
		// Use CDP command to get all cookies (including HttpOnly).
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			cookies, err = network.GetAllCookies().Do(ctx)
			return err
		}),
	)
	if err != nil {
		ac.logger.Warn("Could not retrieve storage state", zap.Error(err))
	}
	storageResult.Cookies = cookies
	artifacts.Storage = storageResult

	return artifacts, nil
}

// Close safely terminates the browser tab and its associated resources.
func (ac *AnalysisContext) Close(ctx context.Context) error {
	ac.mu.Lock()
	if ac.isClosed {
		ac.mu.Unlock()
		return nil
	}
	ac.isClosed = true
	// Capture references needed for closing before releasing the lock.
	harvester := ac.harvester
	sessionCancel := ac.sessionCancel
	sessionContext := ac.sessionContext
	ac.mu.Unlock() // Release the lock before potentially blocking operations.

	// Stop harvester first.
	if harvester != nil {
		harvester.Stop(ctx)
	}

	// Cancel the session context.
	if sessionCancel != nil {
		sessionCancel()
	}

	if sessionContext == nil {
		return nil
	}

	// Wait for the session context to be fully done.
	// Use a robust timeout that respects the caller's deadline (ctx) and the hard timeout.
	waitCtx, cancelWait := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWait()

	select {
	case <-sessionContext.Done():
		ac.logger.Debug("Browser session closed gracefully.")
	case <-waitCtx.Done():
		// This triggers if the caller's deadline OR the 10s timeout is reached.
		ac.logger.Warn("Deadline exceeded waiting for browser session to close.", zap.Error(waitCtx.Err()))
	}

	return nil
}