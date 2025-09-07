// pkg/browser/manager.go
package browser

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"


	"github.com/xkilldash9x/scalpel-cli/internal/browser/shim"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)

const (
	// browserStartupTimeout defines the maximum time allowed for the browser process to launch and become responsive.
	browserStartupTimeout = 30 * time.Second
)

// Manager handles the lifecycle of the headless browser process, ensuring efficient resource utilization and stealth.
type Manager struct {
	logger       *zap.Logger
	globalConfig *config.Config

	// allocatorCtx manages the entire browser process. All session contexts are derived from this.
	allocatorCtx    context.Context
	allocatorCancel context.CancelFunc

	// Caches for instrumentation.
	runtimeTemplateCache  string
	staticTaintConfigJSON string

	// The standardized browser persona to apply for stealth and consistency.
	persona stealth.Persona

	// wg tracks active analysis sessions for a graceful shutdown.
	wg sync.WaitGroup
}

// instrumentationConfigJSON defines the default IAST sinks monitored by the Pinnacle Runtime.
const instrumentationConfigJSON = `[
	{"Name": "document.write", "Setter": false, "Type": "DOMXSS"},
	{"Name": "Element.prototype.innerHTML", "Setter": true, "Type": "DOMXSS"},
	{"Name": "Element.prototype.outerHTML", "Setter": true, "Type": "DOMXSS"},
	{"Name": "window.eval", "Setter": false, "Type": "CodeExecution"},
	{"Name": "Function", "Setter": false, "Type": "CodeExecution"},
	{"Name": "window.location.href", "Setter": true, "Type": "OpenRedirect"},
	{"Name": "window.location.assign", "Setter": false, "Type": "OpenRedirect"},
	{"Name": "window.alert", "Setter": false, "Type": "DebugSink"}
]`

// generateSecureSeed creates a high-entropy seed for the PRNG in the JS evasions script.
func generateSecureSeed() int64 {
	var b [8]byte
	// Use crypto/rand for a high-entropy seed.
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based seed if crypto/rand fails (less secure).
		return time.Now().UnixNano()
	}
	// Convert the random bytes to an int64 using LittleEndian for consistency.
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// NewManager initializes the browser manager, launches the browser process, and prepares instrumentation.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	m := &Manager{
		logger:       logger.Named("browser_manager"),
		globalConfig: cfg,
		// Define the default persona with high-fidelity settings (e.g., standard Windows/Chrome profile).
		persona: stealth.Persona{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			Platform:  "Win32",
			Languages: []string{"en-US", "en"},
			Screen: stealth.ScreenProperties{
				Width: 1920, Height: 1080, AvailWidth: 1920, AvailHeight: 1040, ColorDepth: 24, PixelDepth: 24,
			},
			TimezoneID: "America/Los_Angeles", // Example consistent timezone.
			Locale:     "en-US",
			// Adding Client Hints data for enhanced realism.
			ClientHintsData: &stealth.ClientHints{
				Platform:        "Windows",
				PlatformVersion: "10.0.0",
				Architecture:    "x86",
				Bitness:         "64",
				Mobile:          false,
				Brands: []*emulation.UserAgentBrandVersion{
					{Brand: "Not.A/Brand", Version: "8"},
					{Brand: "Chromium", Version: "126"},
					{Brand: "Google Chrome", Version: "126"},
				},
			},
			NoiseSeed: generateSecureSeed(),
		},
	}

	// Load the instrumentation configuration.
	m.loadInstrumentationConfig()

	// Launch the browser process.
	if err := m.launchBrowser(ctx); err != nil {
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}

	return m, nil
}

// loadInstrumentationConfig prepares the taint shim template and configuration.
func (m *Manager) loadInstrumentationConfig() {
	m.logger.Info("Loading Pinnacle Unified Runtime (Taint Shim) configuration.")

	// Load the configuration from the constant.
	m.staticTaintConfigJSON = instrumentationConfigJSON

	// Load the runtime template from the embedded filesystem (via shim package).
	script, err := shim.GetTaintShimTemplate()
	if err != nil {
		m.logger.Error("CRITICAL: Failed to load Pinnacle Runtime Template. IAST will be disabled.", zap.Error(err))
		m.runtimeTemplateCache = ""
		return
	}
	m.runtimeTemplateCache = script
}

// launchBrowser prepares allocator options and starts the headless browser process.
func (m *Manager) launchBrowser(ctx context.Context) error {
	m.logger.Info("Initializing browser allocator...")

	opts := m.buildAllocatorOptions()

	// Create the allocator context. This prepares the execution environment.
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	m.allocatorCtx = allocCtx
	m.allocatorCancel = cancel

	// Create an initial context to launch the browser (if not already running) and verify responsiveness.
	testCtx, cancelTest := chromedp.NewContext(allocCtx)

	// Ensure the initial tab is closed properly after the check.
	defer func() {
		// Use a background context with a timeout for closing the test tab.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		// Close the target associated with the test context.
		if err := chromedp.Cancel(testCtx, chromedp.WithTargetClose(closeCtx)); err != nil {
			m.logger.Warn("Failed to close initial test tab.", zap.Error(err))
		}
	}()

	// Set a timeout for the initial responsiveness check.
	runCtx, cancelRun := context.WithTimeout(testCtx, browserStartupTimeout)
	defer cancelRun()

	// Run a simple command to ensure the browser starts and the CDP connection is established.
	if err := chromedp.Run(runCtx, chromedp.Navigate("about:blank")); err != nil {
		m.logger.Error("Browser failed to start or respond within the timeout.", zap.Error(err))
		// If the initial connection fails, we must cancel the allocator to clean up the browser process.
		m.allocatorCancel()
		return fmt.Errorf("browser failed to start or respond: %w", err)
	}

	m.logger.Info("Browser launched successfully and is responsive.")
	return nil
}

// buildAllocatorOptions assembles the necessary flags for a stealthy, configurable browser instance.
func (m *Manager) buildAllocatorOptions() []chromedp.ExecAllocatorOption {
	// Start with default options.
	defaultOpts := chromedp.DefaultExecAllocatorOptions[:]
	var opts []chromedp.ExecAllocatorOption

	// Filter out flags that reveal automation or are redundant.
	for _, opt := range defaultOpts {
		if flag, ok := opt.(chromedp.Flag); ok {
			// Remove "enable-automation" (the info bar).
			if flag.Name == "enable-automation" {
				continue
			}
			// Remove default flags that we override later with more specific settings.
			if flag.Name == "disable-background-networking" || flag.Name == "disable-extensions" {
				continue
			}
		}
		opts = append(opts, opt)
	}

	// Apply essential stealth and configuration flags.
	opts = append(opts,
		// CRITICAL: Disable the "AutomationControlled" Blink feature (navigator.webdriver).
		chromedp.Flag("disable-blink-features", "AutomationControlled"),

		// Security and Isolation.
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-plugins", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("no-first-run", true),

		// Feature disabling to reduce fingerprinting surface and improve performance.
		chromedp.Flag("disable-features", "TranslateUI,BlinkGenPropertyTrees,MediaRouter,OptimizationHints,site-per-process"),

		// Apply configuration settings.
		chromedp.Flag("headless", m.globalConfig.Browser.Headless),
		chromedp.Flag("ignore-certificate-errors", m.globalConfig.Browser.IgnoreTLSErrors),

		// We do not set UserAgent here via flag, as it's more robustly handled
		// via emulation.SetUserAgentOverride in the stealth module per session.
	)

	// Optimization: Don't load images if configured.
	if m.globalConfig.Browser.DisableImages {
		opts = append(opts, chromedp.Flag("blink-settings", "imagesEnabled=false"))
	}

	// Disable GPU in headless mode, often improving stability, especially in containerized environments.
	if m.globalConfig.Browser.Headless {
		opts = append(opts, chromedp.Flag("disable-gpu", true))
	}

	// Apply custom arguments from the configuration file.
	for _, arg := range m.globalConfig.Browser.Args {
		parts := strings.SplitN(arg, "=", 2)
		flagName := strings.TrimPrefix(parts[0], "--")

		if len(parts) == 2 {
			opts = append(opts, chromedp.Flag(flagName, parts[1]))
		} else {
			opts = append(opts, chromedp.Flag(flagName, true))
		}
	}

	// Apply platform-specific hardening (e.g., for running in Docker/Linux).
	if runtime.GOOS == "linux" {
		opts = append(opts,
			chromedp.Flag("no-sandbox", true),            // Required if running as root in Docker.
			chromedp.Flag("disable-dev-shm-usage", true), // Prevents issues with small /dev/shm in Docker.
			chromedp.Flag("disable-setuid-sandbox", true),
		)
	}

	return opts
}

// InitializeSession creates a new, fully isolated, and instrumented browser context (tab).
func (m *Manager) InitializeSession(taskCtx context.Context) (interfaces.SessionContext, error) {
	// Create the analysis context structure.
	// Passes the pre-configured persona and instrumentation caches.
	ac := NewAnalysisContext(
		m.allocatorCtx,
		m.globalConfig,
		m.logger,
		m.persona,
		m.runtimeTemplateCache,
		m.staticTaintConfigJSON,
	)

	// Initialize the browser tab and instrumentation.
	// The AnalysisContext handles its own cleanup if initialization fails.
	if err := ac.Initialize(taskCtx); err != nil {
		return nil, fmt.Errorf("failed to initialize analysis session: %w", err)
	}

	// Register the session with the wait group for graceful shutdown.
	m.wg.Add(1)

	// Wrap the context in a sessionWrapper to handle the WaitGroup signaling upon close.
	return &sessionWrapper{
		SessionContext: ac,
		wg:             &m.wg,
		// Use a short ID for logging clarity.
		logger: m.logger.With(zap.String("session_id_short", ac.ID()[:8])),
	}, nil
}

// Shutdown waits for all active sessions to complete and then terminates the browser process.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Browser manager shutdown initiated. Waiting for active sessions to complete...")

	// Use a channel to signal when all sessions are done.
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All sessions have completed.")
	case <-ctx.Done():
		// The provided context (e.g., shutdown deadline) has expired.
		m.logger.Warn("Shutdown deadline exceeded. Forcing browser termination.", zap.Error(ctx.Err()))
	}

	// Terminate the main browser process.
	if m.allocatorCancel != nil {
		m.logger.Info("Shutting down main browser process...")
		m.allocatorCancel()
		// Wait for the allocator context to signal completion.
		<-m.allocatorCtx.Done()
		m.logger.Info("Browser process terminated.")
	}
	return nil
}

// -- sessionWrapper --

// sessionWrapper ensures that the WaitGroup is signaled when the session is closed.
type sessionWrapper struct {
	interfaces.SessionContext
	wg     *sync.WaitGroup
	logger *zap.Logger
	closed bool
	mu     sync.Mutex
}

// Close gracefully closes the underlying session and signals its completion to the manager.
func (sw *sessionWrapper) Close(ctx context.Context) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return nil
	}

	sw.logger.Debug("Closing session via wrapper.")
	err := sw.SessionContext.Close(ctx)
	if err != nil {
		sw.logger.Warn("Error during session context close.", zap.Error(err))
	}

	sw.closed = true
	sw.wg.Done() // Signal the manager that this session is finished.
	sw.logger.Debug("Session wrapper signaled completion.")
	return err
}
