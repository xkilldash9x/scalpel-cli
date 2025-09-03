// pkg/browser/harvester.go
package browser

import (
	"context"
	"sync"
	"time"

	"github.com/chromedp/cdproto/har"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
)

// Harvester collects network (HAR) and console artifacts from a browser session.
type Harvester struct {
	ctx         context.Context // The session context
	cancel      context.CancelFunc
	logger      *zap.Logger
	mu          sync.RWMutex
	consoleLogs []browser.ConsoleLog
	isRunning   bool
}

// NewHarvester creates a new Harvester associated with a specific session context.
func NewHarvester(sessionCtx context.Context, logger *zap.Logger) *Harvester {
	// Create a derived context for the harvester's internal operations.
	ctx, cancel := context.WithCancel(sessionCtx)
	return &Harvester{
		ctx:    ctx,
		cancel: cancel,
		logger: logger.Named("harvester"),
	}
}

// Start begins listening for browser events.
func (h *Harvester) Start() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.isRunning {
		return
	}

	h.consoleLogs = make([]browser.ConsoleLog, 0)
	h.isRunning = true

	// --- Console Log Collection ---
	// Listen for log events (includes console API calls).
	chromedp.ListenTarget(h.ctx, func(ev interface{}) {
		if ev, ok := ev.(*log.EventEntryAdded); ok {
			h.mu.Lock()
			h.consoleLogs = append(h.consoleLogs, browser.ConsoleLog{
				Type: string(ev.Entry.Level),
				Text: ev.Entry.Text,
			})
			h.mu.Unlock()
		}
	})

	// --- HAR Collection ---
	// Use the har package to automatically listen and record network events.
	if err := har.Start(h.ctx); err != nil {
		h.logger.Error("Failed to start HAR collection", zap.Error(err))
		h.isRunning = false
	}
}

// Stop halts event collection and returns the captured artifacts.
func (h *Harvester) Stop(ctx context.Context) (*har.HAR, []browser.ConsoleLog) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isRunning {
		return nil, h.copyLogs()
	}

	// Signal internal listeners to stop.
	h.cancel()
	h.isRunning = false

	// Give a brief moment for final events to be processed.
	time.Sleep(100 * time.Millisecond)

	// Stop the HAR recording and retrieve the final log.
	// We use the provided context (ctx) to respect the caller's deadlines during this operation,
	// combined with the session's executor.
	finalHarLog, err := har.Stop(chromedp.WithExecutor(ctx, chromedp.FromContext(h.ctx)))
	if err != nil {
		// Log the error but still return console logs.
		h.logger.Error("Failed to finalize HAR collection", zap.Error(err))
	}

	return finalHarLog, h.copyLogs()
}

// copyLogs returns a copy of the console logs. Must be called with lock held.
func (h *Harvester) copyLogs() []browser.ConsoleLog {
	logsCopy := make([]browser.ConsoleLog, len(h.consoleLogs))
	copy(logsCopy, h.consoleLogs)
	return logsCopy
}
