// internal/autofix/watcher.go
package autofix

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hpcloud/tail"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Watcher monitors application logs for crashes and generates a post-mortem report.
type Watcher struct {
	logger      *zap.Logger
	cfg         *config.Config
	appLogPath  string
	dastLogPath string
	mu          sync.Mutex
	reportChan  chan<- PostMortem
}

// NewWatcher initializes the Watcher service.
func NewWatcher(logger *zap.Logger, cfg *config.Config, reportChan chan<- PostMortem) (*Watcher, error) {
	appLogPath := cfg.Logger.LogFile
	if appLogPath == "" {
		return nil, fmt.Errorf("logger.log_file must be configured for crash detection")
	}

	// Assuming config structure like cfg.Autofix.DASTLogPath
	dastLogPath := cfg.Autofix.DASTLogPath
	if dastLogPath == "" {
		logger.Info("Autofix: DAST log path not configured. Request correlation will be unavailable.")
	}

	return &Watcher{
		logger:      logger.Named("autofix-watcher"),
		cfg:         cfg,
		appLogPath:  appLogPath,
		dastLogPath: dastLogPath,
		reportChan:  reportChan,
	}, nil
}

// Start begins the log monitoring process.
func (w *Watcher) Start(ctx context.Context) error {
	w.logger.Info("Starting crash detection watcher...", zap.String("app_log", w.appLogPath))

	t, err := tail.TailFile(w.appLogPath, tail.Config{
		Follow:    true,
		ReOpen:    true, // Handle log rotation
		MustExist: true,
		// Start from the end on startup to avoid processing old logs.
		Location: &tail.SeekInfo{Offset: 0, Whence: 2},
		Logger:   tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to tail application log file: %w", err)
	}

	go w.monitorLoop(ctx, t)
	return nil
}

func (w *Watcher) monitorLoop(ctx context.Context, t *tail.Tail) {
	defer func() {
		t.Stop()
		t.Cleanup()
	}()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Stopping log watcher.")
			return
		case line, ok := <-t.Lines:
			if !ok {
				return
			}
			if line.Err != nil {
				continue
			}

			if strings.Contains(line.Text, "panic:") {
				w.handlePanic(ctx, line.Text, t)
			}
		}
	}
}

// handlePanic orchestrates evidence gathering.
func (w *Watcher) handlePanic(ctx context.Context, panicLine string, tailer *tail.Tail) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.logger.Warn("Panic detected! Initiating Phase 1: Evidence Collection.")
	crashTime := time.Now()

	// 1. Ingest Stack Trace.
	stackTrace := w.ingestStackTrace(tailer)
	fullTrace := panicLine + "\n" + strings.Join(stackTrace, "\n")

	// 2. Parse details (using improved parser).
	filePath, lineNum, err := parsePanicLocation(fullTrace)
	if err != nil {
		w.logger.Error("Failed to parse panic location. Aborting self-heal attempt.", zap.Error(err))
		return
	}

	// 3. Correlate DAST request.
	var triggeringRequest *DASTRequest
	if w.dastLogPath != "" {
		triggeringRequest, _ = w.findTriggeringRequest(w.dastLogPath, crashTime)
	}

	// 4. Generate PostMortem.
	report := PostMortem{
		IncidentID:        uuid.New().String(),
		CrashTime:         crashTime,
		PanicMessage:      extractPanicMessage(panicLine),
		FilePath:          filePath,
		LineNumber:        lineNum,
		FullStackTrace:    fullTrace,
		TriggeringRequest: triggeringRequest,
	}

	w.logger.Info("Post-mortem report generated.", zap.String("incident_id", report.IncidentID))

	// 5. Dispatch report.
	select {
	case w.reportChan <- report:
	case <-ctx.Done():
	}
}

// Regex to identify typical log prefixes or new goroutines, indicating the end of the trace.
var newEntryRegex = regexp.MustCompile(`^(\d{4}[-/]\d{2}[-/]\d{2}|\{.*"ts":|INFO|WARN|ERROR|DEBUG|goroutine \d+ \[)`)

// ingestStackTrace reads subsequent lines with adaptive timeouts.
func (w *Watcher) ingestStackTrace(tailer *tail.Tail) []string {
	var stackTrace []string
	timeoutDuration := 500 * time.Millisecond

	for {
		select {
		case line := <-tailer.Lines:
			if line == nil {
				return stackTrace
			}
			text := line.Text

			// Stop if we hit the start of a new entry (and we have already ingested some lines).
			if len(stackTrace) > 0 && newEntryRegex.MatchString(text) {
				return stackTrace
			}
			stackTrace = append(stackTrace, text)
			timeoutDuration = 100 * time.Millisecond // Speed up subsequent reads

		case <-time.After(timeoutDuration):
			// Timeout occurred. Assume the stack trace output is complete.
			return stackTrace
		}
	}
}

// -- Parsing Logic --

var locationRegex = regexp.MustCompile(`([a-zA-Z0-9\._\-\/]+\.go):(\d+)`)

// parsePanicLocation extracts the location, prioritizing application code over runtime/vendor.
func parsePanicLocation(stackTrace string) (string, int, error) {
	lines := strings.Split(stackTrace, "\n")
	for _, line := range lines {
		// Go stack traces indent the file location with a tab.
		if strings.HasPrefix(line, "\t") {
			matches := locationRegex.FindStringSubmatch(line)
			if len(matches) == 3 {
				filePath := matches[1]
				// Heuristic: skip internal runtime or common Go installation paths.
				if strings.Contains(filePath, "runtime/") || strings.Contains(filePath, "/go/src/") {
					continue
				}
				lineNum, _ := strconv.Atoi(matches[2]) // Safe due to regex
				return filePath, lineNum, nil
			}
		}
	}
	return "", 0, fmt.Errorf("could not reliably determine panic location from stack trace")
}

func extractPanicMessage(panicLine string) string {
	parts := strings.SplitN(panicLine, "panic: ", 2)
	if len(parts) > 1 {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(panicLine)
}

// findTriggeringRequest placeholder implementation.
func (w *Watcher) findTriggeringRequest(dastLogPath string, crashTime time.Time) (*DASTRequest, error) {
    w.logger.Debug("Simulating DAST log parsing (Placeholder)...")
    return &DASTRequest{
        Timestamp: crashTime.Add(-50 * time.Millisecond),
        Method:    "POST",
        URL:       "http://localhost:8080/api/vulnerable/process",
        RawRequest: "POST /api/vulnerable/process HTTP/1.1\r\nHost: localhost:8080\r\nContent-Type: application/json\r\n\r\n{\"input\":null}",
    }, nil
}