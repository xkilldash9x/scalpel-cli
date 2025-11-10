// internal/autofix/watcher.go
package autofix

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hpcloud/tail"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Regex Definitions --
var newEntryRegex = regexp.MustCompile(`^(\d{4}[-/]\d{2}[-/]\d{2}|\{.*"ts":|INFO|WARN|ERROR|DEBUG|panic:)`)
var jsonStackRegex = regexp.MustCompile(`"stacktrace":"(.*?)"`)
var locationRegex = regexp.MustCompile(`^\s*(.*?\.go):(\d+)`)
var jsonMessageRegex = regexp.MustCompile(`"msg":"(.*?)"`)

// Watcher monitors application logs for crashes and generates a post-mortem report.
// It tails the application log file, detects panic events, and collects
// relevant information like the stack trace, file path, and line number of the crash.
type Watcher struct {
	// logger is the application's logger instance.
	logger *zap.Logger
	// cfg is the application's configuration.
	cfg config.Interface
	// appLogPath is the path to the application log file to monitor.
	appLogPath string
	// dastLogPath is the path to the DAST (Dynamic Application Security Testing) log file.
	dastLogPath string
	// projectRoot is the root directory of the project.
	projectRoot string
	// reportChan is a channel to send post-mortem reports to.
	reportChan chan<- PostMortem
}

// NewWatcher initializes and returns a new Watcher service.
// It takes a logger, configuration, a channel for sending reports, and the project root directory.
// It returns an error if the application log file is not configured.
func NewWatcher(logger *zap.Logger, cfg config.Interface, reportChan chan<- PostMortem, projectRoot string) (*Watcher, error) {
	// Corrected to use the interface's getter methods
	appLogPath := cfg.Logger().LogFile
	if appLogPath == "" {
		return nil, fmt.Errorf("logger.log_file must be configured for crash detection")
	}

	// Corrected to use the interface's getter methods
	dastLogPath := cfg.Autofix().DASTLogPath
	if dastLogPath == "" {
		logger.Debug("Autofix: DAST log path not configured. Request correlation will be unavailable.")
	}

	return &Watcher{
		logger:      logger.Named("autofix-watcher"),
		cfg:         cfg,
		appLogPath:  appLogPath,
		dastLogPath: dastLogPath,
		projectRoot: projectRoot,
		reportChan:  reportChan,
	}, nil
}

// Start begins the log monitoring process. It starts tailing the application
// log file in a separate goroutine and returns an error if the file cannot be tailed.
func (w *Watcher) Start(ctx context.Context) error {
	w.logger.Info("Starting crash detection watcher...", zap.String("app_log", w.appLogPath))

	t, err := tail.TailFile(w.appLogPath, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to tail application log file: %w", err)
	}

	go w.monitorLoop(ctx, t)
	return nil
}

// The core loop that reads log lines and dispatches handlers.
// This loop acts as a state machine to correctly buffer and process multi-line
// stack traces from a single, shared log file, preventing race conditions.
func (w *Watcher) monitorLoop(ctx context.Context, t *tail.Tail) {
	defer func() {
		t.Stop()
		t.Cleanup()
	}()

	panicRegex := regexp.MustCompile(`("level":"panic"|"level":"fatal"|panic:)`)
	var currentStackTrace []string
	// Timer to flush the stack trace if no new lines arrive after a panic is detected.
	timeout := time.NewTimer(100 * time.Millisecond)
	// Start the timer in a stopped state.
	if !timeout.Stop() {
		<-timeout.C
	}

	// Helper to process the buffered stack trace.
	processStackTrace := func() {
		if len(currentStackTrace) > 0 {
			// Create a copy for the goroutine to prevent data races on the buffer.
			traceCopy := make([]string, len(currentStackTrace))
			copy(traceCopy, currentStackTrace)
			go w.handlePanic(ctx, traceCopy)
			currentStackTrace = nil // Reset buffer after dispatching.
		}
	}

	for {
		select {
		case <-ctx.Done():
			processStackTrace() // Process any pending stack trace before exiting.
			w.logger.Info("Stopping log watcher.")
			return

		case line, ok := <-t.Lines:
			if !ok {
				processStackTrace() // Process pending trace on channel close.
				w.logger.Info("Log file tailer channel closed.")
				return
			}
			if line.Err != nil {
				w.logger.Warn("Error reading from log file", zap.Error(line.Err))
				continue
			}

			text := line.Text
			isNewEntry := newEntryRegex.MatchString(text)
			isPanicEntry := panicRegex.MatchString(text)

			// If we are tracking a stack trace and a new, distinct log entry appears,
			// the previous stack trace must be complete.
			if len(currentStackTrace) > 0 && isNewEntry {
				processStackTrace()
				// Ensure the timer is stopped, as the trace was terminated by a new entry, not a timeout.
				if !timeout.Stop() {
					select {
					case <-timeout.C: // Drain the channel if Stop() returns false.
					default:
					}
				}
			}

			// If the current line is a panic, start a new trace.
			if isPanicEntry {
				// This condition ensures we only start a new trace if we aren't in one,
				// or if we just flushed the previous one.
				if len(currentStackTrace) == 0 {
					currentStackTrace = append(currentStackTrace, text)
					timeout.Reset(100 * time.Millisecond) // Start the timeout for subsequent lines.
				}
			} else if len(currentStackTrace) > 0 {
				// If we are already inside a stack trace, append the line and reset the timeout.
				currentStackTrace = append(currentStackTrace, text)
				timeout.Reset(100 * time.Millisecond)
			}

		case <-timeout.C:
			// The timer fired, indicating the end of the current stack trace.
			processStackTrace()
		}
	}
}

// Orchestrates evidence gathering for a given panic event.
func (w *Watcher) handlePanic(ctx context.Context, stackTrace []string) {
	if len(stackTrace) == 0 {
		return
	}
	w.logger.Warn("Panic detected! Initiating Phase 1: Evidence Collection.")
	crashTime := time.Now()

	// Handle structured (JSON) logs first.
	if strings.Contains(stackTrace[0], "{") && strings.Contains(stackTrace[0], "stacktrace") {
		matches := jsonStackRegex.FindStringSubmatch(stackTrace[0])
		if len(matches) > 1 {
			unescapedTrace, err := strconv.Unquote(`"` + matches[1] + `"`)
			if err == nil {
				// The full trace is embedded in the first line.
				stackTrace = strings.Split(strings.ReplaceAll(unescapedTrace, "\\n", "\n"), "\n")
			}
		}
	}

	panicLine := stackTrace[0]
	fullTrace := strings.Join(stackTrace, "\n")

	filePath, lineNum, err := parsePanicLocation(fullTrace)
	if err != nil {
		w.logger.Error("Failed to parse panic location. Aborting self-heal attempt.", zap.Error(err), zap.String("trace", fullTrace))
		return
	}

	normalizedPath, err := w.normalizeFilePath(filePath)
	if err != nil {
		w.logger.Warn("Could not normalize file path. Using raw path.", zap.String("path", filePath), zap.Error(err))
		normalizedPath = filePath
	}

	var triggeringRequest *DASTRequest
	if w.dastLogPath != "" {
		triggeringRequest, _ = w.findTriggeringRequest(w.dastLogPath, crashTime)
	}

	report := PostMortem{
		IncidentID:        uuid.New().String(),
		CrashTime:         crashTime,
		PanicMessage:      extractPanicMessage(panicLine),
		FilePath:          normalizedPath,
		LineNumber:        lineNum,
		FullStackTrace:    fullTrace,
		TriggeringRequest: triggeringRequest,
	}

	w.logger.Info("Post-mortem report generated.", zap.String("incident_id", report.IncidentID), zap.String("file", report.FilePath))

	select {
	case w.reportChan <- report:
	case <-ctx.Done():
		w.logger.Warn("Context cancelled while sending post-mortem report.", zap.String("incident_id", report.IncidentID))
	}
}

func parsePanicLocation(stackTrace string) (string, int, error) {
	lines := strings.Split(stackTrace, "\n")
	// Iterate through the lines to find the first one that points to application code.
	for _, line := range lines {
		// Standard Go stack traces indent file paths with a tab.
		if !strings.HasPrefix(line, "\t") {
			continue
		}

		matches := locationRegex.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) == 3 {
			filePath := matches[1]
			// Filter out Go runtime, standard library, and vendored dependencies.
			if strings.Contains(filePath, "runtime/") || strings.Contains(filePath, "/go/src/") || strings.Contains(filePath, "/vendor/") {
				continue
			}

			lineNum, _ := strconv.Atoi(matches[2])
			return filePath, lineNum, nil
		}
	}
	return "", 0, fmt.Errorf("could not reliably determine panic location from stack trace")
}

func extractPanicMessage(panicLine string) string {
	// Handle structured JSON logs.
	if strings.HasPrefix(panicLine, "{") {
		matches := jsonMessageRegex.FindStringSubmatch(panicLine)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}
	// Handle standard Go "panic: " prefix.
	parts := strings.SplitN(panicLine, "panic: ", 2)
	if len(parts) > 1 {
		return strings.TrimSpace(parts[1])
	}
	// Fallback for logs without the prefix.
	return strings.TrimSpace(panicLine)
}

func (w *Watcher) normalizeFilePath(filePath string) (string, error) {
	if w.projectRoot == "" || !filepath.IsAbs(filePath) {
		return filepath.ToSlash(filePath), nil
	}
	absProjectRoot, err := filepath.Abs(w.projectRoot)
	if err != nil {
		return "", fmt.Errorf("invalid project root: %w", err)
	}
	relPath, err := filepath.Rel(absProjectRoot, filePath)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(relPath, "..") {
		return "", fmt.Errorf("file path '%s' is outside the project root '%s'", filePath, w.projectRoot)
	}
	return filepath.ToSlash(relPath), nil
}

func (w *Watcher) findTriggeringRequest(_ string, crashTime time.Time) (*DASTRequest, error) {
	w.logger.Debug("Simulating DAST log parsing (Placeholder)...")
	// In a real implementation, this would involve reading the DAST log file backwards
	// to find the last request sent just before the crashTime.
	return &DASTRequest{
		Timestamp:  crashTime.Add(-50 * time.Millisecond),
		Method:     "POST",
		URL:        "http://localhost:8080/api/vulnerable/process",
		RawRequest: "POST /api/vulnerable/process HTTP/1.1\r\nHost: localhost:8080\r\nContent-Type: application/json\r\n\r\n{\"input\":null}",
	}, nil
}
