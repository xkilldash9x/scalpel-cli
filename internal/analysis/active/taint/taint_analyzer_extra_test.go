package taint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

func TestAnalyze_InstrumentFailure(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	mockSession := mocks.NewMockSessionContext()
	ctx := context.Background()

	// Mock ExposeFunction to fail immediately
	expectedErr := errors.New("injection failed")
	// Use MatchedBy to match any string, or specific strings
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(expectedErr).Once()

	err := analyzer.Analyze(ctx, mockSession)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to instrument browser")
	assert.ErrorIs(t, err, expectedErr)
}

func TestExecuteCleanup_Logic(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		c.ProbeExpirationDuration = 100 * time.Millisecond
	}, false)

	// Add a probe that is already expired
	expiredProbe := ActiveProbe{
		Canary:    "EXPIRED",
		CreatedAt: time.Now().Add(-200 * time.Millisecond),
	}
	analyzer.registerProbe(expiredProbe)

	// Add a probe that is fresh
	freshProbe := ActiveProbe{
		Canary:    "FRESH",
		CreatedAt: time.Now(),
	}
	analyzer.registerProbe(freshProbe)

	// Run cleanup manually
	analyzer.executeCleanup()

	analyzer.probesMutex.RLock()
	defer analyzer.probesMutex.RUnlock()

	_, expiredExists := analyzer.activeProbes["EXPIRED"]
	_, freshExists := analyzer.activeProbes["FRESH"]

	assert.False(t, expiredExists, "Expired probe should be removed")
	assert.True(t, freshExists, "Fresh probe should be retained")
}

func TestIsSourceContextMatch(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)

	tests := []struct {
		name          string
		dynamicSource schemas.TaintSource
		staticSource  core.TaintSource // Can be pipe-separated
		want          bool
	}{
		// URL Param Matches
		{"URLParam match LocationSearch", schemas.SourceURLParam, core.SourceLocationSearch, true},
		{"URLParam match LocationHref", schemas.SourceURLParam, core.SourceLocationHref, true},
		{"URLParam match specific param", schemas.SourceURLParam, "param:query:id", true},
		{"URLParam mismatch Hash", schemas.SourceURLParam, core.SourceLocationHash, false},

		// Hash Fragment Matches
		{"Hash match LocationHash", schemas.SourceHashFragment, core.SourceLocationHash, true},
		{"Hash match specific param", schemas.SourceHashFragment, "param:hash:state", true},
		{"Hash mismatch Search", schemas.SourceHashFragment, core.SourceLocationSearch, false},

		// Storage Matches
		{"LocalStorage match LocalStorage", schemas.SourceLocalStorage, core.SourceLocalStorage, true},
		{"LocalStorage match specific param", schemas.SourceLocalStorage, "param:storage:key", true},
		{"SessionStorage match SessionStorage", schemas.SourceSessionStorage, core.SourceSessionStorage, true},
		{"SessionStorage mismatch Cookie", schemas.SourceSessionStorage, core.SourceDocumentCookie, false},

		// Cookie Matches
		{"Cookie match DocumentCookie", schemas.SourceCookie, core.SourceDocumentCookie, true},
		{"Cookie mismatch LocalStorage", schemas.SourceCookie, core.SourceLocalStorage, false},

		// Multi-source static finding
		{"Multi-source match", schemas.SourceURLParam, core.TaintSource(string(core.SourceLocationHash) + "|" + string(core.SourceLocationSearch)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.isSourceContextMatch(tt.dynamicSource, tt.staticSource)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProcessSinkEvent_ErrorPage_Suppressed(t *testing.T) {
	// Setup observer to verify debug logs
	coreLog, _ := observer.New(zaptest.NewLogger(t).Core())
	logger := zaptest.NewLogger(t).WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core { return coreLog }))

	analyzer, reporter := setupCorrelationTest(t)
	analyzer.logger = logger

	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	canary := analyzer.generateCanary("T", schemas.ProbeTypeXSS)
	probe := ActiveProbe{Type: schemas.ProbeTypeXSS, Canary: canary, Value: "payload", Source: schemas.SourceURLParam}
	analyzer.registerProbe(probe)

	// Event on a 404 page
	sinkEvent := SinkEvent{
		Type:      schemas.SinkInnerHTML,
		Value:     "payload" + canary, // Valid match
		PageTitle: "404 Not Found",
		PageURL:   "http://example.com/404",
	}

	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)

	assert.Empty(t, reporter.GetFindings(), "Should not report findings on error pages")
	// Since isErrorPageContext returns true, the code `continue`s inside `processSinkEvent` loop.
	// It doesn't log "Context mismatch", it just skips.
	// We can verify that no report was made.
}

func TestExecutePause_ContextCancelled(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Pass nil for humanoid, should check context first
	err := analyzer.executePause(ctx, nil, 100, 10)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}
