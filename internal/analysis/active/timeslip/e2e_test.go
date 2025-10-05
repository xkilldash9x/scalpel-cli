//go:build e2e
// +build e2e

// Use a separate test package to keep E2E tests distinct
package timeslip_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/timeslip"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// MockReporter for E2E tests (Thread-safe).
type E2EMockReporter struct {
	mu       sync.Mutex
	findings []schemas.Finding
}

func (mr *E2EMockReporter) Write(envelope *schemas.ResultEnvelope) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.findings = append(mr.findings, envelope.Findings...)
	return nil
}

func (mr *E2EMockReporter) GetFindings() []schemas.Finding {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	return mr.findings
}

// VulnerableServer simulates a TOCTOU vulnerability for voucher redemption.
type VulnerableServer struct {
	mu           sync.Mutex
	voucherUsed  bool
	// Configuration options
	useLocking   bool
	processDelay time.Duration
}

func (vs *VulnerableServer) handler(w http.ResponseWriter, r *http.Request) {
	// Optional locking for the "patched" test case.
	if vs.useLocking {
		vs.mu.Lock()
		defer vs.mu.Unlock()
	}

	// 1. Time-of-Check (Read state)
	isUsed := vs.voucherUsed

	// 2. Simulate processing delay (The race window)
	time.Sleep(vs.processDelay)

	// 3. Time-of-Use (Act based on checked state and update)
	if !isUsed {
		// In a non-locked scenario, multiple requests can reach here.
		vs.voucherUsed = true
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"success", "message":"Voucher redeemed!"}`)
	} else {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintln(w, `{"status":"error", "message":"Voucher already used."}`)
	}
}

// Helper to set up the E2E analyzer configuration
func setupE2EAnalyzer(reporter core.Reporter) (*timeslip.Analyzer, error) {
	config := &timeslip.Config{
		Concurrency:        20, // High concurrency to trigger the race
		Timeout:            5 * time.Second,
		ExpectedSuccesses:  1,
		ThresholdMs:        150, // Threshold for timing anomaly detection
		// Define success criteria matching the vulnerable server's success response
		Success: timeslip.SuccessCondition{
			BodyRegex: `"status":"success"`,
		},
	}
	logger := zap.NewNop()
	return timeslip.NewAnalyzer(uuid.New(), config, logger, reporter)
}

// --- IV. End-to-End System Tests ---

func TestE2E_TOCTOU_Vulnerable(t *testing.T) {
	// Setup a vulnerable server with a significant race window (50ms) and no locking
	vs := &VulnerableServer{
		processDelay: 50 * time.Millisecond,
		useLocking:   false,
	}
	server := httptest.NewServer(http.HandlerFunc(vs.handler))
	defer server.Close()

	reporter := &E2EMockReporter{}
	analyzer, err := setupE2EAnalyzer(reporter)
	require.NoError(t, err)

	candidate := &timeslip.RaceCandidate{
		Method: "POST",
		URL:    server.URL + "/redeem",
	}

	// Run the analysis
	err = analyzer.Analyze(context.Background(), candidate)
	require.NoError(t, err)

	// Assertions
	findings := reporter.GetFindings()
	require.NotEmpty(t, findings, "Expected a finding, but none were reported.")

	// We expect a confirmed TOCTOU (Critical) because multiple requests should succeed.
	foundCritical := false
	for _, f := range findings {
		if f.Severity == schemas.SeverityCritical {
			foundCritical = true
			assert.Contains(t, f.Vulnerability.Name, "Critical TOCTOU Race Condition Detected")
			assert.Contains(t, f.Description, "Confirmed TOCTOU race condition")
			break
		}
	}

	assert.True(t, foundCritical, "Expected a CRITICAL severity finding")
}

func TestE2E_Patched_WithLocking(t *testing.T) {
	// Setup a patched server using locking
	vs := &VulnerableServer{
		processDelay: 50 * time.Millisecond,
		useLocking:   true, // Enable locking
	}
	server := httptest.NewServer(http.HandlerFunc(vs.handler))
	defer server.Close()

	reporter := &E2EMockReporter{}
	analyzer, err := setupE2EAnalyzer(reporter)
	require.NoError(t, err)

	candidate := &timeslip.RaceCandidate{
		Method: "POST",
		URL:    server.URL + "/redeem",
	}

	// Run the analysis
	err = analyzer.Analyze(context.Background(), candidate)
	require.NoError(t, err)

	// Assertions
	findings := reporter.GetFindings()

	// We should NOT find any Critical/High/Medium vulnerabilities.
	for _, f := range findings {
		if f.Severity != schemas.SeverityInformational {
			t.Errorf("Found unexpected vulnerability (%s) in a patched server: %s", f.Severity, f.Description)
		}
	}

	// Because locking forces sequential execution with delays (20 requests * 50ms delay > 1s total),
	// we expect an INFORMATIONAL finding due to timing anomalies (delta > ThresholdMs).
	foundInformational := false
	for _, f := range findings {
		if f.Severity == schemas.SeverityInformational {
			foundInformational = true
			assert.Contains(t, f.Description, "Significant timing delta detected")
			break
		}
	}

	assert.True(t, foundInformational, "Expected an INFORMATIONAL finding due to sequential locking delays")
}