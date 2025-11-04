// analyzer_test.go
package idor

import (
	"context"
	"errors" // Added import
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
)

// TestAnalyzer_AnalyzeTraffic_Validation verifies the prerequisite checks.
func TestAnalyzer_AnalyzeTraffic_Validation(t *testing.T) {
	t.Parallel()
	// Discard logger output for clean test runs.
	logger := log.New(io.Discard, "", 0)
	// Initialize the analyzer with a real comparer service instance.
	analyzer := NewIDORAnalyzer(logger, jsoncompare.NewService())
	ctx := context.Background()

	// Define Sessions (using MockSession from idor_test.go)
	userAAuth := &MockSession{UserID: "A", Authenticated: true}
	userBAuth := &MockSession{UserID: "B", Authenticated: true}
	userUnauth := &MockSession{UserID: "U", Authenticated: false}

	// Dummy traffic (required for session validation checks to be reached)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	traffic := []RequestResponsePair{{Request: req}}

	testCases := []struct {
		name      string
		traffic   []RequestResponsePair
		config    Config
		expectErr bool
		errType   interface{}
	}{
		{
			name:      "No Traffic",
			traffic:   nil,
			config:    Config{Session: userAAuth, SecondSession: userBAuth},
			expectErr: false,
		},
		{
			name:      "Missing Primary Session",
			traffic:   traffic,
			config:    Config{Session: nil, SecondSession: userBAuth},
			expectErr: true,
			errType:   &ErrUnauthenticated{},
		},
		{
			name:      "Primary Session Unauthenticated",
			traffic:   traffic,
			config:    Config{Session: userUnauth, SecondSession: userBAuth},
			expectErr: true,
			errType:   &ErrUnauthenticated{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use a very short timeout for the context to prevent the analysis from running long if validation passes.
			ctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
			defer cancel()

			_, err := analyzer.AnalyzeTraffic(ctx, tc.traffic, tc.config)

			if tc.expectErr {
				if err == nil {
					t.Fatal("Expected an error but got nil")
				}
				// Check error type if specified
				if tc.errType != nil {
					// Compare error types robustly
					if fmt.Sprintf("%T", err) != fmt.Sprintf("%T", tc.errType) {
						t.Errorf("Expected error type %T, but got %T (%v)", tc.errType, err, err)
					}
				}
			} else {
				// If we don't expect an error, we must ensure the error is nil OR context.DeadlineExceeded
				// because the analysis might have started and then timed out.
				// Use errors.Is for robust checking of context errors.
				if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
					t.Fatalf("Expected no error (or DeadlineExceeded), but got: %v", err)
				}
			}
		})
	}
}

// TestValidateAndConfigure_Defaults verifies that production defaults are correctly applied.
func TestValidateAndConfigure_Defaults(t *testing.T) {
	// Setup a dummy analyzer to call the internal method.
	analyzer := &IDORAnalyzer{
		logger: log.New(io.Discard, "", 0),
	}
	userA := &MockSession{Authenticated: true}
	userB := &MockSession{Authenticated: true}

	config := Config{
		Session:       userA,
		SecondSession: userB,
		// Leave others empty to test defaults
	}

	err := analyzer.validateAndConfigure(&config)
	if err != nil {
		t.Fatalf("validateAndConfigure failed: %v", err)
	}

	// Check Defaults
	if config.HttpClient == nil {
		t.Error("HttpClient default was not set.")
	} else {
		// Check specific client settings defined in analyzer.go
		if config.HttpClient.Timeout != network.DefaultRequestTimeout {
			t.Errorf("HttpClient Timeout incorrect. Expected %v, Got %v", network.DefaultRequestTimeout, config.HttpClient.Timeout)
		}
		if config.HttpClient.CheckRedirect == nil {
			t.Error("HttpClient CheckRedirect (Do not follow) was not set.")
		}
	}

	if config.ConcurrencyLevel <= 0 {
		t.Errorf("ConcurrencyLevel default was not set correctly (Got %d).", config.ConcurrencyLevel)
	}

	// Check if default comparison options were applied
	defaultOpts := jsoncompare.DefaultOptions()
	// We must ignore unexported fields when comparing regexp.Regexp structs
	if diff := cmp.Diff(defaultOpts, config.ComparisonOptions, cmpopts.IgnoreUnexported(regexp.Regexp{})); diff != "" {
		t.Errorf("ComparisonOptions mismatch (-want +got):\n%s", diff)
	}
}
