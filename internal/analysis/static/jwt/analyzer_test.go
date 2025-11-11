// internal/analysis/static/jwt/analyzer_test.go
package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// Helper to create a test JWT. Re-defined here to avoid test dependency cycles.
func createTestJWTForAnalyzer(alg string, claims jwt.MapClaims, secret interface{}) (string, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("invalid signing algorithm: %s", alg)
	}
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(secret)
}

func TestJWTAnalyzerInfo(t *testing.T) {
	logger := zap.NewNop()
	analyzer := NewJWTAnalyzer(logger, false)

	if analyzer.Name() != "JWT Static Analyzer" {
		t.Errorf("Expected name 'JWT Static Analyzer', got '%s'", analyzer.Name())
	}
	if analyzer.Description() != "Scans HTTP traffic for common JWT vulnerabilities." {
		t.Errorf("Unexpected description: '%s'", analyzer.Description())
	}
	if analyzer.Type() != core.TypePassive {
		t.Errorf("Expected type '%v', got '%v'", core.TypePassive, analyzer.Type())
	}
}

func TestJWTAnalyzer_Analyze(t *testing.T) {
	logger := zap.NewNop()

	// Create some test tokens
	tokenInURL, _ := createTestJWTForAnalyzer("none", jwt.MapClaims{"sub": "url"}, jwt.UnsafeAllowNoneSignatureType)
	tokenInHeader, _ := createTestJWTForAnalyzer("none", jwt.MapClaims{"sub": "header"}, jwt.UnsafeAllowNoneSignatureType)
	tokenInCookie, _ := createTestJWTForAnalyzer("none", jwt.MapClaims{"sub": "cookie"}, jwt.UnsafeAllowNoneSignatureType)
	tokenInBody, _ := createTestJWTForAnalyzer("none", jwt.MapClaims{"sub": "body"}, jwt.UnsafeAllowNoneSignatureType)

	har := schemas.HAR{
		Log: schemas.HARLog{
			Entries: []schemas.Entry{
				{ // Entry 1: Token in URL and Header
					Request: schemas.Request{
						URL: "http://example.com/api?token=" + tokenInURL,
						Headers: []schemas.NVPair{
							{Name: "Authorization", Value: "Bearer " + tokenInHeader},
						},
					},
					Response: schemas.Response{
						Content: schemas.Content{},
					},
				},
				{ // Entry 2: Token in Cookie and Body
					Request: schemas.Request{
						URL: "http://example.com/login",
						Cookies: []schemas.HARCookie{
							{Name: "auth_token", Value: tokenInCookie},
						},
						PostData: &schemas.PostData{
							MimeType: "application/json",
							Text:     `{"jwt": "` + tokenInBody + `"}`,
						},
					},
					Response: schemas.Response{
						Content: schemas.Content{},
					},
				},
			},
		},
	}

	harBytes, _ := json.Marshal(har)
	harRaw := json.RawMessage(harBytes)

	testCases := []struct {
		name              string
		analysisCtx       *core.AnalysisContext
		bruteForceEnabled bool
		expectedFindings  int
		wantErr           bool
	}{
		{
			name: "Successfully finds all 4 tokens",
			analysisCtx: &core.AnalysisContext{
				Artifacts: &schemas.Artifacts{HAR: &harRaw},
				Findings:  []schemas.Finding{},
			},
			bruteForceEnabled: false,
			expectedFindings:  8,
			wantErr:           false,
		},
		{
			name: "Handles nil HAR artifact",
			analysisCtx: &core.AnalysisContext{
				Artifacts: &schemas.Artifacts{HAR: nil},
			},
			bruteForceEnabled: false,
			expectedFindings:  0,
			wantErr:           false,
		},
		{
			name: "Handles malformed HAR JSON",
			analysisCtx: &core.AnalysisContext{
				Artifacts: &schemas.Artifacts{HAR: malformedJSON()},
			},
			bruteForceEnabled: false,
			expectedFindings:  0,
			wantErr:           true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.analysisCtx.Findings = []schemas.Finding{}
			analyzer := NewJWTAnalyzer(logger, tc.bruteForceEnabled)
			err := analyzer.Analyze(context.Background(), tc.analysisCtx)

			if (err != nil) != tc.wantErr {
				t.Fatalf("Analyze() error = %v, wantErr %v", err, tc.wantErr)
			}

			if !tc.wantErr && len(tc.analysisCtx.Findings) != tc.expectedFindings {
				t.Errorf("Expected %d findings, but got %d", tc.expectedFindings, len(tc.analysisCtx.Findings))
			}
		})
	}
}

// malformedJSON returns a json.RawMessage that is intentionally malformed.
func malformedJSON() *json.RawMessage {
	raw := json.RawMessage(`{"log": {"entries": "not-an-array"}}`)
	return &raw
}
