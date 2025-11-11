// internal/analysis/static/jwt/token_logic_test.go
package jwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Helper function to create a JWT for testing purposes.
func createTestJWT(alg string, claims jwt.MapClaims, secret interface{}) (string, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("invalid signing algorithm: %s", alg)
	}
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(secret)
}

func TestAnalyzeToken(t *testing.T) {
	// A consistent secret for signing test tokens
	testSecret := []byte("test-secret")

	// Pre-generate tokens to avoid errors in test cases
	noAlgToken, _ := createTestJWT("none", jwt.MapClaims{"sub": "123"}, jwt.UnsafeAllowNoneSignatureType)
	hs256Token, _ := createTestJWT("HS256", jwt.MapClaims{"sub": "123", "exp": time.Now().Add(time.Hour).Unix()}, testSecret)
	weakSecretToken, _ := createTestJWT("HS256", jwt.MapClaims{"sub": "weak-secret"}, []byte("secret"))
	sensitiveDataToken, _ := createTestJWT("HS256", jwt.MapClaims{"password": "12345"}, testSecret)
	noExpToken, _ := createTestJWT("HS256", jwt.MapClaims{"sub": "no-exp"}, testSecret)

	testCases := []struct {
		name              string
		tokenString       string
		bruteForceEnabled bool
		wantFindings      []FindingType
		wantErr           bool
	}{
		{
			name:              "Valid HS256 Token",
			tokenString:       hs256Token,
			bruteForceEnabled: false,
			wantFindings:      []FindingType{},
			wantErr:           false,
		},
		{
			name:              "Alg None Vulnerability",
			tokenString:       noAlgToken,
			bruteForceEnabled: false,
			wantFindings:      []FindingType{AlgNoneVulnerability, MissingExpiration}, // Also missing expiration
			wantErr:           false,
		},
		{
			name:              "Weak Secret Vulnerability - Brute Force Enabled",
			tokenString:       weakSecretToken,
			bruteForceEnabled: true,
			wantFindings:      []FindingType{WeakSecretVulnerability, MissingExpiration},
			wantErr:           false,
		},
		{
			name:              "Weak Secret Vulnerability - Brute Force Disabled",
			tokenString:       weakSecretToken,
			bruteForceEnabled: false,
			wantFindings:      []FindingType{MissingExpiration}, // Should not find weak secret
			wantErr:           false,
		},
		{
			name:              "Sensitive Info Exposure",
			tokenString:       sensitiveDataToken,
			bruteForceEnabled: false,
			wantFindings:      []FindingType{SensitiveInfoExposure, MissingExpiration},
			wantErr:           false,
		},
		{
			name:              "Missing Expiration",
			tokenString:       noExpToken,
			bruteForceEnabled: false,
			wantFindings:      []FindingType{MissingExpiration},
			wantErr:           false,
		},
		{
			name:              "Malformed Token - Not Enough Parts",
			tokenString:       "a.b",
			bruteForceEnabled: false,
			wantFindings:      nil,
			wantErr:           true,
		},
		{
			name:              "Malformed Token - Invalid Base64",
			tokenString:       "a.b.c%",
			bruteForceEnabled: false,
			wantFindings:      nil,
			wantErr:           true,
		},
		{
			name:              "Empty Token String",
			tokenString:       "",
			bruteForceEnabled: false,
			wantFindings:      nil,
			wantErr:           true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := AnalyzeToken(tc.tokenString, tc.bruteForceEnabled)

			if (err != nil) != tc.wantErr {
				t.Fatalf("AnalyzeToken() error = %v, wantErr %v", err, tc.wantErr)
			}

			if err == nil {
				if len(result.Findings) != len(tc.wantFindings) {
					t.Fatalf("Expected %d findings, but got %d. Findings: %+v", len(tc.wantFindings), len(result.Findings), result.Findings)
				}

				// Check if the types of findings match
				foundTypes := make(map[FindingType]bool)
				for _, f := range result.Findings {
					foundTypes[f.Type] = true
				}

				for _, wantType := range tc.wantFindings {
					if !foundTypes[wantType] {
						t.Errorf("Expected to find finding of type %v, but did not.", wantType)
					}
				}
			}
		})
	}
}

func TestContainsSensitiveData(t *testing.T) {
	testCases := []struct {
		name   string
		claims jwt.MapClaims
		want   bool
	}{
		{"Contains 'password'", jwt.MapClaims{"password": "123"}, true},
		{"Contains 'api_key'", jwt.MapClaims{"api_key": "xyz"}, true},
		{"Contains 'SSN'", jwt.MapClaims{"SSN": "000-00-0000"}, true},
		{"No sensitive data", jwt.MapClaims{"sub": "123", "user": "test"}, false},
		{"Empty claims", jwt.MapClaims{}, false},
		{"Case-insensitivity check", jwt.MapClaims{"PassWord": "123"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsSensitiveData(tc.claims); got != tc.want {
				t.Errorf("containsSensitiveData() = %v, want %v", got, tc.want)
			}
		})
	}
}

// -- Benchmarks --

var benchmarkToken, _ = createTestJWT("HS256", jwt.MapClaims{
	"sub": "benchmark-sub",
	"iat": time.Now().Unix(),
	"exp": time.Now().Add(time.Hour).Unix(),
}, []byte("a-very-secure-secret-that-wont-be-guessed"))

var benchmarkWeakToken, _ = createTestJWT("HS256", jwt.MapClaims{
	"sub": "benchmark-weak",
	"iat": time.Now().Unix(),
}, []byte("password123"))

func BenchmarkAnalyzeToken_NoBruteForce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		AnalyzeToken(benchmarkToken, false)
	}
}

func BenchmarkAnalyzeToken_WithBruteForce_NoMatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		AnalyzeToken(benchmarkToken, true)
	}
}

func BenchmarkAnalyzeToken_WithBruteForce_Match(b *testing.B) {
	for i := 0; i < b.N; i++ {
		AnalyzeToken(benchmarkWeakToken, true)
	}
}
