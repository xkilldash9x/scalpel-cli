// internal/analysis/static/jwt/jwt_fuzz_test.go

package jwt

import (
	"strings"

	"testing"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// FuzzAnalyzeToken validates the core JWT analysis logic (AnalyzeToken).

// It ensures that the analyzer can handle a wide range of inputs and configurations

// without panics and that the analysis results adhere to expected security invariants.

func FuzzAnalyzeToken(f *testing.F) {

	// -- Seed Corpus --

	// A strategic seed corpus provides the fuzzer with diverse starting points.

	// The target signature is (string, bool), so we must provide both.

	// Helper function to add seeds for both bruteForceEnabled states (true and false)

	addSeed := func(token string) {

		f.Add(token, true)

		f.Add(token, false)

	}

	// 1. Valid Tokens

	// A valid HS256 signed token (Example from jwt.io).

	addSeed("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

	// A valid RS256 signed token (tests parsing of different algorithms).

	addSeed("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.TCYt5XsITJX1CxPCT8yAV-TVkIEq_d_4jw3B4PAadV_j84Zbwxv-sMM2tQ-2g4i9dG68rt_h_Xso_3aGz2gBCg")

	// 2. Known Vulnerabilities and Checks

	// A valid HS256 token signed with the weak secret "secret".

	// This ensures the fuzzer explores the WeakSecretVulnerability path when enabled.

	// Payload: {"sub": "weak"}, Secret: "secret"

	addSeed("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3ZWFrIn0.B9M_YX3UuI0-N5y0T-32lU99ac33q9R0VpC8c9_a25w")

	// A token with "alg: none" (CWE-347).

	addSeed("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.")

	// Token with sensitive data (e.g., "password" claim). Payload: {"password": "test"}

	addSeed("eyJhbGciOiJIUzI1NiJ9.eyJwYXNzd29yZCI6InRlc3QifQ.invalid_sig")

	// Token missing expiration ('exp' claim).

	addSeed("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.invalid_sig")

	// 3. Malformed/Edge cases

	addSeed("")

	addSeed(".")

	addSeed("..")

	addSeed("a.b.c")

	addSeed("a.b.")

	addSeed(".b.c")

	// Invalid characters for Base64Url encoding

	f.Add("header%.payload.signature", false)

	// Invalid JSON in payload (base64 for "invalid-json" = aW52YWxpZC1qc29u)

	f.Add("eyJhbGciOiJIUzI1NiJ9.aW52YWxpZC1qc29u.signature", false)

	// -- Fuzz Target --

	// The fuzzer will call this function repeatedly, mutating both the token string

	// and the bruteForceEnabled flag simultaneously.

	f.Fuzz(func(t *testing.T, tokenString string, bruteForceEnabled bool) {

		// 1. Panic Safety (CWE-400: Uncontrolled Resource Consumption)

		// The primary requirement is that the analysis logic must never panic.

		// A panic represents a potential Denial-of-Service vulnerability.

		defer func() {

			if r := recover(); r != nil {

				// Use t.Fatalf to ensure the fuzzer recognizes this as a crash and saves the input.

				t.Fatalf("AnalyzeToken panicked. Input: %q, bruteForceEnabled: %v. Error: %v", tokenString, bruteForceEnabled, r)

			}

		}()

		// 2. Call the function under test.

		result, err := AnalyzeToken(tokenString, bruteForceEnabled)

		// 3. Assertions and Invariant Checks

		// Invariant: TokenString must always match the input due to struct initialization.

		if result.TokenString != tokenString {

			t.Errorf("Invariant violated: Resulting TokenString does not match input. Expected: %q, Got: %q", tokenString, result.TokenString)

		}

		// Invariant: Error vs. Results Consistency

		// If an error occurred during parsing (ParseUnverified failure), the result should be minimal.

		if err != nil {

			if len(result.Findings) > 0 {

				t.Errorf("Invariant violated: Error returned but findings were generated. Input: %q, Err: %v", tokenString, err)

			}

			// Header and Claims should be nil if parsing failed.

			if result.Header != nil || result.Claims != nil {

				t.Errorf("Invariant violated: Error returned but Header/Claims were populated. Input: %q, Err: %v", tokenString, err)

			}

			// If there's an error, we stop further analysis for this iteration.

			return

		}

		// Invariant: Success Guarantees

		// If parsing succeeded, Header/Claims must be populated.

		if result.Header == nil {

			t.Errorf("Invariant violated: Parsing succeeded but Header is nil. Input: %q", tokenString)

			return // Cannot proceed with header-dependent checks

		}

		// Claims can be empty (e.g., {}), but the map itself should not be nil.

		if result.Claims == nil {

			t.Errorf("Invariant violated: Parsing succeeded but Claims map is nil. Input: %q", tokenString)

		}

		// Safely access the algorithm from the header for subsequent checks

		alg, algOk := "", false

		if a, ok := result.Header["alg"].(string); ok {

			alg = a

			algOk = true

		}

		// Invariant: AlgNone Correctness (CWE-347)

		// The finding and the header must be consistent (checking for false positives and negatives).

		foundAlgNone := false

		for _, finding := range result.Findings {

			if finding.Type == AlgNoneVulnerability {

				foundAlgNone = true

				break

			}

		}

		if foundAlgNone {

			// False Positive Check: If the finding is reported, the header must exist and be 'none'.

			if !algOk || !strings.EqualFold(alg, "none") {

				t.Errorf("Invariant violated (False Positive): AlgNoneVulnerability reported, but header 'alg' is missing or not 'none'. Input: %q, Header: %v", tokenString, result.Header)

			}

		} else {

			// False Negative Check: If the finding is NOT reported, the algorithm must NOT be 'none'.

			if algOk && strings.EqualFold(alg, "none") {

				t.Errorf("Invariant violated (False Negative): 'alg: none' detected in header, but AlgNoneVulnerability finding is missing. Input: %q", tokenString)

			}

		}

		// Invariant: Brute Force Logic (CWE-326)

		// WeakSecretVulnerability must be consistent with inputs and token type.

		foundWeakSecret := false

		var weakSecretFinding *Finding

		for i, finding := range result.Findings {

			if finding.Type == WeakSecretVulnerability {

				foundWeakSecret = true

				weakSecretFinding = &result.Findings[i]

				break

			}

		}

		if foundWeakSecret {

			// Precondition 1: Brute force must have been enabled.

			if !bruteForceEnabled {

				t.Errorf("Invariant violated: WeakSecretVulnerability found but bruteForceEnabled was false. Input: %q", tokenString)

			}

			// Precondition 2: The algorithm must be HMAC-based (HS*).

			if !algOk || !strings.HasPrefix(alg, "HS") {

				t.Errorf("Invariant violated: WeakSecretVulnerability found but algorithm is missing or not HS*. Input: %q, Alg: %v", tokenString, alg)

			}

			// Data Integrity: The finding details must contain the cracked key.

			if weakSecretFinding.Detail == nil || weakSecretFinding.Detail["key"] == "" {

				t.Errorf("Invariant violated: WeakSecretVulnerability found but 'key' detail is missing or empty. Input: %q", tokenString)

			}

		}

		// Invariant: Finding Structure Validation

		for _, finding := range result.Findings {

			if finding.Severity == schemas.Severity("") {

				t.Errorf("Invariant violated: Finding has empty severity. Input: %q, Finding Type: %v", tokenString, finding.Type)

			}

			if finding.Description == "" {

				t.Errorf("Invariant violated: Finding has empty description. Input: %q, Finding Type: %v", tokenString, finding.Type)

			}

		}

	})

}
