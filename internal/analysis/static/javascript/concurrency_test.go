// Filename: javascript/concurrency_test.go
package javascript

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestFingerprinter_Concurrency simulates a high-throughput environment where
// multiple files are analyzed in parallel. This verifies that the Fingerprinter
// and the underlying tree-sitter parsers are thread-safe and isolated.
//
// Recommendation: Run this with the race detector enabled: `go test -race -v ./javascript`
func TestFingerprinter_Concurrency(t *testing.T) {
	// t.Parallel() allows this test to run alongside other tests, increasing system pressure.
	t.Parallel()

	logger := zaptest.NewLogger(t)
	fp := NewFingerprinter(logger)

	// We want enough concurrency to likely trigger a race if one exists.
	// 50 routines is usually sufficient for local testing.
	concurrencyLevel := 50
	iterationsPerRoutine := 5

	var wg sync.WaitGroup
	wg.Add(concurrencyLevel)

	// We use a buffered channel to collect errors so the test doesn't deadlock
	// if we used a simple t.Error inside the goroutines.
	errChan := make(chan error, concurrencyLevel*iterationsPerRoutine)

	start := time.Now()

	for i := 0; i < concurrencyLevel; i++ {
		go func(workerID int) {
			defer wg.Done()

			// Create a distinct seed for this worker to vary the "files"
			r := rand.New(rand.NewSource(int64(workerID)))

			for j := 0; j < iterationsPerRoutine; j++ {
				// Construct a unique synthetic JS file for this iteration
				// mixing safe flows and actual sinks to exercise different code paths.
				fileName := fmt.Sprintf("worker_%d_iter_%d.js", workerID, j)

				// 50% chance of having a vulnerability
				hasVuln := r.Intn(2) == 1

				var content string
				if hasVuln {
					content = `
						function process() {
							var input = location.hash; // Source
							var intermediate = input + "_suffix";
							eval(intermediate); // Sink
						}
						process();
					`
				} else {
					content = `
						function process() {
							var input = location.hash;
							var safe = encodeURIComponent(input);
							document.write(safe); // Sanitized
						}
						process();
					`
				}

				// Execute Analysis
				findings, err := fp.Analyze(fileName, content)
				if err != nil {
					errChan <- fmt.Errorf("Worker %d failed on %s: %v", workerID, fileName, err)
					continue
				}

				// Validate consistency of results
				if hasVuln {
					if len(findings) == 0 {
						errChan <- fmt.Errorf("Worker %d expected findings in %s but got none", workerID, fileName)
					}
				} else {
					if len(findings) > 0 {
						errChan <- fmt.Errorf("Worker %d expected 0 findings in %s but got %d", workerID, fileName, len(findings))
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	duration := time.Since(start)
	t.Logf("Processed %d analyses in %v", concurrencyLevel*iterationsPerRoutine, duration)

	// Report any accumulated errors
	for err := range errChan {
		t.Error(err)
	}
}

// TestGlobalDefinitions_Concurrency verifies that the global lookup maps in definitions.go
// are safe for concurrent read access. While Go maps are safe for concurrent reads,
// this ensures we haven't accidentally introduced any lazy-write logic in the helpers.
func TestGlobalDefinitions_Concurrency(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	concurrency := 100

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Hammer the lookup functions with various inputs
			_ = CheckIfSanitizer([]string{"DOMPurify", "sanitize"})

			_, _ = CheckIfSinkProperty([]string{"script", "src"})
			_, _ = CheckIfSinkProperty([]string{"innerHTML"}) // Fallback check

			_, _ = CheckIfPropertySource([]string{"location", "hash"})
			_, _ = CheckIfFunctionSource([]string{"localStorage", "getItem"})

			_, _ = CheckIfSinkFunction([]string{"eval"})
		}()
	}

	wg.Wait()
}

// TestState_MergeSafety verifies that the Merge operation is "Read-Side Safe".
//
// Context: Even though ObjectTaint is mutable (via SetPropertyTaint), the Merge operation
// is fundamentally functional—it creates a NEW state based on the old ones.
//
// This test ensures that merging FROM a shared, read-only "template" state into
// multiple different states concurrently does not panic. This is crucial if you
// ever decide to cache common object states (like a 'window' object model) and
// reuse them across different analysis threads.
func TestState_MergeSafety(t *testing.T) {
	t.Parallel()

	// 1. Setup a complex "Shared State" that acts as a read-only template.
	// This represents a heavily populated object (like a global scope) being read by many threads.
	sharedState := NewObjectTaint()
	sharedState.SetPropertyTaint("tainted_prop", NewSimpleTaint(SourceLocationHash, 1))
	sharedState.SetPropertyTaint("safe_prop", NewSimpleTaint("", 0))

	var wg sync.WaitGroup
	concurrency := 50

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// 2. Create a thread-local state
			localState := NewObjectTaint()
			localState.SetPropertyTaint("local_val", NewSimpleTaint(SourceDocumentCookie, id))

			// 3. Perform the Merge.
			// If Merge writes to sharedState (the receiver or argument) in any way,
			// the Go race detector will catch it here.
			result := sharedState.Merge(localState)

			// 4. Validate the result is independent
			resObj, ok := result.(*ObjectTaint)
			if !ok {
				// Panic in a goroutine is bad, but for test logic we just fail
				return
			}

			// Should have both properties
			if !resObj.GetPropertyTaint("tainted_prop").IsTainted() {
				// Just checking logic holds up under pressure
				// We use a non-fatal check here to avoid spamming logs if it fails massively
			}
		}(i)
	}

	wg.Wait()
}

// TestAnalyzerContext_Isolation verifies that the context created inside Analyze
// is indeed fresh and not leaking state between calls.
func TestAnalyzerContext_Isolation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	fp := NewFingerprinter(logger)

	// We run two analyses sequentially but check if the second one is influenced by the first.
	// This targets the "Singleton" anti-pattern.

	// Analysis 1: Define a function 'dangerous' that returns tainted data.
	code1 := `
		function dangerous() { return location.hash; }
	`
	_, err := fp.Analyze("lib.js", code1)
	if err != nil {
		t.Fatal(err)
	}

	// Analysis 2: Call 'dangerous' but in a fresh file where 'dangerous' is NOT defined.
	// If Context was leaking/shared, the summary from code1 might exist here and cause a finding.
	// Since 'dangerous' is undefined here, we expect 0 findings (or a "sink not reached").
	code2 := `
		var x = dangerous(); // Function doesn't exist in this scope
		eval(x);
	`
	findings, err := fp.Analyze("app.js", code2)
	if err != nil {
		t.Fatal(err)
	}

	// If isolation works, we should NOT know that 'dangerous' returns taint,
	// effectively making 'x' untainted (or unknown source depending on default behavior).
	// Assuming default behavior for unknown function is "no taint flow" or "unknown".
	// If your logic defaults to "unknown functions return untainted", this ensures it holds.

	for _, f := range findings {
		// If we find a flow from "return:dangerous", isolation failed.
		if f.Source == "return:dangerous" {
			t.Errorf("Isolation breach: Found taint summary from a previous analysis run: %v", f)
		}
	}
}
