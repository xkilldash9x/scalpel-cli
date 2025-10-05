package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// A helper to create a new test session, aligned with the current NewSession API.
func setupTestSession(t *testing.T) (*Session, *config.Config, chan schemas.Finding) {
	cfg := config.NewDefaultConfig()
	// Disable humanoid delays for faster, deterministic testing.
	cfg.Browser.Humanoid.Enabled = false
	cfg.Network.PostLoadWait = 10 * time.Millisecond // Short stabilization time.
	cfg.Network.CaptureResponseBodies = true         // Enable body capture for HAR tests.

	logger := zap.NewNop()
	findingsChan := make(chan schemas.Finding, 10)

	s, err := NewSession(context.Background(), cfg, schemas.DefaultPersona, logger, findingsChan)
	require.NoError(t, err, "NewSession should not return an error")

	// Use t.Cleanup to ensure the session is closed at the end of the test,
	// even if the test panics.
	t.Cleanup(func() {
		// Use a background context for cleanup to ensure it runs even if the test's context is canceled.
		assert.NoError(t, s.Close(context.Background()))
	})

	return s, cfg, findingsChan
}

// -- White Box Testing Helper --

// isElementChecked provides direct insight into the internal DOM state for an element.
// This is a white box approach, verifying the 'checked' attribute exists on the internal
// *html.Node, rather than executing more JS, which would be a black box check.
func isElementChecked(t *testing.T, s *Session, selector string) bool {
	// Acquire the operation lock to ensure a stable and consistent DOM state for inspection.
	ctx, unlock := s.acquireOpLock(context.Background())
	defer unlock()
	require.NoError(t, ctx.Err())

	// Use the internal findElementNode to get direct access to the DOM node.
	node, err := s.findElementNode(ctx, selector)
	require.NoError(t, err, "Failed to find node for selector: %s", selector)

	// Directly inspect the node's attributes for the 'checked' property.
	_, isChecked := getAttr(node, "checked")
	return isChecked
}

// -- Lifecycle and State Tests --

func TestSession_Lifecycle(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	assert.NotEmpty(t, s.ID())

	closed := false
	s.SetOnClose(func() {
		closed = true
	})

	// Manually call close for this specific lifecycle test.
	// Note: setupTestSession also registers a cleanup function to close the session.
	err := s.Close(context.Background())
	require.NoError(t, err)

	assert.True(t, closed, "onClose callback should be executed")

	// Verify the session is closed by attempting an operation.
	// It should fail because the session's master context is cancelled.
	_, err = s.ExecuteScript(context.Background(), "1+1", nil)
	assert.ErrorIs(t, err, context.Canceled, "Operations should fail with context.Canceled after session is closed")

	// Calling Close again should be a no-op and not cause errors.
	err = s.Close(context.Background())
	require.NoError(t, err)
}

func TestSession_NavigationAndStateUpdate(t *testing.T) {
	t.Parallel()
	// 1. Setup Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			// Verify User-Agent is set by the session
			assert.Equal(t, schemas.DefaultPersona.UserAgent, r.Header.Get("User-Agent"))
			fmt.Fprintln(w, `<html><head><title>Start Page</title></head><body><h1>Welcome</h1></body></html>`)
		}
	}))
	t.Cleanup(server.Close)

	// 2. Setup Session
	s, _, _ := setupTestSession(t)

	// 3. Navigate
	targetURL := server.URL + "/start"
	err := s.Navigate(context.Background(), targetURL)
	require.NoError(t, err)

	// 4. Verify State (White Box)
	// Directly inspect the internal 'currentURL' field to confirm the state update.
	s.mu.RLock()
	require.NotNil(t, s.currentURL, "Internal currentURL should not be nil after navigation")
	assert.Equal(t, targetURL, s.currentURL.String())
	s.mu.RUnlock()

	// Verify public-facing output as well
	assert.Equal(t, targetURL, s.GetCurrentURL())

	// Verify DOM snapshot
	snapshot, err := s.GetDOMSnapshot(context.Background())
	require.NoError(t, err)
	content, _ := io.ReadAll(snapshot)
	domContent := string(content)

	assert.Contains(t, domContent, "<title>Start Page</title>")
	assert.Contains(t, domContent, "<h1>Welcome</h1>")
}

func TestSession_HandleRedirect(t *testing.T) {
	t.Parallel()
	// 1. Setup Mock Server for redirection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			fmt.Fprintln(w, `<html></html>`)
		} else if r.URL.Path == "/redirect" {
			// Ensure the Referer header is set correctly during the redirect chain
			assert.Contains(t, r.Header.Get("Referer"), "/start")
			http.Redirect(w, r, "/final", http.StatusFound) // 302 Redirect
		} else if r.URL.Path == "/final" {
			assert.Contains(t, r.Header.Get("Referer"), "/redirect")
			fmt.Fprintln(w, `<html><title>Final Page</title></html>`)
		}
	}))
	t.Cleanup(server.Close)

	// 2. Setup Session
	s, _, _ := setupTestSession(t)

	// Initial navigation to set a base URL/Referer
	err := s.Navigate(context.Background(), server.URL+"/start")
	require.NoError(t, err)

	// 3. Navigate to the redirect URL
	err = s.Navigate(context.Background(), server.URL+"/redirect")
	require.NoError(t, err)

	// 4. Verify Final State (Session follows redirects manually)
	expectedURL := server.URL + "/final"
	assert.Equal(t, expectedURL, s.GetCurrentURL())
}

func TestSession_NavigationTimeout(t *testing.T) {
	t.Parallel()
	// Configure a very short request timeout
	timeoutDuration := 200 * time.Millisecond
	cfg := config.NewDefaultConfig()
	cfg.Network.NavigationTimeout = timeoutDuration
	cfg.Network.PostLoadWait = 0

	logger := zap.NewNop()
	s, err := NewSession(context.Background(), cfg, schemas.DefaultPersona, logger, nil)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close(context.Background()) })

	// Server that intentionally delays the response.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second) // Longer than the timeout.
		fmt.Fprintln(w, `<html><body>Slow response</body></html>`)
	}))
	t.Cleanup(server.Close)

	startTime := time.Now()
	// Navigation should fail with a timeout error.
	err = s.Navigate(context.Background(), server.URL)
	duration := time.Since(startTime)

	require.Error(t, err)

	// Verify the duration was respected by the client (should be close to 200ms, not 1s).
	assert.Less(t, duration, 500*time.Millisecond, "Navigation call did not respect the timeout duration")

	// Robustly check for timeout/deadline errors.
	isTimeout := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		isTimeout = true
	}

	assert.True(t, isTimeout, fmt.Sprintf("Error should be a timeout/deadline/cancellation error, but got: %v", err))
}

// -- Advanced Concurrency, Robustness, and Error Handling Tests --

// TestSession_ConcurrentAccess validates the high-level operation lock (opMu).
// It launches multiple goroutines that attempt to perform stateful operations
// on the same session instance simultaneously.
// This test is most effective when run with the "-race" flag (go test -race ./...).
func TestSession_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	var wg sync.WaitGroup
	numGoroutines := 20

	// This test uses ExecuteScript as the concurrent operation, as it's a primary
	// interaction point that involves the JS event loop and state access.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			script := fmt.Sprintf("1 + %d", n)
			var result float64
			// Each goroutine will attempt to acquire the opMu lock.
			rawResult, err := s.ExecuteScript(context.Background(), script, nil)
			if !assert.NoError(t, err, "Goroutine %d should execute script without error", n) {
				return
			}
			if !assert.NoError(t, json.Unmarshal(rawResult, &result), "Goroutine %d failed to unmarshal result", n) {
				return
			}
			assert.Equal(t, float64(1+n), result, "Goroutine %d received incorrect result", n)
		}(i)
	}

	wg.Wait()
}

// TestSession_ExecuteScript_PanicRecovery verifies that a panicking script
// does not kill the session's event loop, allowing subsequent operations to succeed.
// This validates the 'defer/recover' mechanism in the script execution path.
func TestSession_ExecuteScript_PanicRecovery(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	// Script designed to cause a panic in Goja (accessing a property on null).
	panickingScript := `(function() { return null; })().foo = 'bar';`

	// 1. Execute the panicking script.
	_, err := s.ExecuteScript(context.Background(), panickingScript, nil)
	require.Error(t, err, "Executing a panicking script should return an error")
	// The error might be reported as a JS exception or a recovered panic, depending on Goja's internal handling.
	assert.True(t, strings.Contains(err.Error(), "panic in javascript execution") || strings.Contains(err.Error(), "javascript exception"), "Error message should indicate failure")

	// 2. Execute a valid script afterwards.
	// If the event loop goroutine was killed by the panic, this call would time out or fail.
	var result float64
	rawResult, err := s.ExecuteScript(context.Background(), "2 + 2", nil)
	require.NoError(t, err, "A valid script should execute successfully after a panic")
	require.NoError(t, json.Unmarshal(rawResult, &result))
	assert.Equal(t, float64(4), result, "The result of the second script should be correct")
}

// TestSession_ExecuteScript_ContextCancellation verifies that a long-running script
// can be correctly interrupted by cancelling its context.
func TestSession_ExecuteScript_ContextCancellation(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	// An infinite loop script that will run until interrupted.
	infiniteLoopScript := `while (true) {}`

	// Create a context with a short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Execute the script. This should return an error when the context times out.
	_, err := s.ExecuteScript(ctx, infiniteLoopScript, nil)

	require.Error(t, err, "Script execution should be interrupted by context timeout")
	// Verify that the error is the expected context error.
	assert.ErrorIs(t, err, context.DeadlineExceeded, "Error should be context.DeadlineExceeded")
}

// -- DOM Interaction and State Tests --

func TestSession_ExecuteTypeAndSelect_StateUpdate(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		<html><body>
			<input type="text" id="username" value="old_value">
			<select id="options">
				<option value="A">A</option>
				<option value="B" selected="selected">B</option>
			</select>
			<textarea id="area">initial area text</textarea>
		</body></html>`)
	}))
	t.Cleanup(server.Close)

	s, _, _ := setupTestSession(t)
	err := s.Navigate(context.Background(), server.URL)
	require.NoError(t, err)

	// Execute Type (Input)
	newText := "test_user"
	err = s.Type(context.Background(), "//*[@id='username']", newText)
	require.NoError(t, err)

	// Execute Type (Textarea)
	areaText := "lorem ipsum"
	err = s.Type(context.Background(), "//*[@id='area']", areaText)
	require.NoError(t, err)

	// Execute Select
	newValue := "A"
	err = s.ExecuteSelect(context.Background(), "//*[@id='options']", newValue)
	require.NoError(t, err)

	// Verify Select using JavaScript (this is a good way to check the JS-visible state).
	var selectedValue string
	rawResult, err := s.ExecuteScript(context.Background(), `document.getElementById('options').value`, nil)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawResult, &selectedValue))
	assert.Equal(t, newValue, selectedValue)

	// Verify DOM State Update using GetDOMSnapshot (for input/textarea attributes)
	snapshot, err := s.GetDOMSnapshot(context.Background())
	require.NoError(t, err)
	content, _ := io.ReadAll(snapshot)
	domContent := string(content)

	// The internal DOM state should reflect the new values in attributes/content.
	// NOTE: This checks the serialized DOM. The JS property check above is often more reliable
	// for dynamic state that doesn't always reflect to an attribute.
	assert.Contains(t, domContent, fmt.Sprintf(`value="%s"`, newText))
	assert.Contains(t, domContent, `>lorem ipsum</textarea>`)
}

// TestSession_ExecuteClick_Consequences validates the side-effects of clicking various elements.
func TestSession_ExecuteClick_Consequences(t *testing.T) {
	t.Parallel()
	var finalURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalURL = r.URL.String()
		if r.Method == http.MethodPost {
			r.ParseForm()
			fmt.Fprintln(w, `<html><title>POST Success</title></html>`)
		} else if r.URL.Path == "/start" {
			fmt.Fprintln(w, `
				<html><body>
					<a id="navLink" href="/target?id=123">Navigate</a>
					<input type="checkbox" id="check1">
					<input type="checkbox" id="check2" checked="checked">
					<input type="radio" name="r_group" id="radio1" value="r1">
					<input type="radio" name="r_group" id="radio2" value="r2" checked="checked">
					<form action="/post_target" method="POST" id="form1"><button type="submit" id="submitBtn">Submit</button></form>
				</body></html>`)
		} else {
			fmt.Fprintln(w, `<html><title>Final</title></html>`)
		}
	}))
	t.Cleanup(server.Close)

	s, _, _ := setupTestSession(t)

	// -- Test 1: Navigation Click (<a>) --
	t.Run("AnchorClick", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `//*[@id='navLink']`))
		assert.Equal(t, server.URL+"/target?id=123", s.GetCurrentURL())
	})

	// -- Test 2: Checkbox Toggle (White Box) --
	t.Run("CheckboxToggle", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `//*[@id='check1']`))
		require.NoError(t, s.Click(context.Background(), `//*[@id='check2']`))

		// Use the white box helper to inspect the internal DOM directly.
		assert.True(t, isElementChecked(t, s, `//*[@id='check1']`), "check1 should be checked")
		assert.False(t, isElementChecked(t, s, `//*[@id='check2']`), "check2 should be unchecked")
	})

	// -- Test 3: Radio Selection (White Box) --
	t.Run("RadioSelect", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `//*[@id='radio1']`))

		// Use the white box helper for direct state verification.
		assert.True(t, isElementChecked(t, s, `//*[@id='radio1']`), "radio1 should be selected")
		assert.False(t, isElementChecked(t, s, `//*[@id='radio2']`), "radio2 should be deselected")
	})

	// -- Test 4: Form Submission Click --
	t.Run("SubmitButtonClick", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `//*[@id='submitBtn']`))
		assert.Equal(t, server.URL+"/post_target", s.GetCurrentURL())
		assert.Contains(t, finalURL, "/post_target")
	})
}

func TestSession_FormSubmission_POST(t *testing.T) {
	t.Parallel()
	var submittedData string
	var contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprintln(w, `
			<html><body>
				<form action="/submit" method="POST" id="loginForm">
					<input type="text" name="username" value="testuser">
					<input type="checkbox" name="remember" checked>
					<input type="submit" value="Login">
				</form>
			</body></html>`)
		} else if r.Method == http.MethodPost && r.URL.Path == "/submit" {
			r.ParseForm()
			bodyBytes, _ := io.ReadAll(r.Body)
			submittedData = string(bodyBytes) // Read raw body for exact match
			contentType = r.Header.Get("Content-Type")
			fmt.Fprintln(w, `<html><title>Success</title></html>`)
		}
	}))
	t.Cleanup(server.Close)

	s, _, _ := setupTestSession(t)
	err := s.Navigate(context.Background(), server.URL)
	require.NoError(t, err)

	// Update a field first to verify serialization uses the current DOM state
	require.NoError(t, s.Type(context.Background(), `//input[@name="username"]`, "new_user"))

	// Submit the form by clicking the submit button
	err = s.Submit(context.Background(), `//input[@type="submit"]`)
	require.NoError(t, err)

	// Verify Submission Data received by the server. This is a robust end-to-end check.
	// url.Values.Encode() sorts keys alphabetically.
	expectedData := "remember=on&username=new_user"
	assert.Equal(t, expectedData, submittedData)
	assert.Equal(t, "application/x-www-form-urlencoded", contentType)

	// Verify Navigation occurred
	expectedURL := server.URL + "/submit"
	assert.Equal(t, expectedURL, s.GetCurrentURL())
}

// -- Utility and Artifact Tests --

func TestSession_ExecuteScript_GojaIntegration(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	// Test simple return value
	var result float64
	rawResult, err := s.ExecuteScript(context.Background(), "3 + 4", nil)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawResult, &result))
	assert.Equal(t, float64(7), result)

	// Test complex return object
	var obj map[string]interface{}
	script := `({"status": "ok", "message": "hello", "count": 123});`
	rawResult, err = s.ExecuteScript(context.Background(), script, nil)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawResult, &obj))
	assert.Equal(t, "ok", obj["status"])
	assert.Equal(t, "hello", obj["message"])
	assert.Equal(t, float64(123), obj["count"]) // JSON numbers are float64

	// Test error handling for a JS exception
	_, err = s.ExecuteScript(context.Background(), "throw new TypeError('JS Fail')", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "javascript exception")
	assert.Contains(t, err.Error(), "JS Fail")
}

func TestSession_ArtifactCollection(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Test HAR</title></head><body>Content Body</body></html>`)
	}))
	t.Cleanup(server.Close)

	s, _, findingsChan := setupTestSession(t)

	// Navigate to create a HAR entry
	require.NoError(t, s.Navigate(context.Background(), server.URL))

	// Add a finding to the channel
	testFinding := schemas.Finding{Vulnerability: schemas.Vulnerability{Name: "XSS Detected"}, Severity: schemas.SeverityHigh}
	require.NoError(t, s.AddFinding(context.Background(), testFinding))

	// Collect Artifacts
	artifacts, err := s.CollectArtifacts(context.Background())
	require.NoError(t, err)
	require.NotNil(t, artifacts)

	// Verify Final DOM
	assert.Contains(t, artifacts.DOM, "<title>Test HAR</title>")

	// Verify HAR data
	require.NotNil(t, artifacts.HAR)
	var harData schemas.HAR
	require.NoError(t, json.Unmarshal(*artifacts.HAR, &harData))
	require.Len(t, harData.Log.Entries, 1, "Expected one HAR entry for navigation")
	assert.Equal(t, server.URL, harData.Log.Entries[0].Request.URL)
	assert.Contains(t, harData.Log.Entries[0].Response.Content.Text, "Content Body")

	// Verify the finding was received
	select {
	case found := <-findingsChan:
		assert.Equal(t, testFinding.Vulnerability.Name, found.Vulnerability.Name)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timed out waiting for finding to be reported")
	}
}

func TestCombineContext(t *testing.T) {
	t.Parallel()

	t.Run("ParentCancels", func(t *testing.T) {
		parentCtx, parentCancel := context.WithCancel(context.Background())
		secondaryCtx, secondaryCancel := context.WithCancel(context.Background())
		defer secondaryCancel()

		combined, cancel := CombineContext(parentCtx, secondaryCtx)
		defer cancel()

		parentCancel()
		<-combined.Done()
		assert.ErrorIs(t, combined.Err(), context.Canceled)
	})

	t.Run("SecondaryCancels", func(t *testing.T) {
		parentCtx, parentCancel := context.WithCancel(context.Background())
		secondaryCtx, secondaryCancel := context.WithCancel(context.Background())
		defer parentCancel()

		combined, cancel := CombineContext(parentCtx, secondaryCtx)
		defer cancel()

		secondaryCancel()
		<-combined.Done()
		assert.ErrorIs(t, combined.Err(), context.Canceled)
	})
}