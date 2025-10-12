// internal/session/session_test.go
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// A helper to create a new test session, aligned with the current NewSession API.
func setupTestSession(t *testing.T) (*Session, config.Interface, chan schemas.Finding) {
	cfg := config.NewDefaultConfig()

	// Use setters to modify config, adhering to the interface contract.
	cfg.SetBrowserHumanoidEnabled(false)
	cfg.SetNetworkPostLoadWait(10 * time.Millisecond) // Short stabilization time.
	cfg.SetNetworkCaptureResponseBodies(true)         // Enable body capture for HAR tests.

	// Use Nop logger for cleaner test output. Use zap.NewDevelopment() for debugging.
	logger := zap.NewNop()
	findingsChan := make(chan schemas.Finding, 10)

	s, err := NewSession(context.Background(), cfg, schemas.DefaultPersona, logger, findingsChan)
	require.NoError(t, err, "NewSession should not return an error")

	// Use t.Cleanup to ensure the session is closed at the end of the test.
	t.Cleanup(func() {
		// Use a background context for cleanup.
		assert.NoError(t, s.Close(context.Background()))
	})

	return s, cfg, findingsChan
}

// -- White Box Testing Helper --

// isElementChecked provides direct insight into the internal DOM state for an element.
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

	err := s.Close(context.Background())
	require.NoError(t, err)

	assert.True(t, closed, "onClose callback should be executed")

	// Verify the session is closed by attempting an operation.
	// It should fail because the session's master context is cancelled or the pool is closed.
	_, err = s.ExecuteScript(context.Background(), "1+1", nil)
	assert.Error(t, err)
	isCanceled := errors.Is(err, context.Canceled)
	isClosed := strings.Contains(err.Error(), "session closed") || strings.Contains(err.Error(), "vm pool closed")
	assert.True(t, isCanceled || isClosed, "Operations should fail after session is closed, got: %v", err)

	// Calling Close again should be a no-op.
	err = s.Close(context.Background())
	require.NoError(t, err)
}

func TestSession_NavigationAndStateUpdate(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			assert.Equal(t, schemas.DefaultPersona.UserAgent, r.Header.Get("User-Agent"))
			fmt.Fprintln(w, `<html><head><title>Start Page</title></head><body><h1>Welcome</h1></body></html>`)
		}
	}))
	t.Cleanup(server.Close)

	s, _, _ := setupTestSession(t)

	targetURL := server.URL + "/start"
	err := s.Navigate(context.Background(), targetURL)
	require.NoError(t, err)

	s.mu.RLock()
	require.NotNil(t, s.currentURL, "Internal currentURL should not be nil after navigation")
	assert.Equal(t, targetURL, s.currentURL.String())
	s.mu.RUnlock()

	assert.Equal(t, targetURL, s.GetCurrentURL())

	snapshot, err := s.GetDOMSnapshot(context.Background())
	require.NoError(t, err)
	content, _ := io.ReadAll(snapshot)
	domContent := string(content)

	assert.Contains(t, domContent, "<title>Start Page</title>")
	assert.Contains(t, domContent, "<h1>Welcome</h1>")
}

func TestSession_HandleRedirect(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			fmt.Fprintln(w, `<html></html>`)
		case "/redirect":
			assert.Contains(t, r.Header.Get("Referer"), "/start")
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			assert.Contains(t, r.Header.Get("Referer"), "/redirect")
			fmt.Fprintln(w, `<html><title>Final Page</title></html>`)
		}
	}))
	t.Cleanup(server.Close)

	s, _, _ := setupTestSession(t)
	err := s.Navigate(context.Background(), server.URL+"/start")
	require.NoError(t, err)
	err = s.Navigate(context.Background(), server.URL+"/redirect")
	require.NoError(t, err)

	expectedURL := server.URL + "/final"
	assert.Equal(t, expectedURL, s.GetCurrentURL())
}

func TestSession_NavigationTimeout(t *testing.T) {
	t.Parallel()
	timeoutDuration := 200 * time.Millisecond
	cfg := config.NewDefaultConfig()
	cfg.SetNetworkNavigationTimeout(timeoutDuration)
	cfg.SetNetworkPostLoadWait(0)

	logger := zap.NewNop()
	s, err := NewSession(context.Background(), cfg, schemas.DefaultPersona, logger, nil)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close(context.Background()) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		fmt.Fprintln(w, `<html><body>Slow response</body></html>`)
	}))
	t.Cleanup(server.Close)

	startTime := time.Now()
	err = s.Navigate(context.Background(), server.URL)
	duration := time.Since(startTime)

	require.Error(t, err)
	assert.Less(t, duration, 500*time.Millisecond, "Navigation call did not respect the timeout duration")

	isTimeout := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		isTimeout = true
	}
	assert.True(t, isTimeout, fmt.Sprintf("Error should be a timeout/deadline/cancellation error, but got: %v", err))
}

// -- Advanced Concurrency, Robustness, and Error Handling Tests --

func TestSession_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)

			script := fmt.Sprintf("1 + %d", n)
			var result float64
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

func TestSession_ExecuteScript_PanicRecovery(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)
	panickingScript := `(function() { return null; })().foo = 'bar';`

	_, err := s.ExecuteScript(context.Background(), panickingScript, nil)
	require.Error(t, err, "Executing a panicking script should return an error")

	isException := strings.Contains(err.Error(), "javascript exception")
	isPanic := strings.Contains(err.Error(), "panic during script execution") || strings.Contains(err.Error(), "panic before javascript execution")
	assert.True(t, isException || isPanic, fmt.Sprintf("Error message should indicate exception or panic, but got: %v", err))

	var result float64
	rawResult, err := s.ExecuteScript(context.Background(), "2 + 2", nil)
	require.NoError(t, err, "A valid script should execute successfully after a panic")
	require.NoError(t, json.Unmarshal(rawResult, &result))
	assert.Equal(t, float64(4), result, "The result of the second script should be correct")
}

func TestSession_ExecuteScript_ContextCancellation(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)
	infiniteLoopScript := `while (true) {}`

	timeout := 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	startTime := time.Now()
	_, err := s.ExecuteScript(ctx, infiniteLoopScript, nil)
	duration := time.Since(startTime)

	require.Error(t, err, "Script execution should be interrupted by context timeout")
	assert.ErrorIs(t, err, context.DeadlineExceeded, "Error should be context.DeadlineExceeded")
	assert.Contains(t, err.Error(), "javascript execution interrupted by context")
	assert.Less(t, duration, timeout*3, "Cancellation took significantly longer than the timeout.")
}

func TestSession_ExecuteScript_CancellationRaceCondition(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	iterations := 100
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		script := `"quick"`
		var result string
		rawResult, err := s.ExecuteScript(ctx, script, nil)

		cancel()

		if err != nil {
			assert.ErrorIs(t, err, context.Canceled, fmt.Sprintf("Iteration %d: Should be canceled if it errors, got: %v", i, err))
		} else {
			require.NoError(t, json.Unmarshal(rawResult, &result), fmt.Sprintf("Iteration %d: Failed to unmarshal result", i))
			assert.Equal(t, "quick", result, fmt.Sprintf("Iteration %d: Incorrect result", i))
		}

		var checkResult float64
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer checkCancel()
		checkRaw, checkErr := s.ExecuteScript(checkCtx, "1+1", nil)

		if assert.NoError(t, checkErr, fmt.Sprintf("Iteration %d: VM pool is unhealthy. Error: %v", i, checkErr)) {
			require.NoError(t, json.Unmarshal(checkRaw, &checkResult))
			assert.Equal(t, float64(2), checkResult)
		}
	}
}

func TestSession_VM_AcquisitionCancellation(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	ctx := context.Background()
	checkedOutVMs := []*goja.Runtime{}
	poolSize := 0

	s.mu.RLock()
	pool := s.vmPool
	s.mu.RUnlock()
	require.NotNil(t, pool, "VM pool is nil")

	for {
		getTOCtx, cancelGetTO := context.WithTimeout(ctx, 20*time.Millisecond)
		vm, err := pool.Get(getTOCtx)
		cancelGetTO()
		if err != nil {
			break
		}
		checkedOutVMs = append(checkedOutVMs, vm)
		poolSize++
	}

	t.Logf("Inferred VM pool size: %d", poolSize)
	require.NotZero(t, poolSize, "VM pool appears empty, cannot run test.")

	ctxTimeout, cancelTimeout := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelTimeout()

	startTime := time.Now()
	_, err := pool.Get(ctxTimeout)
	duration := time.Since(startTime)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, duration, 300*time.Millisecond, "Acquisition did not respect the timeout.")

	for _, vm := range checkedOutVMs {
		pool.Put(vm)
	}
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

	newText := "test_user"
	err = s.Type(context.Background(), "#username", newText)
	require.NoError(t, err)

	areaText := "lorem ipsum"
	err = s.Type(context.Background(), "#area", areaText)
	require.NoError(t, err)

	newValue := "A"
	err = s.ExecuteSelect(context.Background(), "#options", newValue)
	require.NoError(t, err)

	var selectedValue string
	rawResult, err := s.ExecuteScript(context.Background(), `document.getElementById('options').value`, nil)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawResult, &selectedValue))
	assert.Equal(t, newValue, selectedValue)

	snapshot, err := s.GetDOMSnapshot(context.Background())
	require.NoError(t, err)
	content, _ := io.ReadAll(snapshot)
	domContent := string(content)

	assert.Contains(t, domContent, fmt.Sprintf(`value="%s"`, newText))
	assert.Contains(t, domContent, `>lorem ipsum</textarea>`)
}

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

	t.Run("AnchorClick", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `#navLink`))
		assert.Equal(t, server.URL+"/target?id=123", s.GetCurrentURL())
	})

	t.Run("CheckboxToggle", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `#check1`))
		require.NoError(t, s.Click(context.Background(), `#check2`))
		assert.True(t, isElementChecked(t, s, `#check1`), "check1 should be checked")
		assert.False(t, isElementChecked(t, s, `#check2`), "check2 should be unchecked")
	})

	t.Run("RadioSelect", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `#radio1`))
		assert.True(t, isElementChecked(t, s, `#radio1`), "radio1 should be selected")
		assert.False(t, isElementChecked(t, s, `#radio2`), "radio2 should be deselected")
	})

	t.Run("SubmitButtonClick", func(t *testing.T) {
		require.NoError(t, s.Navigate(context.Background(), server.URL+"/start"))
		require.NoError(t, s.Click(context.Background(), `#submitBtn`))
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
			bodyBytes, _ := io.ReadAll(r.Body)
			submittedData = string(bodyBytes)
			contentType = r.Header.Get("Content-Type")
			fmt.Fprintln(w, `<html><title>Success</title></html>`)
		}
	}))
	t.Cleanup(server.Close)

	s, _, _ := setupTestSession(t)
	err := s.Navigate(context.Background(), server.URL)
	require.NoError(t, err)

	require.NoError(t, s.Type(context.Background(), `input[name="username"]`, "new_user"))
	err = s.Submit(context.Background(), `input[type="submit"]`)
	require.NoError(t, err)

	expectedData := "remember=on&username=new_user"
	assert.Equal(t, expectedData, submittedData)
	assert.Equal(t, "application/x-www-form-urlencoded", contentType)
	expectedURL := server.URL + "/submit"
	assert.Equal(t, expectedURL, s.GetCurrentURL())
}

// -- Utility and Artifact Tests --

func TestSession_ExecuteScript_GojaIntegration(t *testing.T) {
	t.Parallel()
	s, _, _ := setupTestSession(t)

	var result float64
	rawResult, err := s.ExecuteScript(context.Background(), "3 + 4", nil)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawResult, &result))
	assert.Equal(t, float64(7), result)

	var obj map[string]interface{}
	script := `({"status": "ok", "message": "hello", "count": 123});`
	rawResult, err = s.ExecuteScript(context.Background(), script, nil)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawResult, &obj))
	assert.Equal(t, "ok", obj["status"])
	assert.Equal(t, "hello", obj["message"])
	assert.Equal(t, float64(123), obj["count"])

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
	require.NoError(t, s.Navigate(context.Background(), server.URL))
	testFinding := schemas.Finding{Vulnerability: schemas.Vulnerability{Name: "XSS Detected"}, Severity: schemas.SeverityHigh}
	require.NoError(t, s.AddFinding(context.Background(), testFinding))

	artifacts, err := s.CollectArtifacts(context.Background())
	require.NoError(t, err)
	require.NotNil(t, artifacts)

	assert.Contains(t, artifacts.DOM, "<title>Test HAR</title>")

	require.NotNil(t, artifacts.HAR)
	var harData schemas.HAR
	require.NoError(t, json.Unmarshal(*artifacts.HAR, &harData))
	require.Len(t, harData.Log.Entries, 1, "Expected one HAR entry for navigation")
	assert.Equal(t, server.URL, harData.Log.Entries[0].Request.URL)
	assert.Contains(t, harData.Log.Entries[0].Response.Content.Text, "Content Body")

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
