package jsexec_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/jsexec"
	"go.uber.org/zap"
)

// mockBrowserEnvironment is a stub implementation for testing purposes.
type mockBrowserEnvironment struct{}

func (m *mockBrowserEnvironment) JSNavigate(targetURL string)                                     {}
func (m *mockBrowserEnvironment) NotifyURLChange(targetURL string)                                {}
func (m *mockBrowserEnvironment) ExecuteFetch(ctx context.Context, req schemas.FetchRequest) (*schemas.FetchResponse, error) {
	return nil, nil
}
func (m *mockBrowserEnvironment) AddCookieFromString(cookieStr string) error { return nil }
func (m *mockBrowserEnvironment) GetCookieString() (string, error)           { return "", nil }
func (m *mockBrowserEnvironment) PushHistory(state *schemas.HistoryState) error    { return nil }
func (m *mockBrowserEnvironment) ReplaceHistory(state *schemas.HistoryState) error { return nil }
func (m *mockBrowserEnvironment) GetHistoryLength() int                        { return 0 }
func (m *mockBrowserEnvironment) GetCurrentHistoryState() interface{}          { return nil }
func (m *mockBrowserEnvironment) ResolveURL(targetURL string) (*url.URL, error) {
	return url.Parse(targetURL)
}

// newTestRuntime is a helper to set up a runtime with mock dependencies for each test.
func newTestRuntime(t *testing.T) *jsexec.Runtime {
	t.Helper() // Mark this as a test helper function.

	eventLoop := eventloop.NewEventLoop()

	// Use t.Cleanup to ensure the event loop is stopped after the test,
	// preventing leaked goroutines.
	t.Cleanup(func() {
		eventLoop.Stop()
	})

	// Start the event loop so it can process async tasks like setTimeout and Promises.
	eventLoop.Start()

	return jsexec.NewRuntime(zap.NewNop(), eventLoop, &mockBrowserEnvironment{})
}

func TestExecuteScript_Basic(t *testing.T) {
	runtime := newTestRuntime(t)
	ctx := context.Background()

	script := `(5 + 5) * 2`
	result, err := runtime.ExecuteScript(ctx, script, nil)

	require.NoError(t, err)
	assert.Equal(t, int64(20), result)
}

func TestExecuteScript_WithArgs(t *testing.T) {
	runtime := newTestRuntime(t)
	ctx := context.Background()

	script := `(function(prefix, message) { return prefix + message; })`
	args := []interface{}{"Log: ", "Hello World"}

	result, err := runtime.ExecuteScript(ctx, script, args)
	require.NoError(t, err)
	assert.Equal(t, "Log: Hello World", result)
}

func TestExecuteScript_ReturnObject(t *testing.T) {
	runtime := newTestRuntime(t)
	ctx := context.Background()
	script := `({status: "success", code: 200})`

	result, err := runtime.ExecuteScript(ctx, script, nil)
	require.NoError(t, err)

	resMap, ok := result.(map[string]interface{})
	require.True(t, ok, "Result should be a map")
	assert.Equal(t, "success", resMap["status"])
	assert.Equal(t, int64(200), resMap["code"])
}

func TestExecuteScript_Exception(t *testing.T) {
	runtime := newTestRuntime(t)
	ctx := context.Background()
	script := `throw new Error("Intentional Error");`

	_, err := runtime.ExecuteScript(ctx, script, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "javascript exception:")
	assert.Contains(t, err.Error(), "Intentional Error")
}

func TestExecuteScript_Timeout(t *testing.T) {
	runtime := newTestRuntime(t)
	// Context with a very short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Infinite loop to ensure the timeout is triggered.
	script := `while(true) {}`

	startTime := time.Now()
	_, err := runtime.ExecuteScript(ctx, script, nil)
	duration := time.Since(startTime)

	require.Error(t, err)
	// The refactored error message now wraps the context's error directly.
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "javascript execution interrupted by context")

	// Ensure it didn't run excessively long (allowing buffer).
	assert.Less(t, duration, 200*time.Millisecond)
}

func TestExecuteScript_Cancellation(t *testing.T) {
	runtime := newTestRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())

	script := `while(true) {}`

	errChan := make(chan error)
	go func() {
		_, err := runtime.ExecuteScript(ctx, script, nil)
		errChan <- err
	}()

	// Give the script a moment to start running.
	time.Sleep(50 * time.Millisecond)
	// Cancel the context to interrupt the script.
	cancel()

	select {
	case err := <-errChan:
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Contains(t, err.Error(), "javascript execution interrupted by context")
	case <-time.After(1 * time.Second):
		t.Fatal("Execution did not stop after cancellation")
	}
}

// -- New tests for Promise handling --

func TestExecuteScript_PromiseFulfilled(t *testing.T) {
	runtime := newTestRuntime(t)
	ctx := context.Background()

	// This script returns a promise that resolves after a short delay.
	// `setTimeout` requires the event loop provided in `newTestRuntime`.
	script := `new Promise(resolve => setTimeout(() => resolve('async success'), 50))`

	result, err := runtime.ExecuteScript(ctx, script, nil)
	require.NoError(t, err)
	assert.Equal(t, "async success", result)
}

func TestExecuteScript_PromiseRejected(t *testing.T) {
	runtime := newTestRuntime(t)
	ctx := context.Background()

	script := `new Promise((_, reject) => setTimeout(() => reject(new Error('async failure')), 50))`

	_, err := runtime.ExecuteScript(ctx, script, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "promise rejected")
	assert.Contains(t, err.Error(), "async failure")
}

func TestExecuteScript_PromiseTimeout(t *testing.T) {
	runtime := newTestRuntime(t)
	// Set a short timeout on the context.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// This promise takes longer to resolve than the context's timeout.
	script := `new Promise(resolve => setTimeout(() => resolve('this should not be seen'), 200))`

	_, err := runtime.ExecuteScript(ctx, script, nil)
	require.Error(t, err)
	// We expect the context's deadline to be the cause of the error.
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "context done while waiting for promise")
}
