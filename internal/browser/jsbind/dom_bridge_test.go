// internal/browser/jsbind/dom_bridge_test.go
package jsbind

import (
	"context"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/html"

	"github.comcom/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Mock BrowserEnvironment --

// MockBrowserEnvironment implements the BrowserEnvironment interface for testing using testify/mock.
// This provides a more structured way to assert expectations compared to a manual mock.
type MockBrowserEnvironment struct {
	mock.Mock
	mu         sync.RWMutex
	currentURL *url.URL
}

// NewMockBrowserEnvironment creates a new mock environment.
func NewMockBrowserEnvironment(initialURL string) *MockBrowserEnvironment {
	u, err := url.Parse(initialURL)
	if err != nil {
		panic("invalid initialURL for mock environment: " + err.Error())
	}
	return &MockBrowserEnvironment{
		currentURL: u,
	}
}

func (m *MockBrowserEnvironment) JSNavigate(targetURL string) {
	// To ensure subsequent calls to ResolveURL work as expected after a navigation,
	// we update the internal URL state here.
	m.mu.Lock()
	resolved, err := m.resolveURLInternal(targetURL)
	if err == nil {
		m.currentURL = resolved
	}
	m.mu.Unlock()
	m.Called(targetURL)
}

func (m *MockBrowserEnvironment) NotifyURLChange(targetURL string) {
	m.mu.Lock()
	resolved, err := m.resolveURLInternal(targetURL)
	if err == nil {
		m.currentURL = resolved
	}
	m.mu.Unlock()
	m.Called(targetURL)
}

func (m *MockBrowserEnvironment) ExecuteFetch(ctx context.Context, req schemas.FetchRequest) (*schemas.FetchResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.FetchResponse), args.Error(1)
}

func (m *MockBrowserEnvironment) AddCookieFromString(cookieStr string) error {
	args := m.Called(cookieStr)
	return args.Error(0)
}

func (m *MockBrowserEnvironment) GetCookieString() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockBrowserEnvironment) PushHistory(state *schemas.HistoryState) error {
	args := m.Called(state)
	return args.Error(0)
}

func (m *MockBrowserEnvironment) ReplaceHistory(state *schemas.HistoryState) error {
	args := m.Called(state)
	return args.Error(0)
}

func (m *MockBrowserEnvironment) GetHistoryLength() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockBrowserEnvironment) GetCurrentHistoryState() interface{} {
	args := m.Called()
	return args.Get(0)
}

// ResolveURL provides a real implementation for convenience, as most tests rely on it
// functioning correctly without needing to assert its calls.
func (m *MockBrowserEnvironment) ResolveURL(targetURL string) (*url.URL, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resolveURLInternal(targetURL)
}

func (m *MockBrowserEnvironment) resolveURLInternal(targetURL string) (*url.URL, error) {
	base := m.currentURL
	if base == nil {
		// Fallback just in case.
		base, _ = url.Parse("about:blank")
	}
	return base.Parse(targetURL)
}

// -- Test Setup Utilities --

type TestEnvironment struct {
	Bridge  *DOMBridge
	MockEnv *MockBrowserEnvironment
	Logger  *zap.Logger
	T       *testing.T
}

// SetupTest initializes a testing environment without a persistent event loop.
func SetupTest(t *testing.T, initialHTML string, initialURL string) *TestEnvironment {
	t.Helper()
	logger := zaptest.NewLogger(t)
	mockEnv := NewMockBrowserEnvironment(initialURL)
	bridge := NewDOMBridge(logger, mockEnv, schemas.DefaultPersona)

	doc, err := html.Parse(initialHTML)
	require.NoError(t, err)
	bridge.UpdateDOM(doc)

	return &TestEnvironment{
		Bridge:  bridge,
		MockEnv: mockEnv,
		Logger:  logger,
		T:       t,
	}
}

// RunJS simulates the sync.Pool pattern by creating a new VM for each execution.
func (te *TestEnvironment) RunJS(script string) (goja.Value, error) {
	vm := goja.New()
	te.Bridge.BindToRuntime(vm, te.MockEnv.currentURL.String())

	// Provide a basic console.log for debugging within tests.
	vm.Set("console", map[string]interface{}{
		"log": func(args ...interface{}) {
			te.Logger.Info("JS console.log", zap.Any("args", args))
		},
	})
	// Polyfill Event constructor for tests that dispatch events.
	vm.RunString(`
        if (typeof Event === 'undefined') {
            function Event(type, options) { this.type = type; }
            window.Event = Event;
        }
    `)

	return vm.RunString(script)
}

// MustRunJS is a helper that runs a script and fails the test on error.
func (te *TestEnvironment) MustRunJS(script string) goja.Value {
	te.T.Helper()
	val, err := te.RunJS(script)
	require.NoError(te.T, err)
	return val
}

// -- Test Cases --

// Note: TestTimers has been removed as the synchronous model does not support them.

func TestFormSubmissionPOSTUrlEncoded(t *testing.T) {
	html := `
        <html><body>
            <form action="/submit" method="POST">
                <input type="text" name="username" value="John&Doe">
                <textarea name="comments">Hello!</textarea>
                <input type="submit" id="submitBtn" name="action" value="Submit">
            </form>
        </body></html>
    `
	te := SetupTest(t, html, "http://example.com/home")
	mockEnv := te.MockEnv

	// Set up the mock expectation for the fetch call.
	mockEnv.On("ExecuteFetch", mock.Anything, mock.MatchedBy(func(req schemas.FetchRequest) bool {
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "http://example.com/submit", req.URL)
		assert.Equal(t, "action=Submit&comments=Hello%21&username=John%26Doe", string(req.Body))

		var contentType string
		for _, h := range req.Headers {
			if h.Name == "Content-Type" {
				contentType = h.Value
			}
		}
		assert.Equal(t, "application/x-www-form-urlencoded", contentType)
		return true
	})).Return(&schemas.FetchResponse{Status: 200}, nil).Once()

	// This is now a blocking call.
	te.MustRunJS(`document.getElementById('submitBtn').click()`)

	// Verify that the expected call was made.
	mockEnv.AssertExpectations(t)
}

func TestFormSubmissionPOSTMultipart(t *testing.T) {
	html := `
        <html><body>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="text" name="field1" value="value1">
                <input type="submit" id="submitBtn">
            </form>
        </body></html>
    `
	te := SetupTest(t, html, "http://example.com/home")
	mockEnv := te.MockEnv

	// Set up the mock expectation.
	mockEnv.On("ExecuteFetch", mock.Anything, mock.MatchedBy(func(req schemas.FetchRequest) bool {
		assert.Equal(t, "http://example.com/upload", req.URL)

		var contentType string
		for _, header := range req.Headers {
			if header.Name == "Content-Type" {
				contentType = header.Value
			}
		}
		assert.Contains(t, contentType, "multipart/form-data; boundary=")
		body := string(req.Body)
		assert.Contains(t, body, `Content-Disposition: form-data; name="field1"`)
		assert.Contains(t, body, "value1")
		return true
	})).Return(&schemas.FetchResponse{Status: 200}, nil).Once()

	// Trigger the submission.
	te.MustRunJS(`document.getElementById('submitBtn').click()`)

	// Assert that the mock was called as expected.
	mockEnv.AssertExpectations(t)
}

func TestFormSubmissionGET(t *testing.T) {
	html := `
		<html><body>
			<form action="/search" method="GET">
				<input type="text" name="q" value="test query">
				<button type="submit" id="submitBtn"></button>
			</form>
		</body></html>
	`
	te := SetupTest(t, html, "http://example.com/home")
	mockEnv := te.MockEnv

	expectedURL := "http://example.com/search?q=test+query"
	mockEnv.On("JSNavigate", expectedURL).Return().Once()

	te.MustRunJS(`document.getElementById('submitBtn').click()`)

	mockEnv.AssertExpectations(t)
}

// TestConcurrencyAndRaceDetection now more accurately reflects the sync.Pool model.
// Run with `go test -race` to verify thread safety.
func TestConcurrencyAndRaceDetection(t *testing.T) {
	te := SetupTest(t, "<html><body><div id='content'>Initial</div></body></html>", "http://example.com")

	var wg sync.WaitGroup
	iterations := 50

	// Each goroutine simulates getting a fresh VM from the pool via te.RunJS.
	// This tests the internal locking of the DOMBridge itself.
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		script := fmt.Sprintf(`document.body.setAttribute('data-js', %d);`, i)
		go func() {
			defer wg.Done()
			_, _ = te.RunJS(script)
		}()
	}

	// Concurrent Go tasks that read/write the DOMBridge state.
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, err := te.Bridge.GetOuterHTML()
				assert.NoError(t, err)
			} else {
				newDoc, _ := html.Parse(strings.NewReader(fmt.Sprintf("<html><body>Go %d</body></html>", i)))
				te.Bridge.UpdateDOM(newDoc)
			}
		}(i)
	}

	wg.Wait()
	// The test passes if the race detector is silent.
}

// TestMemoryLeakPrevention is adapted for the synchronous, per-call VM model.
func TestMemoryLeakPrevention(t *testing.T) {
	createAndBreakCycle := func() {
		// In this model, the VM and its resources are self-contained within a single
		// function call and are immediately eligible for GC, simplifying leak prevention.
		type LeakyResource struct {
			Data     [1024 * 1024]byte
			Callback func()
		}
		resource := &LeakyResource{}

		vm := goja.New()
		vm.Set("resource", resource)
		script := `(function() { return function() { const d = resource.Data.length; }; })()`
		jsFuncVal, err := vm.RunString(script)
		require.NoError(t, err)

		jsFunc, ok := goja.AssertFunction(jsFuncVal)
		require.True(t, ok)

		// Create the Go -> JS -> Go reference cycle.
		resource.Callback = func() {
			_, _ = jsFunc(goja.Undefined())
		}
		// In a real application, the cycle would be broken by setting resource.Callback = nil.
		// Here, the resource and VM go out of scope together, so the GC can collect them.
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	for i := 0; i < 10; i++ {
		createAndBreakCycle()
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	memoryIncreaseMB := (m2.HeapAlloc - m1.HeapAlloc) / 1024 / 1024
	assert.Less(t, memoryIncreaseMB, uint64(5), "Potential memory leak detected.")
}
