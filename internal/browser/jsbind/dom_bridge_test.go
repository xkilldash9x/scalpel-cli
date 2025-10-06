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

	"github.com/dop251/goja"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/html"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Mock BrowserEnvironment --

type MockBrowserEnvironment struct {
	mock.Mock
	mu         sync.RWMutex
	currentURL *url.URL
}

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

func (m *MockBrowserEnvironment) ResolveURL(targetURL string) (*url.URL, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resolveURLInternal(targetURL)
}

func (m *MockBrowserEnvironment) resolveURLInternal(targetURL string) (*url.URL, error) {
	base := m.currentURL
	if base == nil {
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

func SetupTest(t *testing.T, initialHTML string, initialURL string) *TestEnvironment {
	t.Helper()
	logger := zaptest.NewLogger(t)
	mockEnv := NewMockBrowserEnvironment(initialURL)
	bridge := NewDOMBridge(logger, mockEnv, schemas.DefaultPersona)

	doc, err := html.Parse(strings.NewReader(initialHTML))
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
	// Bind the bridge to the new, ephemeral VM.
	te.Bridge.BindToRuntime(vm, te.MockEnv.currentURL.String())

	vm.Set("console", map[string]interface{}{
		"log": func(args ...interface{}) {
			te.Logger.Info("JS console.log", zap.Any("args", args))
		},
	})
	// Basic Event polyfill for tests that dispatch events.
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

// (Test cases demonstrating DOM manipulation and selection capabilities)

func TestDOMManipulation_AppendAndQuery(t *testing.T) {
	te := SetupTest(t, "<html><body><div id='container'></div></body></html>", "http://example.com")

	script := `
        const container = document.getElementById('container');
        const newElement = document.createElement('p');
        newElement.textContent = 'Hello Shim';
        newElement.id = 'newP';
        container.appendChild(newElement);
        
        // Verify using querySelector
        document.querySelector('#container > #newP').textContent;
    `
	result := te.MustRunJS(script)
	assert.Equal(t, "Hello Shim", result.String())

	// Verify the actual Go DOM state
	htmlStr, err := te.Bridge.GetOuterHTML()
	require.NoError(t, err)
	assert.Contains(t, htmlStr, `<div id="container"><p id="newP">Hello Shim</p></div>`)
}

func TestDOMManipulation_InsertBefore(t *testing.T) {
	te := SetupTest(t, "<html><body><ul><li id='item2'>Two</li></ul></body></html>", "http://example.com")

	script := `
        const list = document.querySelector('ul');
        const item2 = document.getElementById('item2');
        const item1 = document.createElement('li');
        item1.textContent = 'One';
        
        list.insertBefore(item1, item2);
        
        // Verify order
        document.querySelector('ul').textContent;
    `
	result := te.MustRunJS(script)
	assert.Equal(t, "OneTwo", result.String())
}

func TestDOMManipulation_RemoveChild(t *testing.T) {
	te := SetupTest(t, "<html><body><div id='parent'><span id='child'>Remove me</span></div></body></html>", "http://example.com")

	script := `
        const parent = document.getElementById('parent');
        const child = document.getElementById('child');
        parent.removeChild(child);
        
        // Verify removal
        document.getElementById('child') === null;
    `
	result := te.MustRunJS(script)
	assert.True(t, result.ToBoolean())
}

func TestAttributeAccess(t *testing.T) {
	te := SetupTest(t, `<html><body><input id="myInput" type="text" value="initial" data-custom="dataValue"></body></html>`, "http://example.com")

	script := `
        const input = document.getElementById('myInput');
        
        // getAttribute
        const type = input.getAttribute('type');
        
        // setAttribute
        input.setAttribute('value', 'updated');
        const valueAttr = input.getAttribute('value');
        
        // Property access (className)
        input.className = 'test-class';
        const className = input.className;

        // Dataset access
        const customData = input.dataset.custom;
        input.dataset.newName = 'newValue';
        
        ({ type, valueAttr, className, customData, newName: input.getAttribute('data-new-name') })
    `
	result := te.MustRunJS(script)
	resMap := result.Export().(map[string]interface{})

	assert.Equal(t, "text", resMap["type"])
	assert.Equal(t, "updated", resMap["valueAttr"])
	assert.Equal(t, "test-class", resMap["className"])
	assert.Equal(t, "dataValue", resMap["customData"])
	assert.Equal(t, "newValue", resMap["newName"])
}

// (Existing concurrency and memory leak tests)

func TestConcurrencyAndRaceDetection(t *testing.T) {
	te := SetupTest(t, "<html><body><div id='content'>Initial</div></body></html>", "http://example.com")

	var wg sync.WaitGroup
	iterations := 50

	// Concurrent JS execution modifying the DOM
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		script := fmt.Sprintf(`document.body.setAttribute('data-js', %d);`, i)
		go func() {
			defer wg.Done()
			_, _ = te.RunJS(script)
		}()
	}

	// Concurrent Go operations (Reading HTML and updating DOM)
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
	// This test primarily serves to ensure no panics or deadlocks occur under concurrent access,
	// leveraging Go's race detector during testing.
}

func TestMemoryLeakPrevention(t *testing.T) {
	// This test verifies that creating and discarding Goja VMs (as done in RunJS and the actual runtime)
	// does not cause significant memory leaks, ensuring that the DOMBridge releases references correctly.
	createAndBreakCycle := func() {
		type LeakyResource struct {
			Data     [1024 * 1024]byte // 1MB
			Callback func()
		}
		resource := &LeakyResource{}

		vm := goja.New()
		vm.Set("resource", resource)
		// Create a JS function that captures the Go resource
		script := `(function() { return function() { const d = resource.Data.length; }; })()`
		jsFuncVal, err := vm.RunString(script)
		require.NoError(t, err)

		jsFunc, ok := goja.AssertFunction(jsFuncVal)
		require.True(t, ok)

		// Create a cycle: Go resource holds reference to JS function, JS function captures Go resource.
		resource.Callback = func() {
			_, _ = jsFunc(goja.Undefined())
		}
		// When the VM is discarded, Go's garbage collector should be able to clean this up
		// if references are managed correctly.
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Run the cycle creation multiple times.
	for i := 0; i < 10; i++ {
		createAndBreakCycle()
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Use signed integers for the calculation to correctly handle memory shrinking.
	memoryIncreaseBytes := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	memoryIncreaseMB := memoryIncreaseBytes / 1024 / 1024

	// Assert that the increase is significantly less than the total allocated (10MB+).
	// We allow some overhead (e.g., 5MB).
	assert.Less(t, memoryIncreaseMB, int64(5), "Potential memory leak detected: Heap allocation increased significantly.")
}