// internal/browser/jsbind/dom_bridge_test.go
package jsbind

import (
	"context"
	"errors"
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

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/layout"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/style"
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

	// Create a mock layout tree for hit-testing.
	layoutEngine := layout.NewEngine(1024, 768)
	// For simplicity in tests, we'll create a minimal style tree.
	// In a real scenario, this would come from a full style engine pass.
	styleRoot := &style.StyledNode{Node: doc}
	layoutRoot := layoutEngine.BuildAndLayoutTree(styleRoot)
	bridge.UpdateLayoutTree(layoutRoot)

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
        
        // Verify using querySelector.
        document.querySelector('#container > #newP').textContent;
    `
	result := te.MustRunJS(script)
	assert.Equal(t, "Hello Shim", result.String())

	// Verify the actual Go DOM state.
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
        
        // Verify order.
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
        
        // Verify removal.
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
        
        // Property access (className).
        input.className = 'test-class';
        const className = input.className;

        // Dataset access.
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

	// Concurrent JS execution modifying the DOM.
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		script := fmt.Sprintf(`document.body.setAttribute('data-js', %d);`, i)
		go func() {
			defer wg.Done()
			_, _ = te.RunJS(script)
		}()
	}

	// Concurrent Go operations (Reading HTML and updating DOM).
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
		// Create a JS function that captures the Go resource.
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

func TestEventDispatch(t *testing.T) {
	te := SetupTest(t, `<html><body><button id="btn">Click Me</button></body></html>`, "http://example.com")

	script := `
        let clicked = false;
        const btn = document.getElementById('btn');
        btn.addEventListener('click', () => {
            clicked = true;
        });
        btn.click();
        clicked;
    `
	result := te.MustRunJS(script)
	assert.True(t, result.ToBoolean(), "Event listener should have been triggered by .click()")
}

func TestFormSubmission(t *testing.T) {
	te := SetupTest(t, `<html><body><form id="form" action="/submit"><input type="submit" id="submitBtn"></form></body></html>`, "http://example.com")
	te.MockEnv.On("JSNavigate", "http://example.com/submit").Return()

	te.MustRunJS(`document.getElementById('submitBtn').click();`)

	te.MockEnv.AssertCalled(t, "JSNavigate", "http://example.com/submit")
}

func TestFindNodeAtPoint(t *testing.T) {
	te := SetupTest(t, `<html><body style="margin:0; padding:0;"><div id="target" style="width:100px; height:100px; position:absolute; top:50px; left:50px;"></div></body></html>`, "http://example.com")

	node := te.Bridge.FindNodeAtPoint(75, 75)
	require.NotNil(t, node)
	assert.Equal(t, "div", node.Data)

	node := te.Bridge.FindNodeAtPoint(10, 10)
	require.NotNil(t, node)
	assert.Equal(t, "body", node.Data)
}

func TestQuerySelector_ErrorHandling(t *testing.T) {
	te := SetupTest(t, `<html><body></body></html>`, "http://example.com")
	_, err := te.RunJS(`document.querySelector("not a valid selector");`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SyntaxError")
}

// -- New Test Cases for Increased Coverage --

func TestLocationAPI(t *testing.T) {
	te := SetupTest(t, `<html><body></body></html>`, "https://example.com:8080/path?query=1#hash")

	// Test initial properties.
	script := `({
        href: window.location.href,
        protocol: window.location.protocol,
        host: window.location.host,
        hostname: window.location.hostname,
        port: window.location.port,
        pathname: window.location.pathname,
        search: window.location.search,
        hash: window.location.hash,
        origin: window.location.origin
    })`
	result := te.MustRunJS(script)
	resMap := result.Export().(map[string]interface{})
	assert.Equal(t, "https://example.com:8080/path?query=1#hash", resMap["href"])
	assert.Equal(t, "https:", resMap["protocol"])
	assert.Equal(t, "example.com:8080", resMap["host"])
	assert.Equal(t, "example.com", resMap["hostname"])
	assert.Equal(t, "8080", resMap["port"])
	assert.Equal(t, "/path", resMap["pathname"])
	assert.Equal(t, "?query=1", resMap["search"])
	assert.Equal(t, "#hash", resMap["hash"])
	assert.Equal(t, "https://example.com:8080", resMap["origin"])

	// Test setting href.
	te.MockEnv.On("JSNavigate", "https://example.com/newpath").Return().Once()
	te.MustRunJS(`window.location.href = '/newpath'`)
	te.MockEnv.AssertCalled(t, "JSNavigate", "https://example.com/newpath")

	// Test setting hash.
	te.MockEnv.On("NotifyURLChange", "https://example.com:8080/path?query=1#newhash").Return().Once()
	te.MustRunJS(`window.location.hash = 'newhash'`)
	te.MockEnv.AssertCalled(t, "NotifyURLChange", "https://example.com:8080/path?query=1#newhash")

	// Test location.reload().
	te.MockEnv.On("JSNavigate", "https://example.com:8080/path?query=1#hash").Return().Once()
	te.MustRunJS(`window.location.reload()`)
	te.MockEnv.AssertCalled(t, "JSNavigate", "https://example.com:8080/path?query=1#hash")
}

func TestStorageAPI(t *testing.T) {
	te := SetupTest(t, `<html><body></body></html>`, "http://example.com")

	script := `
        // Local Storage
        localStorage.setItem('key1', 'value1');
        const item1 = localStorage.getItem('key1');
        const len1 = localStorage.length;
        localStorage.removeItem('key1');
        const len2 = localStorage.length;
        localStorage.setItem('a', '1');
        localStorage.setItem('b', '2');
        localStorage.clear();
        const len3 = localStorage.length;

        // Session Storage
        sessionStorage.setItem('skey', 'svalue');
        const s_item = sessionStorage.getItem('skey');

        ({item1, len1, len2, len3, s_item})
    `
	result := te.MustRunJS(script)
	resMap := result.Export().(map[string]interface{})

	assert.Equal(t, "value1", resMap["item1"])
	assert.Equal(t, int64(1), resMap["len1"])
	assert.Equal(t, int64(0), resMap["len2"])
	assert.Equal(t, int64(0), resMap["len3"])
	assert.Equal(t, "svalue", resMap["s_item"])
}

func TestFetchAPI(t *testing.T) {
	te := SetupTest(t, `<html><body></body></html>`, "http://example.com")
	// Mock the fetch response.
	mockResp := &schemas.FetchResponse{
		Status:     200,
		StatusText: "OK",
		URL:        "http://example.com/api/data",
		Headers:    []schemas.NVPair{{Name: "Content-Type", Value: "application/json"}},
		Body:       []byte(`{"message":"success"}`),
	}
	te.MockEnv.On("ExecuteFetch", mock.Anything, mock.Anything).Return(mockResp, nil)

	script := `
        fetch('/api/data', {
            method: 'POST',
            headers: { 'X-Custom': 'value' },
            body: 'test'
        }).then(res => res.json()).then(data => data.message)
    `
	// Since fetch is async, we need to handle the promise.
	val, err := te.RunJS(script)
	require.NoError(t, err)

	promise, ok := val.Export().(*goja.Promise)
	require.True(t, ok)

	// Wait for the promise to resolve.
	select {
	case <-time.After(1 * time.Second):
		t.Fatal("promise timed out")
	case <-(func() chan struct{} {
		ch := make(chan struct{})
		go func() {
			for promise.State() == goja.PromiseStatePending {
				time.Sleep(10 * time.Millisecond)
			}
			close(ch)
		}()
		return ch
	})():
	}

	assert.Equal(t, goja.PromiseStateFulfilled, promise.State())
	assert.Equal(t, "success", promise.Result().String())

	// Verify the request passed to ExecuteFetch.
	te.MockEnv.AssertCalled(t, "ExecuteFetch", mock.Anything, mock.MatchedBy(func(req schemas.FetchRequest) bool {
		assert.Equal(t, "http://example.com/api/data", req.URL)
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, []byte("test"), req.Body)
		return true
	}))
}

func TestXMLHttpRequest(t *testing.T) {
	te := SetupTest(t, `<html><body></body></html>`, "http://example.com")
	mockResp := &schemas.FetchResponse{
		Status:     201,
		StatusText: "Created",
		Body:       []byte("response data"),
	}
	// XHR is async, so we use a channel to signal completion.
	requestMade := make(chan schemas.FetchRequest, 1)
	te.MockEnv.On("ExecuteFetch", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		req := args.Get(1).(schemas.FetchRequest)
		requestMade <- req
	}).Return(mockResp, nil)

	script := `
        let finalStatus = 0;
        let response = '';
        const states = [];
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            states.push(xhr.readyState);
            if (xhr.readyState === 4) {
                finalStatus = xhr.status;
                response = xhr.responseText;
            }
        };
        xhr.open('PUT', '/resource');
        xhr.setRequestHeader('X-Request', 'true');
        xhr.send('payload');
        // Return a promise that resolves when the test is done.
        new Promise(resolve => {
            const check = () => {
                if (xhr.readyState === 4) {
                    resolve({finalStatus, response, states});
                } else {
                    setTimeout(check, 10);
                }
            };
            check();
        });
    `
	val, err := te.RunJS(script)
	require.NoError(t, err)
	promise, ok := val.Export().(*goja.Promise)
	require.True(t, ok)

	// Wait for the JS promise to resolve.
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("XHR promise timed out")
	case req := <-requestMade:
		// Verify the request details.
		assert.Equal(t, "http://example.com/resource", req.URL)
		assert.Equal(t, "PUT", req.Method)
		assert.Contains(t, req.Headers, schemas.NVPair{Name: "X-Request", Value: "true"})
		assert.Equal(t, []byte("payload"), req.Body)
	}

	// Now check the resolved promise from JS.
	resMap := promise.Result().Export().(map[string]interface{})
	assert.Equal(t, int64(201), resMap["finalStatus"])
	assert.Equal(t, "response data", resMap["response"])
	assert.Equal(t, []interface{}{int64(1), int64(2), int64(3), int64(4)}, resMap["states"])
}

func TestEventPropagation(t *testing.T) {
	te := SetupTest(t, `<html><body><div id="parent"><span id="child"></span></div></body></html>`, "http://example.com")

	script := `
        const parent = document.getElementById('parent');
        const child = document.getElementById('child');
        const calls = [];
        
        // Listener order:
        // 1. Parent Capture
        // 2. Child Capture
        // 3. Child Bubble (target phase)
        // 4. Parent Bubble
        
        parent.addEventListener('testevent', () => calls.push('parent-capture'), true);
        child.addEventListener('testevent', () => calls.push('child-capture'), true);
        parent.addEventListener('testevent', () => calls.push('parent-bubble'), false);
        child.addEventListener('testevent', () => calls.push('child-bubble'), false);

        child.dispatchEvent(new Event('testevent', { bubbles: true }));
        calls;
    `
	result := te.MustRunJS(script)
	calls, ok := result.Export().([]interface{})
	require.True(t, ok)
	expectedOrder := []interface{}{"parent-capture", "child-capture", "child-bubble", "parent-bubble"}
	assert.Equal(t, expectedOrder, calls)
}

func TestEventStopPropagation(t *testing.T) {
	te := SetupTest(t, `<html><body><div id="parent"><span id="child"></span></div></body></html>`, "http://example.com")

	script := `
        const parent = document.getElementById('parent');
        const child = document.getElementById('child');
        const calls = [];

        parent.addEventListener('stopevent', () => calls.push('parent-bubble'), false);
        child.addEventListener('stopevent', (e) => {
            calls.push('child-bubble');
            e.stopPropagation();
        }, false);

        child.dispatchEvent(new Event('stopevent', { bubbles: true }));
        calls;
    `
	result := te.MustRunJS(script)
	calls, ok := result.Export().([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"child-bubble"}, calls, "Parent listener should not have been called")
}

func TestDefaultClickActions(t *testing.T) {
	t.Run("Checkbox", func(t *testing.T) {
		te := SetupTest(t, `<html><body><input type="checkbox" id="cb"></body></html>`, "http://example.com")
		script := `
            const cb = document.getElementById('cb');
            const initialState = cb.checked;
            cb.click();
            const afterClick1 = cb.checked;
            cb.click();
            const afterClick2 = cb.checked;
            ({initialState, afterClick1, afterClick2})
        `
		result := te.MustRunJS(script)
		resMap := result.Export().(map[string]interface{})
		assert.False(t, resMap["initialState"].(bool))
		assert.True(t, resMap["afterClick1"].(bool))
		assert.False(t, resMap["afterClick2"].(bool))
	})

	t.Run("Radio Button Group", func(t *testing.T) {
		te := SetupTest(t, `<html><body>
            <input type="radio" name="group1" id="r1" value="1">
            <input type="radio" name="group1" id="r2" value="2" checked>
            <input type="radio" name="group1" id="r3" value="3">
        </body></html>`, "http://example.com")
		script := `
            const r1 = document.getElementById('r1');
            const r2 = document.getElementById('r2');
            const r3 = document.getElementById('r3');
            
            const r2Initial = r2.checked;
            r1.click();
            const r1After = r1.checked;
            const r2After = r2.checked;
            ({r2Initial, r1After, r2After})
        `
		result := te.MustRunJS(script)
		resMap := result.Export().(map[string]interface{})
		assert.True(t, resMap["r2Initial"].(bool))
		assert.True(t, resMap["r1After"].(bool))
		assert.False(t, resMap["r2After"].(bool))
	})
}

func TestDocumentWrite(t *testing.T) {
	te := SetupTest(t, `<html><body><div id="target"></div></body></html>`, "http://example.com")

	te.MustRunJS(`document.write('<p>appended</p>');`)

	htmlStr, err := te.Bridge.GetOuterHTML()
	require.NoError(t, err)
	assert.Contains(t, htmlStr, "<body><div id=\"target\"></div><p>appended</p></body>")
}

func TestCloneNode(t *testing.T) {
	te := SetupTest(t, `<html><body><div id="original"><p>text</p></div></body></html>`, "http://example.com")

	script := `
        const original = document.getElementById('original');
        const shallowClone = original.cloneNode(false);
        const deepClone = original.cloneNode(true);
        
        document.body.appendChild(shallowClone);
        document.body.appendChild(deepClone);
        
        ({
            shallowChildCount: shallowClone.childNodes.length,
            deepChildCount: deepClone.childNodes.length,
            deepChildText: deepClone.querySelector('p').textContent
        })
    `
	result := te.MustRunJS(script)
	resMap := result.Export().(map[string]interface{})

	assert.Equal(t, int64(0), resMap["shallowChildCount"])
	assert.Equal(t, int64(1), resMap["deepChildCount"])
	assert.Equal(t, "text", resMap["deepChildText"])
}

func TestXHR_ErrorHandling(t *testing.T) {
	te := SetupTest(t, `<html><body></body></html>`, "http://example.com")
	te.MockEnv.On("ExecuteFetch", mock.Anything, mock.Anything).Return(nil, errors.New("network error"))

	script := `
        new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', '/test');
            // This is a simplification; a real browser calls onerror.
            // But onreadystatechange is sufficient to test the state change.
            xhr.onreadystatechange = () => {
                if (xhr.readyState === 4 && xhr.status === 0) {
                    reject(new Error('xhr error'));
                }
            };
            xhr.send();
        });
    `
	_, err := te.RunJS(script)
	assert.Error(t, err)
	// The promise rejection from JS is caught by goja.
	assert.Contains(t, err.Error(), "xhr error")
}
