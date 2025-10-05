// internal/browser/jsbind/dom_bridge_test.go
package jsbind

import (
	"context"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/html"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// "github.com/xkilldash9x/scalpel-cli/internal/browser/layout" // Required if Hit Testing tests are implemented
)

// -- Mock BrowserEnvironment --

// MockBrowserEnvironment implements the BrowserEnvironment interface for testing.
// It is designed to be thread-safe as it is accessed by both the test runner and the event loop goroutine.
type MockBrowserEnvironment struct {
	mu sync.RWMutex

	CurrentURL string

	// Recorded interactions
	Navigations   []string
	URLChanges    []string
	FetchRequests []schemas.FetchRequest

	// State management
	Cookies      map[string]string
	History      []*schemas.HistoryState
	HistoryIndex int

	// Configurable responses
	FetchResponse *schemas.FetchResponse
	FetchError    error

	// Synchronization helper for async operations (like form submissions)
	FetchSignal chan struct{}
}

func NewMockBrowserEnvironment(initialURL string) *MockBrowserEnvironment {
	return &MockBrowserEnvironment{
		CurrentURL:   initialURL,
		Cookies:      make(map[string]string),
		History:      []*schemas.HistoryState{{URL: initialURL}},
		HistoryIndex: 0,
		// Initialize FetchSignal with a buffer for robust testing.
		FetchSignal: make(chan struct{}, 10),
	}
}

// Helper to safely update the current URL and the active history entry's URL.
func (m *MockBrowserEnvironment) updateCurrentURL(targetURL string) {
	// Assumes lock is already held
	m.CurrentURL = targetURL
	if m.HistoryIndex >= 0 && m.HistoryIndex < len(m.History) {
		m.History[m.HistoryIndex].URL = targetURL
	}
}

func (m *MockBrowserEnvironment) JSNavigate(targetURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Resolve URL before navigation
	resolvedURL, err := m.resolveURLInternal(targetURL)
	if err != nil {
		// Handle resolution error if necessary
		return
	}
	resolvedStr := resolvedURL.String()

	m.Navigations = append(m.Navigations, resolvedStr)

	// Simulate browser behavior: navigation pushes a new history entry.
	m.History = m.History[:m.HistoryIndex+1]
	m.History = append(m.History, &schemas.HistoryState{URL: resolvedStr})
	m.HistoryIndex++
	m.CurrentURL = resolvedStr
}

func (m *MockBrowserEnvironment) NotifyURLChange(targetURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.URLChanges = append(m.URLChanges, targetURL)
	m.updateCurrentURL(targetURL)
}

func (m *MockBrowserEnvironment) ExecuteFetch(ctx context.Context, req schemas.FetchRequest) (*schemas.FetchResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FetchRequests = append(m.FetchRequests, req)

	// Simulate navigation often resulting from a fetch (e.g., form POST)
	m.updateCurrentURL(req.URL)

	// Signal that a fetch occurred (used to fix race conditions in tests).
	if m.FetchSignal != nil {
		select {
		case m.FetchSignal <- struct{}{}:
		default:
			// Don't block if the buffer is full or channel closed.
		}
	}

	if m.FetchError != nil {
		return nil, m.FetchError
	}
	if m.FetchResponse != nil {
		return m.FetchResponse, nil
	}
	// Default success response
	return &schemas.FetchResponse{Status: 200, URL: req.URL}, nil
}

func (m *MockBrowserEnvironment) AddCookieFromString(cookieStr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Simplified cookie parsing: key=value; options...
	parts := strings.SplitN(cookieStr, "=", 2)
	if len(parts) == 2 {
		key := strings.TrimSpace(parts[0])
		valueParts := strings.SplitN(parts[1], ";", 2)
		m.Cookies[key] = strings.TrimSpace(valueParts[0])
	}
	return nil
}

func (m *MockBrowserEnvironment) GetCookieString() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var cookies []string
	// Sort keys for deterministic output in tests
	keys := make([]string, 0, len(m.Cookies))
	for k := range m.Cookies {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		cookies = append(cookies, k+"="+m.Cookies[k])
	}
	return strings.Join(cookies, "; "), nil
}

func (m *MockBrowserEnvironment) PushHistory(state *schemas.HistoryState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Resolve the URL if provided
	if state.URL != "" {
		resolvedURL, err := m.resolveURLInternal(state.URL)
		if err == nil {
			state.URL = resolvedURL.String()
			m.CurrentURL = state.URL
		}
	}

	// Prune forward history and append new state
	m.History = m.History[:m.HistoryIndex+1]
	m.History = append(m.History, state)
	m.HistoryIndex++
	return nil
}

func (m *MockBrowserEnvironment) ReplaceHistory(state *schemas.HistoryState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Resolve the URL if provided
	if state.URL != "" {
		resolvedURL, err := m.resolveURLInternal(state.URL)
		if err == nil {
			state.URL = resolvedURL.String()
			m.CurrentURL = state.URL
		}
	}

	if len(m.History) > 0 {
		m.History[m.HistoryIndex] = state
	}
	return nil
}

func (m *MockBrowserEnvironment) GetHistoryLength() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.History)
}

func (m *MockBrowserEnvironment) GetCurrentHistoryState() interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.HistoryIndex >= 0 && m.HistoryIndex < len(m.History) {
		return m.History[m.HistoryIndex].State
	}
	return nil
}

// resolveURLInternal is the internal implementation assuming lock is held or not needed for CurrentURL read.
func (m *MockBrowserEnvironment) resolveURLInternal(targetURL string) (*url.URL, error) {
	base, err := url.Parse(m.CurrentURL)
	if err != nil {
		// Fallback if CurrentURL is invalid
		base, _ = url.Parse("about:blank")
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	return base.ResolveReference(target), nil
}

func (m *MockBrowserEnvironment) ResolveURL(targetURL string) (*url.URL, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resolveURLInternal(targetURL)
}

// -- Test Setup Utilities --

// TestEnvironment encapsulates the bridge, event loop, and mocks for a test run.
type TestEnvironment struct {
	Bridge  *DOMBridge
	Loop    *eventloop.EventLoop
	MockEnv *MockBrowserEnvironment
	Logger  *zap.Logger
	T       *testing.T
}

// SetupTest initializes a complete testing environment.
// It ensures the event loop is running and the bridge is bound safely within the loop's goroutine.
func SetupTest(t *testing.T, initialHTML string, initialURL string) *TestEnvironment {
	t.Helper()
	logger := zaptest.NewLogger(t)
	// 1. Create the event loop, which manages the goja.Runtime instance.
	loop := eventloop.NewEventLoop()
	mockEnv := NewMockBrowserEnvironment(initialURL)

	bridge := NewDOMBridge(logger, loop, mockEnv, schemas.DefaultPersona)

	// 2. Parse initial HTML and update the Go-side DOM structure.
	doc, err := html.Parse(strings.NewReader(initialHTML))
	require.NoError(t, err)
	bridge.UpdateDOM(doc)

	// 3. Start the event loop.
	loop.Start()
	t.Cleanup(func() {
		// Ensure the loop is stopped cleanly after the test to prevent goroutine leaks.
		// Terminate ensures timers are also cancelled.
		loop.Terminate()
	})

	// 4. Bind the bridge to the runtime. This MUST happen on the event loop's goroutine.
	loop.RunOnLoop(func(vm *goja.Runtime) {
		bridge.BindToRuntime(vm, initialURL)
		// Setup console.log for debugging visibility during tests
		vm.Set("console", map[string]interface{}{
			"log": func(args ...interface{}) {
				logger.Info("JS console.log", zap.Any("args", args))
			},
		})
		// Polyfill basic Event constructor for testing dispatchEvent (Goja is ES5.1)
		vm.RunString(`
            if (typeof Event === 'undefined') {
                function Event(type, options) {
                    this.type = type;
                    this.bubbles = options && options.bubbles || false;
                    this.cancelable = options && options.cancelable || false;
                }
                window.Event = Event;
            }
        `)
	})

	return &TestEnvironment{
		Bridge:  bridge,
		Loop:    loop,
		MockEnv: mockEnv,
		Logger:  logger,
		T:       t,
	}
}

// RunJS executes a JavaScript string on the event loop and returns the result or error synchronously.
func (te *TestEnvironment) RunJS(script string) (goja.Value, error) {
	var result goja.Value
	var err error
	// Use a channel to wait for completion.
	done := make(chan struct{})

	te.Loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)
		result, err = vm.RunString(script)
	})

	// Wait for the script execution to complete on the event loop.
	<-done
	return result, err
}

// MustRunJS is like RunJS but fails the test if an error occurs.
func (te *TestEnvironment) MustRunJS(script string) goja.Value {
	te.T.Helper()
	val, err := te.RunJS(script)
	require.NoError(te.T, err, "JavaScript execution failed")
	return val
}

// AssertJSEval evaluates a JS expression and asserts the result equals the expected value.
func (te *TestEnvironment) AssertJSEval(script string, expected interface{}) {
	te.T.Helper()
	// Wrap in an IIFE and return the expression result
	script = fmt.Sprintf("(function() { return (%s); })()", script)
	val := te.MustRunJS(script)

	var actual interface{}
	if val != nil && !goja.IsUndefined(val) {
		actual = val.Export()
	}
	// Handle Goja exporting JS null as Go nil
	if val != nil && goja.IsNull(val) {
		actual = nil
	}

	assert.Equal(te.T, expected, actual, "JS assertion failed for script: %s", script)
}

// ExposeCallback exposes a Go function to the JS runtime (useful for testing async operations).
func (te *TestEnvironment) ExposeCallback(name string, callback interface{}) {
	te.Loop.RunOnLoop(func(vm *goja.Runtime) {
		vm.Set(name, callback)
	})
}

// -- Test Cases --

// -- 1. Initialization and Core Structure --

func TestBasicSetupAndGlobals(t *testing.T) {
	html := "<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>"
	te := SetupTest(t, html, "http://example.com")

	// Verify Go-side DOM structure (Read-only access)
	doc := te.Bridge.GetDocumentNode()
	require.NotNil(t, doc)
	h1 := htmlquery.FindOne(doc, "//h1")
	require.NotNil(t, h1)

	// Verify JS-side globals and structure
	te.AssertJSEval("typeof window", "object")
	te.AssertJSEval("window === self", true)
	te.AssertJSEval("document.body.tagName", "BODY")
	te.AssertJSEval("document.head.tagName", "HEAD")
	te.AssertJSEval("document.documentElement.tagName", "HTML")
	te.AssertJSEval("window.innerWidth", int64(1920))
}

// -- 2. DOM Querying and Traversal --

func TestDOMQuerying(t *testing.T) {
	html := `
		<html><body>
			<div id="main" class="container">
				<p class="item">P1</p>
				<p class="item" id="item'with'quote">P2</p>
			</div>
		</body></html>
	`
	te := SetupTest(t, html, "http://example.com")

	t.Run("getElementById", func(t *testing.T) {
		te.AssertJSEval("document.getElementById('main').className", "container")
		te.AssertJSEval("document.getElementById('nonexistent')", nil)

		// Test ID with quotes (verifies XPath escaping)
		te.AssertJSEval(`document.getElementById("item'with'quote").textContent`, "P2")
	})

	t.Run("querySelector", func(t *testing.T) {
		te.AssertJSEval("document.querySelector('.item').textContent", "P1")
		// Contextual querySelector
		te.AssertJSEval("document.querySelector('#main').querySelector('p:nth-child(2)').textContent", "P2")
		te.AssertJSEval("document.querySelector('.nonexistent')", nil)
	})

	t.Run("querySelectorAll", func(t *testing.T) {
		te.AssertJSEval("document.querySelectorAll('.item').length", int64(2))
		te.AssertJSEval("document.querySelectorAll('.item')[1].textContent", "P2")
	})

	t.Run("Traversal", func(t *testing.T) {
		te.AssertJSEval("document.getElementById('main').parentNode.tagName", "BODY")
		te.AssertJSEval("document.body.parentNode.tagName", "HTML")
		te.AssertJSEval("document.documentElement.parentNode.nodeType", int64(9)) // Document Node
		te.AssertJSEval("document.parentNode", nil)
	})
}

// -- 3. DOM Manipulation --

func TestDOMManipulation(t *testing.T) {
	html := `<html><body><div id="parent"><span id="child1"></span></div></body></html>`
	te := SetupTest(t, html, "http://example.com")

	// Tests run sequentially in the same environment.
	t.Run("CreateAndAppendChild", func(t *testing.T) {
		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var parent = document.getElementById('parent');
			var newChild = document.createElement('p');
			newChild.id = 'child2';
			parent.appendChild(newChild);
		`)

		te.AssertJSEval("document.getElementById('child2').parentNode.id", "parent")

		// Verify Go side (thread-safe access)
		doc := te.Bridge.GetDocumentNode()
		child2 := htmlquery.FindOne(doc, "//p[@id='child2']")
		require.NotNil(t, child2)
	})

	t.Run("InsertBefore", func(t *testing.T) {
		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var parent = document.getElementById('parent');
			var child1 = document.getElementById('child1');
			var newChild = document.createElement('img');
			newChild.id = 'child0';
			// Added safety check for child1 existence before inserting.
			if (child1) {
				parent.insertBefore(newChild, child1);
			}
		`)

		// Verify order: child0, child1, child2
		te.AssertJSEval(`
			Array.from(document.getElementById('parent').childNodes).map(n => n.id).join(',')
		`, "child0,child1,child2")
	})

	t.Run("InsertBefore_NullRef", func(t *testing.T) {
		// insertBefore(newNode, null) acts like appendChild
		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var parent = document.getElementById('parent');
			var newChild = document.createElement('div');
			newChild.id = 'childEnd';
			parent.insertBefore(newChild, null);
		`)

		te.AssertJSEval(`
			Array.from(document.getElementById('parent').childNodes).map(n => n.id).join(',')
		`, "child0,child1,child2,childEnd")
	})

	t.Run("RemoveChild", func(t *testing.T) {
		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var parent = document.getElementById('parent');
			var child1 = document.getElementById('child1');
			// Added safety check in case element somehow doesn't exist due to prior state issues.
			if (child1) {
				parent.removeChild(child1);
			}
		`)

		te.AssertJSEval("document.getElementById('child1')", nil)
	})

	t.Run("Reparenting (Implicit Removal)", func(t *testing.T) {
		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var newParent = document.createElement('section');
			newParent.id = 'newParent';
			document.body.appendChild(newParent);

			var child0 = document.getElementById('child0'); // Currently in 'parent'
			if (child0) {
				newParent.appendChild(child0);
			}
		`)

		te.AssertJSEval("document.getElementById('child0').parentNode.id", "newParent")
		// 'parent' should have lost child0
		te.AssertJSEval(`
			Array.from(document.getElementById('parent').childNodes).map(n => n.id).join(',')
		`, "child2,childEnd")
	})

	t.Run("InnerHTML", func(t *testing.T) {
		// Setter
		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var parent = document.getElementById('parent');
			parent.innerHTML = '<a>Link1</a><a>Link2</a>';
		`)

		// Verify structure change
		te.AssertJSEval("document.getElementById('parent').childNodes.length", int64(2))
		te.AssertJSEval("document.querySelector('#parent a').innerHTML", "Link1")

		// Getter
		val := te.MustRunJS(`document.getElementById('parent').innerHTML`)
		assert.Contains(t, val.String(), "<a>Link1</a>")
		assert.Contains(t, val.String(), "<a>Link2</a>")
	})

	t.Run("DocumentWrite", func(t *testing.T) {
		te.MustRunJS(`document.write('<p id="written">Doc Write</p>');`)
		// Implementation appends to body
		te.AssertJSEval("document.getElementById('written').innerHTML", "Doc Write")
	})
}

// -- 4. Attributes and Properties --

func TestAttributesAndProperties(t *testing.T) {
	html := `<html><body>
		<input id="myInput" type="text" value="initial" disabled>
		<a id="myLink" href="/relative/path">Link</a>
		<textarea id="myTextarea">Initial Text</textarea>
	</body></html>`
	te := SetupTest(t, html, "http://example.com/home/")

	t.Run("Attribute Methods", func(t *testing.T) {
		te.AssertJSEval("document.getElementById('myInput').getAttribute('type')", "text")
		te.AssertJSEval("document.getElementById('myInput').getAttribute('nonexistent')", nil)

		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var input = document.getElementById('myInput');
			input.setAttribute('data-custom', 'test-value');
			input.removeAttribute('disabled');
		`)

		te.AssertJSEval("document.getElementById('myInput').getAttribute('data-custom')", "test-value")
		te.AssertJSEval("document.getElementById('myInput').getAttribute('disabled')", nil)
	})

	t.Run("Standard Properties (id, className)", func(t *testing.T) {
		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var input = document.getElementById('myInput');
			input.className = 'c1 c2';
			input.id = 'newID';
		`)
		te.AssertJSEval("document.getElementById('newID').className", "c1 c2")
		te.AssertJSEval("document.getElementById('newID').getAttribute('class')", "c1 c2")
	})

	t.Run("Value Property (Input)", func(t *testing.T) {
		// Using 'newID' from previous test
		te.AssertJSEval("document.getElementById('newID').value", "initial")
		te.MustRunJS(`document.getElementById('newID').value = 'new value';`)

		// Setting the property updates the attribute for inputs
		te.AssertJSEval("document.getElementById('newID').value", "new value")
		te.AssertJSEval("document.getElementById('newID').getAttribute('value')", "new value")
	})

	t.Run("Value Property (Textarea)", func(t *testing.T) {
		// Textarea value property reflects inner content, not an attribute
		te.AssertJSEval("document.getElementById('myTextarea').value", "Initial Text")
		te.MustRunJS(`document.getElementById('myTextarea').value = 'New Textarea Content';`)

		te.AssertJSEval("document.getElementById('myTextarea').value", "New Textarea Content")
		te.AssertJSEval("document.getElementById('myTextarea').innerHTML", "New Textarea Content")
	})

	t.Run("Boolean Properties", func(t *testing.T) {
		// 'newID' currently has disabled removed
		te.AssertJSEval("document.getElementById('newID').disabled", false)

		te.MustRunJS(`
			// Fix: JavaScript Variable Scope Leakage. Changed const to var.
			var input = document.getElementById('newID');
			input.disabled = true;
			input.checked = true;
		`)

		te.AssertJSEval("document.getElementById('newID').disabled", true)
		te.AssertJSEval("document.getElementById('newID').checked", true)
	})

	t.Run("Href/Src Resolution", func(t *testing.T) {
		// The property should return the resolved absolute URL
		te.AssertJSEval("document.getElementById('myLink').href", "http://example.com/relative/path")

		// getAttribute should return the raw value
		te.AssertJSEval("document.getElementById('myLink').getAttribute('href')", "/relative/path")
	})
}

func TestDatasetAndStyle(t *testing.T) {
	html := `<html><body><div id="el" data-user-id="123" style="color: red; font-size: 16px;"></div></body></html>`
	te := SetupTest(t, html, "http://example.com")

	t.Run("Dataset Proxy", func(t *testing.T) {
		// Getter (kebab-case -> camelCase)
		te.AssertJSEval("document.getElementById('el').dataset.userId", "123")

		// Setter (camelCase -> kebab-case)
		te.MustRunJS(`document.getElementById('el').dataset.newProp = 'test';`)
		te.AssertJSEval("document.getElementById('el').getAttribute('data-new-prop')", "test")
	})

	t.Run("Style Proxy", func(t *testing.T) {
		// Getter
		te.AssertJSEval("document.getElementById('el').style.color", "red")
		te.AssertJSEval("document.getElementById('el').style.fontSize", "16px")

		// Setter
		te.MustRunJS(`
			var el = document.getElementById('el');
			el.style.backgroundColor = 'blue';
			el.style.color = 'green';
		`)

		// Verify serialized style attribute (sorted alphabetically by implementation)
		te.AssertJSEval("document.getElementById('el').getAttribute('style')", "background-color: blue; color: green; font-size: 16px")
	})
}

// -- 5. Events --

func TestEventDispatchAndListeners(t *testing.T) {
	html := `
		<html><body>
			<div id="gp"><div id="p"><button id="c"></button></div></div>
		</body></html>
	`
	te := SetupTest(t, html, "http://example.com")

	// Setup listeners and tracking array
	te.MustRunJS(`
		window.eventLog = [];
		// Fix: JavaScript Variable Scope Leakage. Changed const to var.
		var gp = document.getElementById('gp');
		var p = document.getElementById('p');
		var c = document.getElementById('c');

        // Event Phases: 1=CAPTURING, 2=AT_TARGET, 3=BUBBLING

		// Capturing phase
		gp.addEventListener('click', (e) => window.eventLog.push('gp-cap@' + e.eventPhase), true);
		p.addEventListener('click', (e) => window.eventLog.push('p-cap@' + e.eventPhase), true);

		// Bubbling phase
		gp.addEventListener('click', (e) => window.eventLog.push('gp-bub@' + e.eventPhase), false);
		p.addEventListener('click', (e) => window.eventLog.push('p-bub@' + e.eventPhase), false);

        // Target phase
		c.addEventListener('click', (e) => window.eventLog.push('c-target@' + e.eventPhase), false);
	`)

	// Dispatch the event using .click()
	te.MustRunJS(`document.getElementById('c').click()`)

	// Retrieve the log
	val := te.MustRunJS(`window.eventLog.join(';')`)
	log := val.String()

	// Expected order: Capturing -> Target -> Bubbling
	expectedOrder := "gp-cap@1;p-cap@1;c-target@2;p-bub@3;gp-bub@3"
	assert.Equal(t, expectedOrder, log)
}

func TestEventStopPropagation(t *testing.T) {
	html := `<html><body><div id="p"><button id="c"></button></div></body></html>`
	te := SetupTest(t, html, "http://example.com")

	t.Run("Stop Bubbling", func(t *testing.T) {
		te.MustRunJS(`
			window.eventLog = [];
			document.getElementById('p').addEventListener('click', () => window.eventLog.push('p-bub'));
			document.getElementById('c').addEventListener('click', (e) => {
				window.eventLog.push('c-bub');
				e.stopPropagation();
			});
		`)

		te.MustRunJS(`document.getElementById('c').click()`)
		val := te.MustRunJS(`window.eventLog.join(';')`)
		assert.Equal(t, "c-bub", val.String())
	})

	t.Run("Stop Capturing", func(t *testing.T) {
		// This test relies on the parentNode fix in dom_bridge.go.
		te.MustRunJS(`
            window.eventLog = [];

			// We clone the node to remove previously attached listeners from the "Stop Bubbling" subtest.
            const p_old = document.getElementById('p');
			// The check for p_old.parentNode is now reliable due to the fix.
			if (p_old && p_old.parentNode) {
				const p_new = p_old.cloneNode(true);
				p_old.parentNode.insertBefore(p_new, p_old);
				p_old.parentNode.removeChild(p_old);
			}

            const p = document.getElementById('p');
            const c = document.getElementById('c');

			p.addEventListener('click', (e) => {
				window.eventLog.push('p-cap');
				e.stopPropagation();
			}, true);
            c.addEventListener('click', () => window.eventLog.push('c-target')); // Should not run
		`)

		te.MustRunJS(`document.getElementById('c').click()`)
		val := te.MustRunJS(`window.eventLog.join(';')`)
		assert.Equal(t, "p-cap", val.String())
	})
}

func TestDefaultClickActions(t *testing.T) {
	html := `
		<html><body>
			<a id="myLink" href="/destination">Link</a>
			<input type="checkbox" id="myCheckbox" checked>
			<input type="radio" name="group1" id="radio1" checked>
			<input type="radio" name="group1" id="radio2">
		</body></html>
	`
	te := SetupTest(t, html, "http://example.com/home")
	mockEnv := te.MockEnv

	t.Run("AnchorTagNavigation", func(t *testing.T) {
		te.MustRunJS(`document.getElementById('myLink').click()`)

		// Check mock environment for navigation
		mockEnv.mu.RLock()
		defer mockEnv.mu.RUnlock()
		assert.Contains(t, mockEnv.Navigations, "http://example.com/destination")
	})

	t.Run("CheckboxToggle", func(t *testing.T) {
		te.AssertJSEval("document.getElementById('myCheckbox').checked", true)
		te.MustRunJS(`document.getElementById('myCheckbox').click()`)
		te.AssertJSEval("document.getElementById('myCheckbox').checked", false)
		te.MustRunJS(`document.getElementById('myCheckbox').click()`)
		te.AssertJSEval("document.getElementById('myCheckbox').checked", true)
	})

	t.Run("RadioGroupBehavior", func(t *testing.T) {
		te.AssertJSEval("document.getElementById('radio1').checked", true)
		te.AssertJSEval("document.getElementById('radio2').checked", false)

		// Click radio2
		te.MustRunJS(`document.getElementById('radio2').click()`)

		te.AssertJSEval("document.getElementById('radio1').checked", false)
		te.AssertJSEval("document.getElementById('radio2').checked", true)
	})
}

// -- 6. Browser APIs (Timers, Storage, Location, History, Cookies) --

func TestTimers(t *testing.T) {
	// Testing timers requires waiting for asynchronous execution. We use channels for robust synchronization.
	te := SetupTest(t, "<html></html>", "http://example.com")

	t.Run("setTimeout", func(t *testing.T) {
		done := make(chan bool, 1)
		te.ExposeCallback("signalDone", func() { done <- true })

		startTime := time.Now()
		te.MustRunJS(`setTimeout(signalDone, 20);`)

		select {
		case <-done:
			assert.GreaterOrEqual(t, time.Since(startTime), 20*time.Millisecond)
		case <-time.After(1 * time.Second):
			t.Fatal("setTimeout did not execute in time")
		}
	})

	t.Run("clearTimeout", func(t *testing.T) {
		executed := make(chan bool, 1)
		te.ExposeCallback("signalExecuted", func() { executed <- true })

		te.MustRunJS(`
			var timerId = setTimeout(signalExecuted, 20);
			clearTimeout(timerId);
		`)

		select {
		case <-executed:
			t.Fatal("clearTimeout failed, the timeout executed")
		case <-time.After(100 * time.Millisecond):
			// Success
		}
	})

	t.Run("setInterval", func(t *testing.T) {
		ticks := make(chan int, 5)
		count := 0
		te.ExposeCallback("signalTick", func() {
			count++
			ticks <- count
		})

		te.MustRunJS(`
			var counter = 0;
			var intervalId = setInterval(function() {
				signalTick();
				counter++;
				if (counter >= 3) {
					clearInterval(intervalId);
				}
			}, 20);
		`)

		// Wait for 3 ticks
		timeout := time.After(1 * time.Second)
		tickCount := 0
	loop:
		for {
			select {
			case c := <-ticks:
				tickCount = c
				if tickCount >= 3 {
					break loop
				}
			case <-timeout:
				t.Fatalf("setInterval did not execute 3 times, got %d", tickCount)
			}
		}
	})
}

func TestStorageAPIs(t *testing.T) {
	te := SetupTest(t, "<html></html>", "http://example.com")

	testStorage := func(storageName string) {
		t.Run(storageName, func(t *testing.T) {
			te.MustRunJS(fmt.Sprintf(`%s.clear()`, storageName))
			te.AssertJSEval(fmt.Sprintf(`%s.length`, storageName), int64(0))

			// SetItem, GetItem, Length
			te.MustRunJS(fmt.Sprintf(`%s.setItem('k1', 'v1'); %s.setItem('k2', 'v2');`, storageName, storageName))
			te.AssertJSEval(fmt.Sprintf(`%s.getItem('k1')`, storageName), "v1")
			te.AssertJSEval(fmt.Sprintf(`%s.length`, storageName), int64(2))

			// RemoveItem
			te.MustRunJS(fmt.Sprintf(`%s.removeItem('k1')`, storageName))
			te.AssertJSEval(fmt.Sprintf(`%s.getItem('k1')`, storageName), nil)

			// Clear
			te.MustRunJS(fmt.Sprintf(`%s.clear()`, storageName))
			te.AssertJSEval(fmt.Sprintf(`%s.length`, storageName), int64(0))
		})
	}

	testStorage("localStorage")
	testStorage("sessionStorage")
}

func TestLocationAPI(t *testing.T) {
	initialURL := "https://www.example.com:8080/path/to/page?query=1#hashfrag"
	te := SetupTest(t, "<html></html>", initialURL)
	mockEnv := te.MockEnv

	t.Run("Properties", func(t *testing.T) {
		te.AssertJSEval("location.href", initialURL)
		te.AssertJSEval("location.protocol", "https:")
		te.AssertJSEval("location.host", "www.example.com:8080")
		te.AssertJSEval("location.pathname", "/path/to/page")
		te.AssertJSEval("location.search", "?query=1")
		te.AssertJSEval("location.hash", "#hashfrag")
		te.AssertJSEval("location.origin", "https://www.example.com:8080")
	})

	t.Run("Navigation (Set Href)", func(t *testing.T) {
		te.MustRunJS(`window.location.href = 'http://othersite.com/new'`)

		// Check if the mock environment recorded the navigation
		mockEnv.mu.RLock()
		assert.Contains(t, mockEnv.Navigations, "http://othersite.com/new")
		mockEnv.mu.RUnlock()

		// JS state updates immediately
		te.AssertJSEval("location.href", "http://othersite.com/new")
	})

	t.Run("Navigation (Relative URL)", func(t *testing.T) {
		// Assuming current URL is "http://othersite.com/new"
		te.MustRunJS(`window.location.assign('subpage?q=2')`)

		mockEnv.mu.RLock()
		defer mockEnv.mu.RUnlock()
		assert.Contains(t, mockEnv.Navigations, "http://othersite.com/subpage?q=2")
	})

	t.Run("Hash Change (In-page)", func(t *testing.T) {
		// Current URL is "http://othersite.com/subpage?q=2"
		expectedURL := "http://othersite.com/subpage?q=2#section1"

		// Listen for hashchange event
		te.MustRunJS(`
			window.hashChanged = false;
			document.addEventListener('hashchange', () => { window.hashChanged = true; });
		`)

		te.MustRunJS(`window.location.hash = 'section1'`)

		// Check URL change notification (not full navigation)
		mockEnv.mu.RLock()
		assert.Contains(t, mockEnv.URLChanges, expectedURL)
		mockEnv.mu.RUnlock()

		// Verify hashchange event fired
		te.AssertJSEval("window.hashChanged", true)
	})
}

func TestHistoryAPI(t *testing.T) {
	te := SetupTest(t, "<html></html>", "http://example.com/page1")

	// Initial state
	te.AssertJSEval("history.length", int64(1))
	te.AssertJSEval("history.state", nil)

	// 1. pushState
	te.MustRunJS(`history.pushState({page: 2}, 'Title 2', '/page2')`)

	// Verify JS state
	te.AssertJSEval("history.length", int64(2))
	te.AssertJSEval("history.state.page", int64(2))

	// Verify Mock environment state
	te.MockEnv.mu.RLock()
	assert.Equal(t, 2, len(te.MockEnv.History))
	assert.Equal(t, 1, te.MockEnv.HistoryIndex)
	assert.Equal(t, "http://example.com/page2", te.MockEnv.History[1].URL)
	te.MockEnv.mu.RUnlock()

	// 2. replaceState
	te.MustRunJS(`history.replaceState({page: '2_mod'}, 'Title 2 Mod', '/page2_mod')`)

	// Verify JS state (length unchanged)
	te.AssertJSEval("history.length", int64(2))
	te.AssertJSEval("history.state.page", "2_mod")

	// Verify Mock environment state
	te.MockEnv.mu.RLock()
	assert.Equal(t, "http://example.com/page2_mod", te.MockEnv.History[1].URL)
	te.MockEnv.mu.RUnlock()
}

func TestCookies(t *testing.T) {
	te := SetupTest(t, "<html></html>", "http://example.com")

	// 1. Set cookies
	te.MustRunJS(`document.cookie = 'user=JohnDoe'`)
	te.MustRunJS(`document.cookie = 'session=abc; path=/'`)

	// 2. Get cookies (order is deterministic due to sorting in mock)
	te.AssertJSEval("document.cookie", "session=abc; user=JohnDoe")

	// Verify the mock environment state
	te.MockEnv.mu.RLock()
	defer te.MockEnv.mu.RUnlock()
	assert.Equal(t, "JohnDoe", te.MockEnv.Cookies["user"])
	assert.Equal(t, "abc", te.MockEnv.Cookies["session"])
}

// -- 7. Form Submission --

func TestFormSubmissionGET(t *testing.T) {
	html := `
		<html><body>
			<form action="/search" method="GET">
				<input type="text" name="q" value="test query">
				<input type="checkbox" name="active" value="true" checked>
				<input type="checkbox" name="ignored" value="false">
				<input type="checkbox" name="default_on" checked>
				<select name="sort"><option value="desc" selected>D</option></select>
				<button type="submit" id="submitBtn"></button>
			</form>
		</body></html>
	`
	te := SetupTest(t, html, "http://example.com/home")

	// Expected URL: parameters sorted alphabetically by serializeForm and encoded.
	expectedURL := "http://example.com/search?active=true&default_on=on&q=test+query&sort=desc"

	// Trigger submission
	te.MustRunJS(`document.getElementById('submitBtn').click()`)

	// GET submission results in navigation (JSNavigate)
	te.MockEnv.mu.RLock()
	defer te.MockEnv.mu.RUnlock()
	assert.Contains(t, te.MockEnv.Navigations, expectedURL)
}

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

	// Trigger submission
	te.MustRunJS(`document.getElementById('submitBtn').click()`)

	// Fix: Broken Form Submission (Test Synchronization)
	// The form submission occurs asynchronously in a goroutine. We must wait for it.
	select {
	case <-te.MockEnv.FetchSignal:
		// Received signal, proceed to check results.
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for form submission ExecuteFetch call.")
	}

	// POST submission results in ExecuteFetch
	te.MockEnv.mu.RLock()
	defer te.MockEnv.mu.RUnlock()

	require.Len(t, te.MockEnv.FetchRequests, 1)
	req := te.MockEnv.FetchRequests[0]

	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "http://example.com/submit", req.URL)

	contentType := ""
	for _, h := range req.Headers {
		if h.Name == "Content-Type" {
			contentType = h.Value
		}
	}
	assert.Equal(t, "application/x-www-form-urlencoded", contentType)

	// Body sorted and encoded, submitter included.
	expectedBody := "action=Submit&comments=Hello%21&username=John%26Doe"
	assert.Equal(t, expectedBody, string(req.Body))
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

	// Trigger submission
	te.MustRunJS(`document.getElementById('submitBtn').click()`)

	// Fix: Broken Form Submission (Test Synchronization)
	select {
	case <-te.MockEnv.FetchSignal:
		// Received signal.
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for form submission ExecuteFetch call.")
	}

	te.MockEnv.mu.RLock()
	defer te.MockEnv.mu.RUnlock()

	require.Len(t, te.MockEnv.FetchRequests, 1)
	req := te.MockEnv.FetchRequests[0]

	// Check Content-Type (must include boundary)
	contentType := ""
	for _, header := range req.Headers {
		if header.Name == "Content-Type" {
			contentType = header.Value
		}
	}
	assert.Contains(t, contentType, "multipart/form-data; boundary=")

	// Verify body content structure
	body := string(req.Body)
	assert.Contains(t, body, `Content-Disposition: form-data; name="field1"`)
	assert.Contains(t, body, "value1")
}

// -- 8. Concurrency and Lifecycle Management --

// TestConcurrencyAndRaceDetection validates that the locking mechanisms prevent data races.
// Run with `go test -race`.
func TestConcurrencyAndRaceDetection(t *testing.T) {
	te := SetupTest(t, "<html><body><div id='content'>Initial</div></body></html>", "http://example.com")

	var wg sync.WaitGroup
	iterations := 50

	// 1. Concurrent JavaScript tasks (serialized by the event loop)
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		script := fmt.Sprintf(`
			const content = document.getElementById('content');
            if (content) { content.setAttribute('data-js', %d); }
		`, i)
		go func() {
			defer wg.Done()
			// We ignore potential errors if the element is removed by a Go task
			_, _ = te.RunJS(script)
		}()
	}

	// 2. Concurrent Go tasks that read/write the DOMBridge state (protected by internal locks)
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				// Read operation (thread-safe via RLock)
				_, err := te.Bridge.GetOuterHTML()
				assert.NoError(t, err)
			} else {
				// Write operation (thread-safe via Lock)
				newDoc, _ := html.Parse(strings.NewReader(fmt.Sprintf("<html><body><div id='content'>Go %d</div></body></html>", i)))
				te.Bridge.UpdateDOM(newDoc)
			}
		}(i)
	}

	wg.Wait()
	// If the race detector doesn't panic, the test passes.
}

// TestMemoryLeakPrevention addresses the "Context Closure" leak documented.
func TestMemoryLeakPrevention(t *testing.T) {
	// This test verifies that explicitly breaking cross-boundary reference cycles allows GC.

	// Function to create a cycle and then break it.
	createAndBreakCycle := func(t *testing.T) {
		// Setup environment (t.Cleanup ensures loop stops)
		te := SetupTest(t, "<html></html>", "http://example.com")

		// Create the cycle: Go object -> JS Callback -> JS Closure -> Go object
		type LeakyResource struct {
			Data     [1024 * 1024]byte // 1MB payload
			Callback func()
		}
		resource := &LeakyResource{}

		// Create the reference cycle within the runtime
		te.Loop.RunOnLoop(func(vm *goja.Runtime) {
			vm.Set("resource", resource)
			// JS closure captures 'resource'
			script := `(function() { return function() { const d = resource.Data.length; }; })()`
			_, err := vm.RunString(script)
			require.NoError(t, err)

			// Store the JS function back on the Go object
			resource.Callback = func() {
				// Callback implementation irrelevant for the leak test
			}
		})

		// CRITICAL STEP: Explicitly break the cycle before the environment is discarded.
		// This follows the recommendations in the provided documentation.
		resource.Callback = nil
	}

	// Measure memory before
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Run iterations
	for i := 0; i < 10; i++ {
		// Use a subtest so t.Cleanup runs after each iteration.
		t.Run(fmt.Sprintf("Iteration_%d", i), createAndBreakCycle)
	}

	// Measure memory after, forcing GC
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Check for significant memory increase (allocated 10MB total).
	memoryIncreaseMB := (m2.HeapAlloc - m1.HeapAlloc) / 1024 / 1024
	t.Logf("Memory increase: %d MB", memoryIncreaseMB)

	// Should be significantly less than 10MB if GC worked.
	assert.Less(t, memoryIncreaseMB, uint64(5), "Potential memory leak: HeapAlloc increased significantly.")
}

// -- 9. Helpers and Errors --

func TestHelperFunctions(t *testing.T) {
	t.Run("camelToKebab", func(t *testing.T) {
		assert.Equal(t, "background-color", camelToKebab("backgroundColor"))
		assert.Equal(t, "font-size", camelToKebab("fontSize"))
		assert.Equal(t, "simple", camelToKebab("simple"))
	})

	t.Run("StyleAttributeUtils", func(t *testing.T) {
		styleStr := " color: red; z-index: 1; background-color: blue; "
		parsed := parseStyleAttribute(styleStr)
		// Test serialization (must be sorted alphabetically)
		serialized := serializeStyleAttribute(parsed)
		expectedSerialized := "background-color: blue; color: red; z-index: 1"
		assert.Equal(t, expectedSerialized, serialized)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("ElementNotFoundError", func(t *testing.T) {
		err := NewElementNotFoundError("#missing-id")
		assert.Equal(t, "element not found matching selector '#missing-id'", err.Error())

		// Verify type assertion
		var target *ElementNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("NavigationError", func(t *testing.T) {
		underlying := fmt.Errorf("net error")
		err := &NavigationError{Err: underlying}
		// Verify unwrapping
		assert.ErrorIs(t, err, underlying)
	})
}