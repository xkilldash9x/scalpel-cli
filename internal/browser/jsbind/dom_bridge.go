// internal/browser/jsbind/dom_bridge.go
package jsbind

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

// listenerGroup stores event listeners separated by phase (Capturing vs Bubbling/Target).
// This structure is essential for W3C compliant event propagation.
type listenerGroup struct {
	// Listeners invoked during the Capturing phase (useCapture = true).
	Capturing []goja.Value
	// Listeners invoked during the Target or Bubbling phase (useCapture = false).
	Bubbling []goja.Value
}

// =================================================================================================
// DOM Bridge and Core Wrappers
// =================================================================================================

// DOMBridge manages the synchronization between the *html.Node DOM representation and the Goja runtime.
type DOMBridge struct {
	// mu protects access to the bridge state (e.g., DOM structure, eventListeners, nodeMap, storage).
	// It is crucial for synchronizing access between the main Go routines (via Session methods)
	// and the single-threaded JavaScript Event Loop.
	mu       sync.RWMutex
	document *html.Node // The root of the HTML document.
	runtime  *goja.Runtime
	logger   *zap.Logger

	// eventLoop is essential for handling asynchronous JS operations like setTimeout or Promises.
	eventLoop *eventloop.EventLoop

	// Mapping between *html.Node pointers and their corresponding Goja wrapper objects.
	nodeMap map[*html.Node]*goja.Object

	// Event listeners registered via addEventListener.
	eventListeners map[*html.Node]map[string]*listenerGroup

	// Storage simulation (LocalStorage/SessionStorage)
	localStorage   map[string]string
	sessionStorage map[string]string

	// Callbacks provided by the Session for interactive location management.
	navigateCallback        NavigationFunc
	notifyURLChangeCallback NavigationFunc

	// Stores the current location state for the active JS context.
	currentLocationState map[string]string
}

// Element is a Goja wrapper for an *html.Node that represents an element.
type Element struct {
	bridge *DOMBridge
	Node   *html.Node
	Object *goja.Object
}

// NavigationFunc is the function signature for callbacks used by the DOMBridge
// to communicate with the Session regarding URL changes.
type NavigationFunc func(targetURL string)

// NewDOMBridge creates a new DOMBridge instance and initializes the JS runtime environment.
func NewDOMBridge(logger *zap.Logger, eventLoop *eventloop.EventLoop, navigateCallback NavigationFunc, notifyURLChangeCallback NavigationFunc) *DOMBridge {
	if logger == nil {
		logger = zap.NewNop()
	}

	bridge := &DOMBridge{
		logger:                  logger.Named("dom_bridge"),
		eventLoop:               eventLoop,
		nodeMap:                 make(map[*html.Node]*goja.Object),
		eventListeners:          make(map[*html.Node]map[string]*listenerGroup),
		localStorage:            make(map[string]string),
		sessionStorage:          make(map[string]string),
		navigateCallback:        navigateCallback,
		notifyURLChangeCallback: notifyURLChangeCallback,
		currentLocationState:    make(map[string]string),
	}
	return bridge
}

// BindToRuntime injects the DOM APIs into the Goja runtime.
// This function must be executed on the event loop thread.
func (b *DOMBridge) BindToRuntime(vm *goja.Runtime) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.runtime = vm
	global := vm.GlobalObject()

	// 1. Create and bind the 'document' object.
	documentObj := b.wrapNode(b.document)
	_ = global.Set("document", documentObj)

	// 2. Create and bind the 'window' object, which is the global 'this'.
	_ = global.Set("window", global)
	_ = global.Set("self", global)

	// 3. Bind timers (setTimeout, etc.) using the event loop.
	b.initTimers()

	// 4. Bind Storage APIs to the window.
	b.bindStorageAPIs()

	// 5. Bind scroll APIs to the window.
	b.bindScrollAPIs()

	// Basic simulation of dimensions.
	if goja.IsUndefined(global.Get("innerWidth")) {
		_ = global.Set("innerWidth", 1920)
		_ = global.Set("innerHeight", 1080)
	}
	if goja.IsUndefined(global.Get("scrollX")) {
		_ = global.Set("scrollX", 0)
		_ = global.Set("scrollY", 0)
	}
}

// UpdateDOM safely replaces the root document node for the bridge.
func (b *DOMBridge) UpdateDOM(doc *html.Node, initialURL string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.document = doc
	// Clear the node map to prevent stale references from the old DOM.
	b.nodeMap = make(map[*html.Node]*goja.Object)
	// Reset event listeners as well.
	b.eventListeners = make(map[*html.Node]map[string]*listenerGroup)

	if b.runtime != nil {
		// Re-initialize document and head/body properties
		documentObj := b.wrapNode(b.document)
		_ = b.runtime.Set("document", documentObj)
		b.bindDocumentAndElementMethods(documentObj, b.document)

		// Re-initialize location object for the new page context
		b.InitializeLocation(initialURL)
	}
}

// GetDocumentNode provides thread safe access to the root document node.
func (b *DOMBridge) GetDocumentNode() *html.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.document
}

// GetEventLoop returns the associated event loop.
func (b *DOMBridge) GetEventLoop() *eventloop.EventLoop {
	return b.eventLoop
}

// =================================================================================================
// Node Wrapping and JS Object Creation
// =================================================================================================

// wrapNode creates or retrieves the Goja object wrapper for a given *html.Node.
// This is the core of maintaining object identity between Go and JavaScript.
func (b *DOMBridge) wrapNode(node *html.Node) *goja.Object {
	if node == nil {
		return nil
	}

	// Check the cache first to ensure the same JS object is returned for the same Go node.
	if obj, exists := b.nodeMap[node]; exists {
		return obj
	}

	obj := b.runtime.NewObject()

	// -- Core Node Properties --
	_ = obj.Set("nodeType", node.Type)
	_ = obj.Set("nodeName", strings.ToUpper(node.Data))
	_ = obj.Set("parentNode", func(call goja.FunctionCall) goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		return b.runtime.ToValue(b.wrapNode(node.Parent))
	})
	b.defineChildNodesProperty(obj, node)

	// -- DOM Manipulation Methods --
	_ = obj.Set("appendChild", b.jsAppendChild(node))
	// Add removeChild, insertBefore etc. here if needed.

	// -- Event Target Methods --
	_ = obj.Set("addEventListener", b.jsAddEventListener(node))
	_ = obj.Set("removeEventListener", b.jsRemoveEventListener(node)) // Placeholder for completeness
	_ = obj.Set("dispatchEvent", b.jsDispatchEvent(node))         // Placeholder for completeness

	// Bind methods and properties specific to Element nodes or the Document node.
	b.bindDocumentAndElementMethods(obj, node)

	// Cache the newly created wrapper.
	b.nodeMap[node] = obj
	return obj
}

// unwrapNode finds the *html.Node corresponding to a Goja object wrapper.
func (b *DOMBridge) unwrapNode(obj *goja.Object) *html.Node {
	if obj == nil {
		return nil
	}
	// This O(N) search is a bottleneck. In a high performance scenario,
	// this would be optimized, perhaps using Goja's private value storage.
	for node, wrapper := range b.nodeMap {
		if wrapper == obj {
			return node
		}
	}
	return nil
}

// bindDocumentAndElementMethods attaches the appropriate APIs based on the node type.
func (b *DOMBridge) bindDocumentAndElementMethods(obj *goja.Object, node *html.Node) {
	// Methods applicable to both Document and Element nodes.
	_ = obj.Set("querySelector", b.jsQuerySelector(node))
	_ = obj.Set("querySelectorAll", b.jsQuerySelectorAll(node))

	if node.Type == html.DocumentNode {
		_ = obj.Set("getElementById", b.jsGetElementById())
		_ = obj.Set("createElement", b.jsCreateElement())
		_ = obj.Set("write", b.jsDocumentWrite())

		// Expose essential elements (body, head).
		body := htmlquery.FindOne(b.document, "//body")
		if body != nil {
			_ = obj.Set("body", b.wrapNode(body))
		}
		head := htmlquery.FindOne(b.document, "//head")
		if head != nil {
			_ = obj.Set("head", b.wrapNode(head))
		}

	} else if node.Type == html.ElementNode {
		// -- Element-specific Properties --
		_ = obj.Set("tagName", strings.ToUpper(node.Data))
		b.defineHTMLProperties(obj, node)
		b.defineValueProperty(obj, node)
		b.defineDatasetProperty(obj, node)

		// -- Element-specific Methods --
		b.bindAttributeMethods(obj, node)
		_ = obj.Set("click", b.jsClick(node))
		_ = obj.Set("focus", b.jsFocus(node))
		_ = obj.Set("blur", b.jsBlur(node))
	}
}

// =================================================================================================
// JS Property Definitions (Getters/Setters)
// =================================================================================================

// defineChildNodesProperty sets up a live getter for the 'childNodes' property.
func (b *DOMBridge) defineChildNodesProperty(obj *goja.Object, node *html.Node) {
	getter := func(goja.FunctionCall) goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		var children []*goja.Object
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			wrapped := b.wrapNode(c)
			if wrapped != nil {
				children = append(children, wrapped)
			}
		}
		return b.runtime.ToValue(children)
	}
	b.DefineProperty(obj, "childNodes", getter, nil)
}

// defineHTMLProperties sets up getters and setters for innerHTML and outerHTML.
func (b *DOMBridge) defineHTMLProperties(obj *goja.Object, node *html.Node) {
	getter := func(goja.FunctionCall) goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		var buf bytes.Buffer
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			_ = html.Render(&buf, c)
		}
		return b.runtime.ToValue(buf.String())
	}
	setter := func(call goja.FunctionCall) goja.Value {
		htmlContent := call.Argument(0).String()
		nodes, err := html.ParseFragment(strings.NewReader(htmlContent), node)
		if err != nil {
			b.logger.Warn("Failed to parse HTML for innerHTML assignment", zap.Error(err))
			return goja.Undefined()
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		for c := node.FirstChild; c != nil; {
			next := c.NextSibling
			node.RemoveChild(c)
			c = next
		}
		for _, newNode := range nodes {
			node.AppendChild(newNode)
		}
		return call.Argument(0)
	}
	b.DefineProperty(obj, "innerHTML", getter, setter)
}

// defineValueProperty sets up the getter/setter for the 'value' property on form elements.
func (b *DOMBridge) defineValueProperty(obj *goja.Object, node *html.Node) {
	getter := func(goja.FunctionCall) goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		tagName := strings.ToLower(node.Data)
		if tagName == "textarea" {
			return b.runtime.ToValue(htmlquery.InnerText(node))
		}
		return b.runtime.ToValue(htmlquery.SelectAttr(node, "value"))
	}
	setter := func(call goja.FunctionCall) goja.Value {
		value := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		tagName := strings.ToLower(node.Data)
		if tagName == "textarea" {
			for c := node.FirstChild; c != nil; {
				next := c.NextSibling
				node.RemoveChild(c)
				c = next
			}
			node.AppendChild(&html.Node{Type: html.TextNode, Data: value})
		} else {
			setAttr(node, "value", value)
		}
		return call.Argument(0)
	}
	b.DefineProperty(obj, "value", getter, setter)
}

// defineDatasetProperty implements element.dataset using a JS Proxy for live access to data-* attributes.
func (b *DOMBridge) defineDatasetProperty(obj *goja.Object, elementNode *html.Node) {
	getter := func(goja.FunctionCall) goja.Value {
		target := b.runtime.NewObject()
		trapConfig := &goja.ProxyTrapConfig{
			Get: func(t *goja.Object, p goja.Value) goja.Value {
				propName := p.String()
				attrName := "data-" + camelToKebab(propName)
				b.mu.RLock()
				defer b.mu.RUnlock()
				val := htmlquery.SelectAttr(elementNode, attrName)
				for _, attr := range elementNode.Attr {
					if attr.Key == attrName {
						return b.runtime.ToValue(val)
					}
				}
				return goja.Undefined()
			},
			Set: func(t *goja.Object, p goja.Value, v goja.Value) bool {
				propName := p.String()
				value := v.String()
				attrName := "data-" + camelToKebab(propName)
				b.mu.Lock()
				defer b.mu.Unlock()
				setAttr(elementNode, attrName, value)
				return true
			},
		}
		proxy := b.runtime.NewProxy(target, trapConfig)
		if proxy == nil {
			b.logger.Warn("JS Proxy creation failed; dataset functionality will be degraded.")
			return b.runtime.NewObject()
		}
		return b.runtime.ToValue(proxy)
	}
	b.DefineProperty(obj, "dataset", getter, nil)
}

// =================================================================================================
// JS Method Implementations (Element, Document, etc.)
// =================================================================================================

// -- Document Methods --

func (b *DOMBridge) jsGetElementById() goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		id := call.Argument(0).String()
		b.mu.RLock()
		defer b.mu.RUnlock()
		escapedID := strings.ReplaceAll(id, "'", "\\'")
		xpath := fmt.Sprintf("//*[@id='%s']", escapedID)
		node := htmlquery.FindOne(b.document, xpath)
		if node == nil {
			return goja.Null()
		}
		return b.runtime.ToValue(b.wrapNode(node))
	}).(goja.Callable)
}

func (b *DOMBridge) jsCreateElement() goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		tagName := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		node := &html.Node{
			Type: html.ElementNode,
			Data: strings.ToLower(tagName),
		}
		return b.runtime.ToValue(b.wrapNode(node))
	}).(goja.Callable)
}

func (b *DOMBridge) jsDocumentWrite() goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		content := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		body := htmlquery.FindOne(b.document, "//body")
		if body == nil {
			return goja.Undefined()
		}
		nodes, err := html.ParseFragment(strings.NewReader(content), body)
		if err != nil {
			return goja.Undefined()
		}
		for _, node := range nodes {
			body.AppendChild(node)
		}
		return goja.Undefined()
	}).(goja.Callable)
}

// -- Shared Element/Document Query Methods --

func (b *DOMBridge) jsQuerySelector(contextNode *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		selector := call.Argument(0).String()
		b.mu.RLock()
		defer b.mu.RUnlock()
		node, err := htmlquery.Query(contextNode, selector)
		if err != nil {
			b.logger.Warn("Error evaluating XPath selector in querySelector", zap.String("selector", selector), zap.Error(err))
			return goja.Null()
		}
		if node == nil {
			return goja.Null()
		}
		return b.runtime.ToValue(b.wrapNode(node))
	}).(goja.Callable)
}

func (b *DOMBridge) jsQuerySelectorAll(contextNode *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		selector := call.Argument(0).String()
		b.mu.RLock()
		defer b.mu.RUnlock()
		nodes, err := htmlquery.QueryAll(contextNode, selector)
		if err != nil {
			b.logger.Warn("Error evaluating XPath selector in querySelectorAll", zap.String("selector", selector), zap.Error(err))
			return b.runtime.ToValue([]interface{}{})
		}
		var results []*goja.Object
		for _, node := range nodes {
			results = append(results, b.wrapNode(node))
		}
		return b.runtime.ToValue(results)
	}).(goja.Callable)
}

// -- Element Methods --

func (b *DOMBridge) jsClick(node *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		b.DispatchEventOnNode(node, "mousedown")
		b.DispatchEventOnNode(node, "mouseup")
		b.DispatchEventOnNode(node, "click")
		b.mu.RLock()
		tagName := strings.ToLower(node.Data)
		href := htmlquery.SelectAttr(node, "href")
		b.mu.RUnlock()
		if tagName == "a" && href != "" {
			location := b.runtime.Get("location").ToObject(b.runtime)
			if location != nil {
				propDesc, _ := location.Get("href")
				if propDesc != nil && !goja.IsUndefined(propDesc) {
					setter := propDesc.ToObject(b.runtime).Get("set")
					if setterFunc, ok := goja.AssertFunction(setter); ok {
						_, _ = setterFunc(location, b.runtime.ToValue(href))
					}
				}
			}
		}
		return goja.Undefined()
	}).(goja.Callable)
}

func (b *DOMBridge) jsFocus(node *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		b.DispatchEventOnNode(node, "focus")
		return goja.Undefined()
	}).(goja.Callable)
}

func (b *DOMBridge) jsBlur(node *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		b.DispatchEventOnNode(node, "blur")
		return goja.Undefined()
	}).(goja.Callable)
}

func (b *DOMBridge) bindAttributeMethods(obj *goja.Object, node *html.Node) {
	_ = obj.Set("getAttribute", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		b.mu.RLock()
		defer b.mu.RUnlock()
		val := htmlquery.SelectAttr(node, name)
		for _, attr := range node.Attr {
			if attr.Key == name {
				return b.runtime.ToValue(val)
			}
		}
		return goja.Null()
	})
	_ = obj.Set("setAttribute", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		setAttr(node, name, value)
		return goja.Undefined()
	})
	_ = obj.Set("removeAttribute", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		removeAttr(node, name)
		return goja.Undefined()
	})
}

func (b *DOMBridge) jsAppendChild(parentNode *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		childObj := call.Argument(0).ToObject(b.runtime)
		b.mu.Lock()
		defer b.mu.Unlock()
		childNode := b.unwrapNode(childObj)
		if childNode != nil {
			if childNode.Parent != nil {
				childNode.Parent.RemoveChild(childNode)
			}
			parentNode.AppendChild(childNode)
		}
		return call.Argument(0)
	}).(goja.Callable)
}

// =================================================================================================
// EventTarget Implementation (addEventListener, DispatchEvent)
// =================================================================================================

func (b *DOMBridge) jsAddEventListener(node *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}
		eventType := call.Argument(0).String()
		listenerVal := call.Argument(1)
		if _, ok := goja.AssertFunction(listenerVal); !ok {
			return goja.Undefined()
		}
		useCapture := false
		if len(call.Arguments) > 2 {
			optionsArg := call.Argument(2)
			if !goja.IsUndefined(optionsArg) {
				if obj, ok := optionsArg.Export().(map[string]interface{}); ok {
					if captureVal, ok := obj["capture"].(bool); ok {
						useCapture = captureVal
					}
				} else {
					useCapture = optionsArg.ToBoolean()
				}
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		b.addEventListener(node, eventType, listenerVal, useCapture)
		return goja.Undefined()
	}).(goja.Callable)
}

func (b *DOMBridge) jsRemoveEventListener(node *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		return goja.Undefined()
	}).(goja.Callable)
}

func (b *DOMBridge) jsDispatchEvent(node *html.Node) goja.Callable {
	return b.runtime.ToValue(func(call goja.FunctionCall) goja.Value {
		return goja.Undefined()
	}).(goja.Callable)
}

func (b *DOMBridge) addEventListener(node *html.Node, eventType string, listenerVal goja.Value, useCapture bool) {
	nodeListeners, exists := b.eventListeners[node]
	if !exists {
		nodeListeners = make(map[string]*listenerGroup)
		b.eventListeners[node] = nodeListeners
	}
	group, exists := nodeListeners[eventType]
	if !exists {
		group = &listenerGroup{}
		nodeListeners[eventType] = group
	}
	var targetList *[]goja.Value
	if useCapture {
		targetList = &group.Capturing
	} else {
		targetList = &group.Bubbling
	}
	for _, existingListener := range *targetList {
		if existingListener.SameAs(listenerVal) {
			return
		}
	}
	*targetList = append(*targetList, listenerVal)
}

func (b *DOMBridge) DispatchEventOnNode(targetNode *html.Node, eventType string) {
	const (
		EventPhaseCapturing = 1
		EventPhaseAtTarget  = 2
		EventPhaseBubbling  = 3
	)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.runtime == nil || targetNode == nil {
		return
	}
	bubbles := true
	switch eventType {
	case "focus", "blur", "load", "scroll":
		bubbles = false
	}
	var (
		stopPropagation bool
		currentPhase    uint16
	)
	var ancestors []*html.Node
	for n := targetNode.Parent; n != nil; n = n.Parent {
		ancestors = append(ancestors, n)
	}
	eventObj := b.runtime.NewObject()
	_ = eventObj.Set("type", eventType)
	_ = eventObj.Set("bubbles", bubbles)
	_ = eventObj.Set("target", b.wrapNode(targetNode))
	_ = eventObj.Set("stopPropagation", func(call goja.FunctionCall) goja.Value {
		stopPropagation = true
		return goja.Undefined()
	})
	getter := func(goja.FunctionCall) goja.Value {
		return b.runtime.ToValue(currentPhase)
	}
	b.DefineProperty(eventObj, "eventPhase", getter, nil)
	invokeListeners := func(node *html.Node, phase uint16) {
		group, exists := b.eventListeners[node][eventType]
		if !exists {
			return
		}
		var listeners []goja.Value
		if phase == EventPhaseCapturing {
			listeners = group.Capturing
		} else {
			listeners = group.Bubbling
		}
		thisObj := b.wrapNode(node)
		for _, listener := range listeners {
			if fn, ok := goja.AssertFunction(listener); ok {
				_, _ = fn(thisObj, eventObj)
			}
		}
	}
	currentPhase = EventPhaseCapturing
	for i := len(ancestors) - 1; i >= 0; i-- {
		invokeListeners(ancestors[i], EventPhaseCapturing)
		if stopPropagation {
			return
		}
	}
	currentPhase = EventPhaseAtTarget
	invokeListeners(targetNode, EventPhaseBubbling)
	invokeListeners(targetNode, EventPhaseCapturing)
	if stopPropagation {
		return
	}
	if bubbles {
		currentPhase = EventPhaseBubbling
		for _, node := range ancestors {
			invokeListeners(node, EventPhaseBubbling)
			if stopPropagation {
				return
			}
		}
	}
}

// =================================================================================================
// Window APIs (Timers, Storage, Location, Scroll)
// =================================================================================================

func (b *DOMBridge) initTimers() {
	timerFunc := func(isInterval bool) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			if b.eventLoop == nil {
				b.logger.Warn("Timer function called but no event loop is available.")
				return goja.Undefined()
			}
			callback, ok := goja.AssertFunction(call.Argument(0))
			if !ok {
				return goja.Undefined()
			}
			delay := call.Argument(1).ToInteger()
			if delay < 0 {
				delay = 0
			}
			var callbackArgs []goja.Value
			if len(call.Arguments) > 2 {
				callbackArgs = call.Arguments[2:]
			}
			timerCallback := func() {
				_, err := callback(goja.Undefined(), callbackArgs...)
				if err != nil {
					b.logger.Error("An error occurred in a timer callback", zap.Error(err))
				}
			}
			var timer interface{}
			duration := time.Duration(delay) * time.Millisecond
			if isInterval {
				timer = b.eventLoop.SetInterval(timerCallback, duration)
			} else {
				timer = b.eventLoop.SetTimeout(timerCallback, duration)
			}
			return b.runtime.ToValue(timer)
		}
	}
	clearTimerFunc := func(call goja.FunctionCall) goja.Value {
		if b.eventLoop == nil {
			return goja.Undefined()
		}
		timerID := call.Argument(0).Export()
		if timerID != nil {
			b.eventLoop.ClearTimeout(timerID)
		}
		return goja.Undefined()
	}
	global := b.runtime.GlobalObject()
	_ = global.Set("setTimeout", timerFunc(false))
	_ = global.Set("clearTimeout", clearTimerFunc)
	_ = global.Set("setInterval", timerFunc(true))
	_ = global.Set("clearInterval", clearTimerFunc)
}

func (b *DOMBridge) bindStorageAPIs() {
	createStorageObject := func(storageMap map[string]string) *goja.Object {
		obj := b.runtime.NewObject()
		_ = obj.Set("getItem", func(call goja.FunctionCall) goja.Value {
			key := call.Argument(0).String()
			b.mu.RLock()
			defer b.mu.RUnlock()
			if val, exists := storageMap[key]; exists {
				return b.runtime.ToValue(val)
			}
			return goja.Null()
		})
		_ = obj.Set("setItem", func(call goja.FunctionCall) goja.Value {
			key := call.Argument(0).String()
			value := call.Argument(1).String()
			b.mu.Lock()
			defer b.mu.Unlock()
			storageMap[key] = value
			return goja.Undefined()
		})
		_ = obj.Set("removeItem", func(call goja.FunctionCall) goja.Value {
			key := call.Argument(0).String()
			b.mu.Lock()
			defer b.mu.Unlock()
			delete(storageMap, key)
			return goja.Undefined()
		})
		_ = obj.Set("clear", func(call goja.FunctionCall) goja.Value {
			b.mu.Lock()
			defer b.mu.Unlock()
			for k := range storageMap {
				delete(storageMap, k)
			}
			return goja.Undefined()
		})
		getter := func(goja.FunctionCall) goja.Value {
			b.mu.RLock()
			defer b.mu.RUnlock()
			return b.runtime.ToValue(len(storageMap))
		}
		b.DefineProperty(obj, "length", getter, nil)
		return obj
	}
	global := b.runtime.GlobalObject()
	_ = global.Set("localStorage", createStorageObject(b.localStorage))
	_ = global.Set("sessionStorage", createStorageObject(b.sessionStorage))
}

func (b *DOMBridge) bindScrollAPIs() {
	window := b.runtime.GlobalObject()
	updateScroll := func(x, y int64) {
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}
		_ = window.Set("scrollX", x)
		_ = window.Set("scrollY", y)
		if b.document != nil {
			b.DispatchEventOnNode(b.document, "scroll")
		}
	}
	_ = window.Set("scrollTo", func(call goja.FunctionCall) goja.Value {
		var x, y int64
		if len(call.Arguments) > 0 {
			x = call.Argument(0).ToInteger()
		}
		if len(call.Arguments) > 1 {
			y = call.Argument(1).ToInteger()
		}
		updateScroll(x, y)
		return goja.Undefined()
	})
	_ = window.Set("scrollBy", func(call goja.FunctionCall) goja.Value {
		var dx, dy int64
		if len(call.Arguments) > 0 {
			dx = call.Argument(0).ToInteger()
		}
		if len(call.Arguments) > 1 {
			dy = call.Argument(1).ToInteger()
		}
		currentX := window.Get("scrollX").ToInteger()
		currentY := window.Get("scrollY").ToInteger()
		updateScroll(currentX+dx, currentY+dy)
		return goja.Undefined()
	})
}

func (b *DOMBridge) InitializeLocation(initialURLString string) {
	if b.runtime == nil {
		return
	}
	parsedURL, err := url.Parse(initialURLString)
	if err != nil || initialURLString == "" {
		parsedURL, _ = url.Parse("about:blank")
	}
	b.updateStateFromURL(parsedURL)
	location := b.runtime.NewObject()
	_ = b.runtime.Set("location", location)
	getter := func(propName string) func(goja.FunctionCall) goja.Value {
		return func(goja.FunctionCall) goja.Value {
			return b.runtime.ToValue(b.currentLocationState[propName])
		}
	}
	createStandardSetter := func(modifier func(*url.URL, string)) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			newValue := call.Argument(0).String()
			currentHref := b.currentLocationState["href"]
			u, err := url.Parse(currentHref)
			if err != nil {
				return call.Argument(0)
			}
			modifier(u, newValue)
			if u.String() != currentHref {
				b.updateStateFromURL(u)
				if b.navigateCallback != nil {
					b.navigateCallback(u.String())
				}
			}
			return call.Argument(0)
		}
	}
	setterHref := func(call goja.FunctionCall) goja.Value {
		newHref := call.Argument(0).String()
		currentHref := b.currentLocationState["href"]
		baseU, _ := url.Parse(currentHref)
		resolvedU, err := baseU.Parse(newHref)
		if err != nil {
			return call.Argument(0)
		}
		baseCopy, resolvedBase := *baseU, *resolvedU
		baseCopy.Fragment, resolvedBase.Fragment = "", ""
		if baseCopy.String() == resolvedBase.String() && currentHref != "about:blank" {
			return b.handleHashChange(resolvedU.Fragment)
		}
		b.updateStateFromURL(resolvedU)
		if b.navigateCallback != nil {
			b.navigateCallback(resolvedU.String())
		}
		return call.Argument(0)
	}
	b.DefineProperty(location, "href", getter("href"), setterHref)
	setterHash := func(call goja.FunctionCall) goja.Value {
		newHash := strings.TrimPrefix(call.Argument(0).String(), "#")
		return b.handleHashChange(newHash)
	}
	b.DefineProperty(location, "hash", getter("hash"), setterHash)
	b.DefineProperty(location, "protocol", getter("protocol"), createStandardSetter(func(u *url.URL, v string) { u.Scheme = strings.TrimSuffix(v, ":") }))
	b.DefineProperty(location, "host", getter("host"), createStandardSetter(func(u *url.URL, v string) { u.Host = v }))
	b.DefineProperty(location, "hostname", getter("hostname"), createStandardSetter(func(u *url.URL, v string) { u.Host = v + ":" + u.Port() }))
	b.DefineProperty(location, "port", getter("port"), createStandardSetter(func(u *url.URL, v string) { u.Host = u.Hostname() + ":" + v }))
	b.DefineProperty(location, "pathname", getter("pathname"), createStandardSetter(func(u *url.URL, v string) { u.Path = v }))
	b.DefineProperty(location, "search", getter("search"), createStandardSetter(func(u *url.URL, v string) { u.RawQuery = strings.TrimPrefix(v, "?") }))
	b.DefineProperty(location, "origin", getter("origin"), nil)
	_ = location.Set("reload", func(call goja.FunctionCall) goja.Value {
		if b.navigateCallback != nil {
			b.navigateCallback(b.currentLocationState["href"])
		}
		return goja.Undefined()
	})
	_ = location.Set("assign", setterHref)
	_ = location.Set("replace", setterHref)
	_ = location.Set("toString", func(call goja.FunctionCall) goja.Value { return b.runtime.ToValue(b.currentLocationState["href"]) })
}

func (b *DOMBridge) handleHashChange(newHash string) goja.Value {
	currentHref := b.currentLocationState["href"]
	u, _ := url.Parse(currentHref)
	if u.Fragment == newHash {
		return b.runtime.ToValue(newHash)
	}
	u.Fragment = newHash
	b.updateStateFromURL(u)
	if b.notifyURLChangeCallback != nil {
		b.notifyURLChangeCallback(u.String())
	}
	b.DispatchEventOnNode(b.document, "hashchange")
	return b.runtime.ToValue(newHash)
}

func (b *DOMBridge) updateStateFromURL(u *url.URL) {
	if u == nil {
		return
	}
	b.currentLocationState["href"] = u.String()
	b.currentLocationState["protocol"] = u.Scheme + ":"
	b.currentLocationState["host"] = u.Host
	b.currentLocationState["hostname"] = u.Hostname()
	b.currentLocationState["port"] = u.Port()
	b.currentLocationState["pathname"] = u.Path
	b.currentLocationState["search"] = ""
	if u.RawQuery != "" {
		b.currentLocationState["search"] = "?" + u.RawQuery
	}
	b.currentLocationState["hash"] = ""
	if u.Fragment != "" {
		b.currentLocationState["hash"] = "#" + u.Fragment
	}
	b.currentLocationState["origin"] = u.Scheme + "://" + u.Host
}

// =================================================================================================
// Go-side Utilities (Public API for Session)
// =================================================================================================

func (b *DOMBridge) QuerySelector(selector string) (*html.Node, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	node := htmlquery.FindOne(b.document, selector)
	if node == nil {
		return nil, NewElementNotFoundError(selector)
	}
	return node, nil
}

func (b *DOMBridge) GetOuterHTML() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var buf bytes.Buffer
	if err := html.Render(&buf, b.document); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// =================================================================================================
// Internal Helper Functions
// =================================================================================================

func (b *DOMBridge) DefineProperty(obj *goja.Object, propName string, getter interface{}, setter interface{}) {
	if b.runtime == nil {
		return
	}
	descriptor := b.runtime.NewObject()
	if getter != nil {
		_ = descriptor.Set("get", getter)
	}
	if setter != nil {
		_ = descriptor.Set("set", setter)
	}
	_ = descriptor.Set("enumerable", true)
	_ = descriptor.Set("configurable", true)
	objectConstructor := b.runtime.GlobalObject().Get("Object").ToObject(b.runtime)
	defineProperty, _ := goja.AssertFunction(objectConstructor.Get("defineProperty"))
	_, err := defineProperty(goja.Undefined(), obj, b.runtime.ToValue(propName), descriptor)
	if err != nil {
		b.logger.Error("Failed to define property", zap.String("property", propName), zap.Error(err))
	}
}

func camelToKebab(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && 'A' <= r && r <= 'Z' {
			result.WriteRune('-')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

func removeAttr(n *html.Node, key string) {
	if n == nil {
		return
	}
	for i, attr := range n.Attr {
		if attr.Key == key {
			n.Attr = append(n.Attr[:i], n.Attr[i+1:]...)
			return
		}
	}
}

func setAttr(n *html.Node, key, val string) {
	if n == nil {
		return
	}
	for i, attr := range n.Attr {
		if attr.Key == key {
			n.Attr[i].Val = val
			return
		}
	}
	n.Attr = append(n.Attr, html.Attribute{Key: key, Val: val})
}