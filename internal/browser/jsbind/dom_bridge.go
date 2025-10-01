// internal/browser/jsbind/dom_bridge.go
package jsbind

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"go.uber.org/zap"
	"golang.org/x/net/html"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Interfaces and Core Structs --

// BrowserEnvironment defines the callbacks the DOMBridge needs to interact with the Session.
type BrowserEnvironment interface {
	JSNavigate(targetURL string)
	NotifyURLChange(targetURL string)
	ExecuteFetch(ctx context.Context, req schemas.FetchRequest) (*schemas.FetchResponse, error)
	AddCookieFromString(cookieStr string) error
	GetCookieString() (string, error)
	PushHistory(state *schemas.HistoryState) error
	ReplaceHistory(state *schemas.HistoryState) error
	GetHistoryLength() int
	GetCurrentHistoryState() interface{}
	ResolveURL(targetURL string) (*url.URL, error)
}

// DOMBridge manages the synchronization between the *html.Node DOM representation and the Goja runtime.
type DOMBridge struct {
	mu sync.RWMutex

	document *html.Node
	runtime  *goja.Runtime
	logger   *zap.Logger

	eventLoop *eventloop.EventLoop
	browser   BrowserEnvironment

	// Re-introduced for O(1) Go -> JS lookups.
	nodeMap map[*html.Node]*goja.Object

	localStorage   map[string]string
	sessionStorage map[string]string

	currentLocationState map[string]string
	eventListeners       map[*html.Node]map[string]*listenerGroup
}

// nativeNode is a small struct that we embed within a Goja object.
type nativeNode struct {
	bridge *DOMBridge
	node   *html.Node
}

// listenerGroup stores event listeners separated by phase.
type listenerGroup struct {
	Capturing []goja.Value
	Bubbling  []goja.Value
}

// -- Constructor and Initialization --

// NewDOMBridge creates a new DOMBridge instance.
func NewDOMBridge(logger *zap.Logger, eventLoop *eventloop.EventLoop, browserEnv BrowserEnvironment) *DOMBridge {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &DOMBridge{
		logger:               logger.Named("dom_bridge"),
		eventLoop:            eventLoop,
		browser:              browserEnv,
		nodeMap:              make(map[*html.Node]*goja.Object),
		localStorage:         make(map[string]string),
		sessionStorage:       make(map[string]string),
		currentLocationState: make(map[string]string),
		eventListeners:       make(map[*html.Node]map[string]*listenerGroup),
	}
}

// BindToRuntime injects the DOM APIs into the Goja runtime.
func (b *DOMBridge) BindToRuntime(vm *goja.Runtime, initialURL string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.runtime = vm
	global := vm.GlobalObject()

	// Clear state from any previous binding.
	b.nodeMap = make(map[*html.Node]*goja.Object)
	b.eventListeners = make(map[*html.Node]map[string]*listenerGroup)

	if b.document == nil {
		doc, err := html.Parse(strings.NewReader("<html><head></head><body></body></html>"))
		if err != nil {
			panic("failed to parse fallback empty document: " + err.Error())
		}
		b.document = doc
	}

	documentObj := b.wrapNode(b.document)
	_ = global.Set("document", documentObj)
	_ = global.Set("window", global)
	_ = global.Set("self", global)

	b.initTimers()
	b.bindStorageAPIs()
	b.bindScrollAPIs()
	b.bindHistoryAPI()
	b.InitializeLocation(initialURL)

	_ = global.Set("innerWidth", 1920)
	_ = global.Set("innerHeight", 1080)
	_ = global.Set("scrollX", 0)
	_ = global.Set("scrollY", 0)
}

// UpdateDOM safely replaces the root document node.
func (b *DOMBridge) UpdateDOM(doc *html.Node) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if doc == nil {
		var err error
		doc, err = html.Parse(strings.NewReader("<html><head></head><body></body></html>"))
		if err != nil {
			panic("failed to parse fallback empty document: " + err.Error())
		}
	}
	b.document = doc
}

// GetDocumentNode provides thread safe access to the root document node.
func (b *DOMBridge) GetDocumentNode() *html.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.document
}

// -- Core Wrapping Logic --

// wrapNode creates or retrieves the Goja object wrapper for a given *html.Node.
func (b *DOMBridge) wrapNode(node *html.Node) *goja.Object {
	if node == nil {
		return nil
	}
	if obj, exists := b.nodeMap[node]; exists {
		return obj
	}

	native := &nativeNode{bridge: b, node: node}

	// FIX: Create a standard JavaScript object instead of a Host object (reflection wrapper).
	// Host objects do not support defining accessor properties (getters/setters).
	// obj := b.runtime.ToValue(native).ToObject(b.runtime) // OLD
	obj := b.runtime.NewObject()
	// Store the Go data within the JS object.
	_ = SetObjectData(b.runtime, obj, native)

	_ = obj.Set("nodeType", node.Type)
	_ = obj.Set("nodeName", strings.ToUpper(node.Data))
	b.defineParentAndChildProperties(obj, node)
	_ = obj.Set("appendChild", b.jsAppendChild(native))
	_ = obj.Set("removeChild", b.jsRemoveChild(native))
	_ = obj.Set("insertBefore", b.jsInsertBefore(native))
	_ = obj.Set("addEventListener", b.jsAddEventListener(native))
	_ = obj.Set("removeEventListener", b.jsRemoveEventListener(native))
	_ = obj.Set("dispatchEvent", b.jsDispatchEvent(native))
	b.bindDocumentAndElementMethods(obj, node)

	b.nodeMap[node] = obj
	return obj
}

// unwrapNode extracts the embedded *nativeNode struct from a JS object wrapper.
func unwrapNode(obj goja.Value) *nativeNode {
	if obj == nil || goja.IsUndefined(obj) || goja.IsNull(obj) {
		return nil
	}

	gojaObj := obj.ToObject(nil)
	if gojaObj == nil {
		return nil
	}

	// FIX: Retrieve the data using Data() instead of Export().
	// v, ok := obj.ToObject(nil).Export().(*nativeNode) // OLD

	data := GetObjectData(gojaObj)
	if data == nil {
		return nil
	}

	v, ok := data.(*nativeNode)
	if !ok {
		return nil
	}
	return v
}

// bindDocumentAndElementMethods attaches APIs based on the node type.
func (b *DOMBridge) bindDocumentAndElementMethods(obj *goja.Object, node *html.Node) {
	native := unwrapNode(obj)
	// Add nil check for safety, although wrapNode should ensure native is set.
	if native == nil {
		return
	}

	_ = obj.Set("querySelector", b.jsQuerySelector(native))
	_ = obj.Set("querySelectorAll", b.jsQuerySelectorAll(native))

	if node.Type == html.DocumentNode {
		_ = obj.Set("getElementById", b.jsGetElementById())
		_ = obj.Set("createElement", b.jsCreateElement())
		_ = obj.Set("write", b.jsDocumentWrite())
		b.defineCookieProperty(obj)
		if docElem := htmlquery.FindOne(node, "/html"); docElem != nil {
			_ = obj.Set("documentElement", b.wrapNode(docElem))
		}
		if body := htmlquery.FindOne(node, "//body"); body != nil {
			_ = obj.Set("body", b.wrapNode(body))
		}
		if head := htmlquery.FindOne(node, "//head"); head != nil {
			_ = obj.Set("head", b.wrapNode(head))
		}
	} else if node.Type == html.ElementNode {
		_ = obj.Set("tagName", strings.ToUpper(node.Data))
		b.defineHTMLProperties(obj, node)
		b.defineValueProperty(obj, node)
		b.defineDatasetProperty(obj, node)
		b.defineStyleProperty(obj, node)
		b.defineAttributeProperty(obj, node, "id", "id")
		b.defineAttributeProperty(obj, node, "className", "class")
		b.defineAttributeProperty(obj, node, "href", "href")
		b.defineAttributeProperty(obj, node, "src", "src")
		b.defineAttributeProperty(obj, node, "title", "title")
		b.defineAttributeProperty(obj, node, "alt", "alt")
		b.defineBooleanAttributeProperty(obj, node, "disabled", "disabled")
		b.defineBooleanAttributeProperty(obj, node, "checked", "checked")
		b.defineBooleanAttributeProperty(obj, node, "selected", "selected")
		b.defineBooleanAttributeProperty(obj, node, "readOnly", "readonly")
		b.defineBooleanAttributeProperty(obj, node, "required", "required")
		b.bindAttributeMethods(obj, node)
		_ = obj.Set("click", b.jsClick(native))
		_ = obj.Set("focus", b.jsFocus(native))
		_ = obj.Set("blur", b.jsBlur(native))
	}
}

// -- JS Property Definitions --

func (b *DOMBridge) defineParentAndChildProperties(obj *goja.Object, node *html.Node) {
	_ = obj.Set("parentNode", b.runtime.ToValue(func() goja.Value {
		b.mu.Lock()
		defer b.mu.Unlock()
		if parent := b.wrapNode(node.Parent); parent != nil {
			return parent
		}
		return goja.Null()
	}))

	b.DefineProperty(obj, "childNodes", func() goja.Value {
		b.mu.Lock()
		defer b.mu.Unlock()
		var children []*goja.Object
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			if wrapped := b.wrapNode(c); wrapped != nil {
				children = append(children, wrapped)
			}
		}
		return b.runtime.ToValue(children)
	}, nil)
}

func (b *DOMBridge) defineHTMLProperties(obj *goja.Object, node *html.Node) {
	getter := func() goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		var buf bytes.Buffer
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			_ = html.Render(&buf, c)
		}
		return b.runtime.ToValue(buf.String())
	}
	setter := func(value goja.Value) {
		nodes, err := html.ParseFragment(strings.NewReader(value.String()), node)
		if err != nil {
			b.logger.Warn("Failed to parse innerHTML", zap.Error(err))
			return
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
	}
	b.DefineProperty(obj, "innerHTML", getter, setter)
}

func (b *DOMBridge) defineValueProperty(obj *goja.Object, node *html.Node) {
	getter := func() goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		if strings.ToLower(node.Data) == "textarea" {
			return b.runtime.ToValue(htmlquery.InnerText(node))
		}
		return b.runtime.ToValue(htmlquery.SelectAttr(node, "value"))
	}
	setter := func(value goja.Value) {
		valStr := value.String()
		b.mu.Lock()
		defer b.mu.Unlock()
		if strings.ToLower(node.Data) == "textarea" {
			for c := node.FirstChild; c != nil; {
				next := c.NextSibling
				node.RemoveChild(c)
				c = next
			}
			node.AppendChild(&html.Node{Type: html.TextNode, Data: valStr})
		} else {
			setAttr(node, "value", valStr)
		}
	}
	b.DefineProperty(obj, "value", getter, setter)
}

func (b *DOMBridge) defineDatasetProperty(obj *goja.Object, elementNode *html.Node) {
	getter := func() goja.Value {
		target := b.runtime.NewObject()
		trapConfig := &goja.ProxyTrapConfig{
			Get: func(t *goja.Object, p string, r goja.Value) goja.Value {
				attrName := "data-" + camelToKebab(p)
				b.mu.RLock()
				defer b.mu.RUnlock()
				for _, attr := range elementNode.Attr {
					if attr.Key == attrName {
						return b.runtime.ToValue(attr.Val)
					}
				}
				return goja.Undefined()
			},
			Set: func(t *goja.Object, p string, v goja.Value, r goja.Value) bool {
				attrName := "data-" + camelToKebab(p)
				b.mu.Lock()
				defer b.mu.Unlock()
				setAttr(elementNode, attrName, v.String())
				return true
			},
		}
		return b.runtime.ToValue(b.runtime.NewProxy(target, trapConfig))
	}
	b.DefineProperty(obj, "dataset", getter, nil)
}

func (b *DOMBridge) defineCookieProperty(docObj *goja.Object) {
	getter := func() goja.Value {
		if b.browser == nil {
			return b.runtime.ToValue("")
		}
		cookieStr, err := b.browser.GetCookieString()
		if err != nil {
			b.logger.Warn("failed to get cookie string", zap.Error(err))
			return b.runtime.ToValue("")
		}
		return b.runtime.ToValue(cookieStr)
	}
	setter := func(value goja.Value) {
		if b.browser != nil {
			if err := b.browser.AddCookieFromString(value.String()); err != nil {
				b.logger.Warn("failed to set cookie string", zap.Error(err))
			}
		}
	}
	b.DefineProperty(docObj, "cookie", getter, setter)
}
// -- JS Method Implementations --

func (b *DOMBridge) jsGetElementById() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		id := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		// XPath does not handle all characters in IDs well, so we escape quotes.
		escapedID := strings.ReplaceAll(id, "'", "\\'")
		xpath := fmt.Sprintf("//*[@id='%s']", escapedID)
		node := htmlquery.FindOne(b.document, xpath)
		if node == nil {
			return goja.Null()
		}
		return b.wrapNode(node)
	}
}

func (b *DOMBridge) jsCreateElement() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		tagName := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		node := &html.Node{
			Type: html.ElementNode,
			Data: strings.ToLower(tagName),
		}
		// We wrap it, which also adds it to our internal tracking if needed.
		return b.wrapNode(node)
	}
}

func (b *DOMBridge) jsDocumentWrite() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
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
	}
}

func (b *DOMBridge) jsQuerySelector(contextNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		selector := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		node, err := htmlquery.Query(contextNative.node, selector)
		if err != nil {
			b.logger.Warn("Error evaluating XPath selector in querySelector", zap.String("selector", selector), zap.Error(err))
			return goja.Null()
		}
		if node == nil {
			return goja.Null()
		}
		return b.wrapNode(node)
	}
}

func (b *DOMBridge) jsQuerySelectorAll(contextNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		selector := call.Argument(0).String()
		b.mu.Lock()
		defer b.mu.Unlock()
		nodes, err := htmlquery.QueryAll(contextNative.node, selector)
		if err != nil {
			b.logger.Warn("Error evaluating XPath selector in querySelectorAll", zap.String("selector", selector), zap.Error(err))
			return b.runtime.NewArray()
		}
		results := make([]goja.Value, len(nodes))
		for i, node := range nodes {
			results[i] = b.wrapNode(node)
		}
		return b.runtime.ToValue(results)
	}
}

func (b *DOMBridge) jsClick(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		// Event dispatching handles its own locking.
		b.DispatchEventOnNode(native.node, "mousedown")
		b.DispatchEventOnNode(native.node, "mouseup")
		b.DispatchEventOnNode(native.node, "click")

		b.mu.RLock()
		tagName := strings.ToLower(native.node.Data)
		href := htmlquery.SelectAttr(native.node, "href")
		b.mu.RUnlock()

		// If it's a link with an href, simulate navigation.
		if tagName == "a" && href != "" {
			b.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				locationVal := vm.Get("location")
				if location, ok := locationVal.(*goja.Object); ok {
					if err := location.Set("href", href); err != nil {
						b.logger.Warn("Failed to set location.href during click simulation", zap.Error(err))
					}
				}
			})
		}
		return goja.Undefined()
	}
}

func (b *DOMBridge) jsFocus(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		b.DispatchEventOnNode(native.node, "focus")
		return goja.Undefined()
	}
}

func (b *DOMBridge) jsBlur(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		b.DispatchEventOnNode(native.node, "blur")
		return goja.Undefined()
	}
}

func (b *DOMBridge) bindAttributeMethods(obj *goja.Object, node *html.Node) {
	_ = obj.Set("getAttribute", func(name string) goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		for _, attr := range node.Attr {
			if attr.Key == name {
				return b.runtime.ToValue(attr.Val)
			}
		}
		return goja.Null()
	})
	_ = obj.Set("setAttribute", func(name, value string) {
		b.mu.Lock()
		defer b.mu.Unlock()
		setAttr(node, name, value)
	})
	_ = obj.Set("removeAttribute", func(name string) {
		b.mu.Lock()
		defer b.mu.Unlock()
		removeAttr(node, name)
	})
}

func (b *DOMBridge) jsAppendChild(parentNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		childNative := unwrapNode(call.Argument(0))
		if childNative == nil {
			return goja.Undefined()
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if childNative.node.Parent != nil {
			childNative.node.Parent.RemoveChild(childNative.node)
		}
		parentNative.node.AppendChild(childNative.node)
		return call.Argument(0)
	}
}

func (b *DOMBridge) jsRemoveChild(parentNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		childNative := unwrapNode(call.Argument(0))
		if childNative == nil {
			// In JS this would throw an error, we'll just no-op.
			return goja.Undefined()
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		// Verify the child actually belongs to this parent.
		if childNative.node.Parent == parentNative.node {
			parentNative.node.RemoveChild(childNative.node)
		}
		return call.Argument(0)
	}
}

func (b *DOMBridge) jsInsertBefore(parentNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		newNative := unwrapNode(call.Argument(0))
		refNative := unwrapNode(call.Argument(1))

		if newNative == nil {
			return goja.Undefined()
		}

		b.mu.Lock()
		defer b.mu.Unlock()

		// If the new node is already in the tree, remove it first.
		if newNative.node.Parent != nil {
			newNative.node.Parent.RemoveChild(newNative.node)
		}

		if refNative == nil {
			// If reference node is null, append to the end.
			parentNative.node.AppendChild(newNative.node)
		} else {
			// Verify the reference node is a child of the parent.
			if refNative.node.Parent == parentNative.node {
				parentNative.node.InsertBefore(newNative.node, refNative.node)
			}
		}

		return call.Argument(0)
	}
}

// -- EventTarget Implementation --

func (b *DOMBridge) jsAddEventListener(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
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
			if obj, ok := optionsArg.Export().(map[string]interface{}); ok {
				if captureVal, ok := obj["capture"].(bool); ok {
					useCapture = captureVal
				}
			} else {
				useCapture = optionsArg.ToBoolean()
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		b.addEventListener(native.node, eventType, listenerVal, useCapture)
		return goja.Undefined()
	}
}

func (b *DOMBridge) jsRemoveEventListener(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		// A full implementation would need to parse the arguments similar to addEventListener
		// and then find and remove the matching function from the slice.
		b.logger.Warn("removeEventListener is not fully implemented")
		return goja.Undefined()
	}
}

func (b *DOMBridge) jsDispatchEvent(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		eventObj := call.Argument(0).ToObject(b.runtime)
		if eventObj == nil {
			return goja.Undefined()
		}
		eventType := eventObj.Get("type").String()
		b.DispatchEventOnNode(native.node, eventType)
		return goja.Undefined()
	}
}

// addEventListener is the internal logic for adding a listener to the map.
// It must be called while holding a write lock.
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
	// Prevent duplicate listeners.
	for _, existingListener := range *targetList {
		if existingListener.SameAs(listenerVal) {
			return
		}
	}
	*targetList = append(*targetList, listenerVal)
}

// DispatchEventOnNode implements the W3C event propagation model: Capturing -> Target -> Bubbling.
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

	var ancestors []*html.Node
	for n := targetNode.Parent; n != nil; n = n.Parent {
		ancestors = append(ancestors, n)
	}

	var (
		stopPropagation  bool
		defaultPrevented bool
		currentPhase     uint16
	)
	eventObj := b.runtime.NewObject()
	_ = eventObj.Set("type", eventType)
	_ = eventObj.Set("bubbles", bubbles)
	_ = eventObj.Set("target", b.wrapNode(targetNode))
	_ = eventObj.Set("stopPropagation", func() { stopPropagation = true })
	_ = eventObj.Set("preventDefault", func() { defaultPrevented = true })
	b.DefineProperty(eventObj, "eventPhase", func() goja.Value { return b.runtime.ToValue(currentPhase) }, nil)
	b.DefineProperty(eventObj, "defaultPrevented", func() goja.Value { return b.runtime.ToValue(defaultPrevented) }, nil)

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
				if _, err := fn(thisObj, eventObj); err != nil {
					b.logger.Error("Error executing event listener", zap.String("eventType", eventType), zap.Error(err))
				}
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
	invokeListeners(targetNode, EventPhaseCapturing)
	if stopPropagation {
		return
	}
	invokeListeners(targetNode, EventPhaseBubbling)
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

// -- Window APIs (Timers, Storage, Location, etc.) --

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

			timerCallback := func(vm *goja.Runtime) {
				if _, err := callback(goja.Undefined(), callbackArgs...); err != nil {
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

	clearer := func(call goja.FunctionCall) goja.Value {
		if b.eventLoop == nil {
			return goja.Undefined()
		}
		timerID := call.Argument(0).Export()
		if timerID == nil {
			return goja.Undefined()
		}
		switch t := timerID.(type) {
		case *eventloop.Timer:
			b.eventLoop.ClearTimeout(t)
		case *eventloop.Interval:
			b.eventLoop.ClearInterval(t)
		}
		return goja.Undefined()
	}

	global := b.runtime.GlobalObject()
	_ = global.Set("setTimeout", timerFunc(false))
	_ = global.Set("setInterval", timerFunc(true))
	_ = global.Set("clearTimeout", clearer)
	_ = global.Set("clearInterval", clearer)
}

func (b *DOMBridge) bindStorageAPIs() {
	createStorageObject := func(storageMap map[string]string) *goja.Object {
		obj := b.runtime.NewObject()
		_ = obj.Set("getItem", func(key string) goja.Value {
			b.mu.RLock()
			defer b.mu.RUnlock()
			if val, exists := storageMap[key]; exists {
				return b.runtime.ToValue(val)
			}
			return goja.Null()
		})
		_ = obj.Set("setItem", func(key, value string) {
			b.mu.Lock()
			defer b.mu.Unlock()
			storageMap[key] = value
		})
		_ = obj.Set("removeItem", func(key string) {
			b.mu.Lock()
			defer b.mu.Unlock()
			delete(storageMap, key)
		})
		_ = obj.Set("clear", func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			for k := range storageMap {
				delete(storageMap, k)
			}
		})
		b.DefineProperty(obj, "length", func() goja.Value {
			b.mu.RLock()
			defer b.mu.RUnlock()
			return b.runtime.ToValue(len(storageMap))
		}, nil)
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
		if docNode := b.GetDocumentNode(); docNode != nil {
			b.DispatchEventOnNode(docNode, "scroll")
		}
	}
	_ = window.Set("scrollTo", func(x, y int64) {
		updateScroll(x, y)
	})
	_ = window.Set("scrollBy", func(dx, dy int64) {
		currentX := window.Get("scrollX").ToInteger()
		currentY := window.Get("scrollY").ToInteger()
		updateScroll(currentX+dx, currentY+dy)
	})
}

func (b *DOMBridge) bindHistoryAPI() {
	if b.browser == nil {
		return
	}
	history := b.runtime.NewObject()
	_ = history.Set("pushState", func(state goja.Value, title string, url goja.Value) {
		b.browser.PushHistory(&schemas.HistoryState{
			State: state.Export(),
			Title: title,
			URL:   url.String(),
		})
	})
	_ = history.Set("replaceState", func(state goja.Value, title string, url goja.Value) {
		b.browser.ReplaceHistory(&schemas.HistoryState{
			State: state.Export(),
			Title: title,
			URL:   url.String(),
		})
})

	b.DefineProperty(history, "length", func() goja.Value {
		return b.runtime.ToValue(b.browser.GetHistoryLength())
	}, nil)
	b.DefineProperty(history, "state", func() goja.Value {
		return b.runtime.ToValue(b.browser.GetCurrentHistoryState())
	}, nil)
	b.runtime.GlobalObject().Set("history", history)
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

	getter := func(propName string) func() goja.Value {
		return func() goja.Value {
			b.mu.RLock()
			defer b.mu.RUnlock()
			return b.runtime.ToValue(b.currentLocationState[propName])
		}
	}

	createStandardSetter := func(modifier func(*url.URL, string)) func(value goja.Value) {
		return func(value goja.Value) {
			b.mu.Lock()
			currentHref := b.currentLocationState["href"]
			u, err := url.Parse(currentHref)
			if err != nil {
				b.mu.Unlock()
				return
			}
			modifier(u, value.String())
			newURLString := u.String()
			if newURLString != currentHref {
				b.updateStateFromURL(u)
				b.mu.Unlock()
				if b.browser != nil {
					b.browser.JSNavigate(newURLString)
				}
			} else {
				b.mu.Unlock()
			}
		}
	}

	setterHref := func(value goja.Value) {
		newHref := value.String()
		b.mu.Lock()
		currentHref := b.currentLocationState["href"]
		baseU, err := url.Parse(currentHref)
		if err != nil {
			b.mu.Unlock()
			if b.browser != nil {
				b.browser.JSNavigate(newHref)
			}
			return
		}
		resolvedU, err := baseU.Parse(newHref)
		if err != nil {
			b.mu.Unlock()
			return
		}
		resolvedURLString := resolvedU.String()
		b.updateStateFromURL(resolvedU)
		b.mu.Unlock()
		if b.browser != nil {
			b.browser.JSNavigate(resolvedURLString)
		}
	}

	setterHash := func(value goja.Value) {
		b.handleHashChange(strings.TrimPrefix(value.String(), "#"))
	}

	b.DefineProperty(location, "href", getter("href"), setterHref)
	b.DefineProperty(location, "hash", getter("hash"), setterHash)
	b.DefineProperty(location, "protocol", getter("protocol"), createStandardSetter(func(u *url.URL, v string) { u.Scheme = strings.TrimSuffix(v, ":") }))
	b.DefineProperty(location, "host", getter("host"), createStandardSetter(func(u *url.URL, v string) { u.Host = v }))
	b.DefineProperty(location, "hostname", getter("hostname"), createStandardSetter(func(u *url.URL, v string) {
		if port := u.Port(); port != "" {
			u.Host = v + ":" + port
		} else {
			u.Host = v
		}
	}))
	b.DefineProperty(location, "port", getter("port"), createStandardSetter(func(u *url.URL, v string) { u.Host = u.Hostname() + ":" + v }))
	b.DefineProperty(location, "pathname", getter("pathname"), createStandardSetter(func(u *url.URL, v string) { u.Path = v }))
	b.DefineProperty(location, "search", getter("search"), createStandardSetter(func(u *url.URL, v string) { u.RawQuery = strings.TrimPrefix(v, "?") }))
	b.DefineProperty(location, "origin", getter("origin"), nil)
	_ = location.Set("reload", func() {
		b.mu.RLock()
		href := b.currentLocationState["href"]
		b.mu.RUnlock()
		if b.browser != nil {
			b.browser.JSNavigate(href)
		}
	})
	_ = location.Set("assign", setterHref)
	_ = location.Set("replace", setterHref)
	_ = location.Set("toString", getter("href"))
}

func (b *DOMBridge) handleHashChange(newHash string) {
	b.mu.Lock()
	currentHref := b.currentLocationState["href"]
	u, _ := url.Parse(currentHref)
	if u.Fragment == newHash {
		b.mu.Unlock()
		return
	}
	u.Fragment = newHash
	newURLString := u.String()
	b.updateStateFromURL(u)
	b.mu.Unlock()

	if b.browser != nil {
		b.browser.NotifyURLChange(newURLString)
	}
	if docNode := b.GetDocumentNode(); docNode != nil {
		b.DispatchEventOnNode(docNode, "hashchange")
	}
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
	if (u.Scheme == "http" || u.Scheme == "https") && u.Path == "" {
		b.currentLocationState["pathname"] = "/"
	} else {
		b.currentLocationState["pathname"] = u.Path
	}
	if u.RawQuery != "" {
		b.currentLocationState["search"] = "?" + u.RawQuery
	} else {
		b.currentLocationState["search"] = ""
	}
	if u.Fragment != "" {
		b.currentLocationState["hash"] = "#" + u.Fragment
	} else {
		b.currentLocationState["hash"] = ""
	}
	if u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "ftp" {
		b.currentLocationState["origin"] = u.Scheme + "://" + u.Host
	} else {
		b.currentLocationState["origin"] = "null"
	}
}

// -- Go-side Utilities --

func (b *DOMBridge) QuerySelector(selector string) (*html.Node, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	node := htmlquery.FindOne(b.document, selector)
	if node == nil {
		return nil, fmt.Errorf("element not found for selector: %s", selector)
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

// -- Internal Helper Functions --

// SetObjectData attaches an arbitrary Go value to a goja.Object using a hidden property.
func SetObjectData(rt *goja.Runtime, obj *goja.Object, data interface{}) error {
	wrappedData := rt.ToValue(data)
	// Define a non-enumerable, non-writable, non-configurable property to store the data.
	return obj.DefineDataProperty("__native__", wrappedData, goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE)
}

// GetObjectData retrieves an arbitrary Go value previously attached by SetObjectData.
func GetObjectData(obj *goja.Object) interface{} {
	if obj == nil {
		return nil
	}
	wrappedData := obj.Get("__native__")
	if wrappedData == nil || goja.IsUndefined(wrappedData) || goja.IsNull(wrappedData) {
		return nil
	}
	return wrappedData.Export()
}

func (b *DOMBridge) DefineProperty(obj *goja.Object, name string, getter interface{}, setter interface{}) {
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
	defineProperty, ok := goja.AssertFunction(objectConstructor.Get("defineProperty"))
	if !ok {
		b.logger.Error("Object.defineProperty not found or not a function")
		return
	}
	if _, err := defineProperty(goja.Undefined(), obj, b.runtime.ToValue(name), descriptor); err != nil {
		b.logger.Error("Failed to define property", zap.String("property", name), zap.Error(err))
	}
}

func (b *DOMBridge) defineAttributeProperty(obj *goja.Object, node *html.Node, propName, attrName string) {
	getter := func() goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		val := htmlquery.SelectAttr(node, attrName)
		if (propName == "href" || propName == "src") && b.browser != nil {
			if resolved, err := b.browser.ResolveURL(val); err == nil {
				return b.runtime.ToValue(resolved.String())
			}
		}
		return b.runtime.ToValue(val)
	}
	setter := func(value goja.Value) {
		b.mu.Lock()
		defer b.mu.Unlock()
		setAttr(node, attrName, value.String())
	}
	b.DefineProperty(obj, propName, getter, setter)
}

func (b *DOMBridge) defineBooleanAttributeProperty(obj *goja.Object, node *html.Node, propName, attrName string) {
	getter := func() goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		for _, attr := range node.Attr {
			if attr.Key == attrName {
				return b.runtime.ToValue(true)
			}
		}
		return b.runtime.ToValue(false)
	}
	setter := func(value goja.Value) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if value.ToBoolean() {
			setAttr(node, attrName, "")
		} else {
			removeAttr(node, attrName)
		}
	}
	b.DefineProperty(obj, propName, getter, setter)
}

func parseStyleAttribute(styleStr string) map[string]string {
	styles := make(map[string]string)
	for _, part := range strings.Split(styleStr, ";") {
		if strings.Contains(part, ":") {
			kv := strings.SplitN(part, ":", 2)
			if key := strings.TrimSpace(kv[0]); key != "" {
				styles[key] = strings.TrimSpace(kv[1])
			}
		}
	}
	return styles
}

func serializeStyleAttribute(styles map[string]string) string {
	parts := make([]string, 0, len(styles))
	for key, val := range styles {
		parts = append(parts, key+": "+val)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (b *DOMBridge) defineStyleProperty(obj *goja.Object, node *html.Node) {
	getter := func() goja.Value {
		target := b.runtime.NewObject()
		trapConfig := &goja.ProxyTrapConfig{
			Get: func(t *goja.Object, p string, r goja.Value) goja.Value {
				b.mu.RLock()
				defer b.mu.RUnlock()
				styles := parseStyleAttribute(htmlquery.SelectAttr(node, "style"))
				if val, ok := styles[camelToKebab(p)]; ok {
					return b.runtime.ToValue(val)
				}
				return goja.Undefined()
			},
			Set: func(t *goja.Object, p string, v goja.Value, r goja.Value) bool {
				b.mu.Lock()
				defer b.mu.Unlock()
				styles := parseStyleAttribute(htmlquery.SelectAttr(node, "style"))
				styles[camelToKebab(p)] = v.String()
				setAttr(node, "style", serializeStyleAttribute(styles))
				return true
			},
		}
		return b.runtime.ToValue(b.runtime.NewProxy(target, trapConfig))
	}
	b.DefineProperty(obj, "style", getter, nil)
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