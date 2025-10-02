// internal/browser/jsbind/dom_bridge.go
package jsbind

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
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
	"github.com/xkilldash9x/scalpel-cli/internal/browser/layout"
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

	// Stores the root of the computed layout tree for hit-testing.
	layoutRoot *layout.LayoutBox

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
	b.layoutRoot = nil // Clear layout tree on re-bind

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

// UpdateLayoutTree provides the DOMBridge with the latest calculated layout tree.
// This should be called by the session after a layout pass.
func (b *DOMBridge) UpdateLayoutTree(root *layout.LayoutBox) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.layoutRoot = root
}

// Lock exposes the write lock for external synchronization (e.g., from Session).
func (b *DOMBridge) Lock() {
	b.mu.Lock()
}

// Unlock exposes the write unlock for external synchronization.
func (b *DOMBridge) Unlock() {
	b.mu.Unlock()
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

	obj := b.runtime.NewObject()
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
		// Dispatch the standard JS events.
		b.DispatchEventOnNode(native.node, "mousedown")
		b.DispatchEventOnNode(native.node, "mouseup")
		b.DispatchEventOnNode(native.node, "click")

		// Perform the browser's default action.
		b.mu.Lock()
		defer b.mu.Unlock()
		b.PerformDefaultClickAction(native.node)

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
			return goja.Undefined()
		}
		b.mu.Lock()
		defer b.mu.Unlock()
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

		if newNative.node.Parent != nil {
			newNative.node.Parent.RemoveChild(newNative.node)
		}

		if refNative == nil {
			parentNative.node.AppendChild(newNative.node)
		} else {
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
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}
		eventType := call.Argument(0).String()
		listenerVal := call.Argument(1)
		if _, ok := goja.AssertFunction(listenerVal); !ok {
			// Real browsers silently ignore attempts to remove non-function listeners.
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
		b.removeEventListener(native.node, eventType, listenerVal, useCapture)
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

func (b *DOMBridge) removeEventListener(node *html.Node, eventType string, listenerVal goja.Value, useCapture bool) {
	nodeListeners, exists := b.eventListeners[node]
	if !exists {
		return
	}
	group, exists := nodeListeners[eventType]
	if !exists {
		return
	}

	// Figure out if we're dealing with the bubbling or capturing phase listeners.
	var targetList *[]goja.Value
	if useCapture {
		targetList = &group.Capturing
	} else {
		targetList = &group.Bubbling
	}

	// Find the index of the listener to remove.
	// It's crucial to compare function references, which SameAs does.
	foundIndex := -1
	for i, existingListener := range *targetList {
		if existingListener.SameAs(listenerVal) {
			foundIndex = i
			break
		}
	}

	// If we found the listener, remove it from the slice.
	if foundIndex != -1 {
		*targetList = append((*targetList)[:foundIndex], (*targetList)[foundIndex+1:]...)
	}

	// Clean up empty maps to prevent memory leaks.
	if len(group.Capturing) == 0 && len(group.Bubbling) == 0 {
		delete(nodeListeners, eventType)
	}
	if len(nodeListeners) == 0 {
		delete(b.eventListeners, node)
	}
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

// PerformDefaultClickAction contains the core logic for what happens when an element is clicked.
// It's called by both the JS .click() method and the native mouse event handler.
// NOTE: This function assumes a write lock is already held on the DOMBridge.
func (b *DOMBridge) PerformDefaultClickAction(node *html.Node) {
	tagName := strings.ToLower(node.Data)

	switch tagName {
	case "a":
		if href := htmlquery.SelectAttr(node, "href"); href != "" {
			if b.browser != nil {
				if resolvedURL, err := b.browser.ResolveURL(href); err == nil {
					b.browser.JSNavigate(resolvedURL.String())
				}
			}
		}

	case "input":
		inputType := strings.ToLower(htmlquery.SelectAttr(node, "type"))
		switch inputType {
		case "checkbox":
			if _, hasChecked := getAttribute(node, "checked"); hasChecked {
				removeAttr(node, "checked")
			} else {
				setAttr(node, "checked", "")
			}
		case "radio":
			name := htmlquery.SelectAttr(node, "name")
			if name == "" {
				setAttr(node, "checked", "")
				return
			}
			xpath := fmt.Sprintf("//input[@type='radio'][@name='%s']", name)
			radioGroup, _ := htmlquery.QueryAll(b.document, xpath)
			for _, radioNode := range radioGroup {
				if radioNode != node {
					removeAttr(radioNode, "checked")
				}
			}
			setAttr(node, "checked", "")
		case "submit":
			if formNode := findParentForm(node); formNode != nil {
				b.submitForm(formNode, node)
			}
		}

	case "button":
		buttonType := strings.ToLower(htmlquery.SelectAttr(node, "type"))
		if buttonType == "submit" || buttonType == "" {
			if formNode := findParentForm(node); formNode != nil {
				b.submitForm(formNode, node)
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

// FindNodeAtPoint performs a hit-test on the layout tree to find the top-most
// rendered element at the given viewport coordinates (x, y).
func (b *DOMBridge) FindNodeAtPoint(x, y float64) *html.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.layoutRoot == nil {
		b.logger.Warn("FindNodeAtPoint called but layout tree is not available.")
		return nil
	}

	hitBox := b.hitTestRecursive(b.layoutRoot, x, y)
	if hitBox != nil && hitBox.StyledNode != nil {
		return hitBox.StyledNode.Node
	}

	return nil
}

// hitTestRecursive traverses the layout tree to find a matching box.
// It checks children first in reverse rendering order (last child first).
func (b *DOMBridge) hitTestRecursive(box *layout.LayoutBox, x, y float64) *layout.LayoutBox {
	if box == nil {
		return nil
	}

	// Hit test children first, from top-most to bottom-most in the stacking context.
	for i := len(box.Children) - 1; i >= 0; i-- {
		child := box.Children[i]
		if found := b.hitTestRecursive(child, x, y); found != nil {
			return found
		}
	}

	// If no children were hit, check the current box itself.

	// A proper hit test must account for transforms. We do this by applying the
	// inverse transform to the point, and then checking if that transformed point
	// lies within the original, untransformed bounding box of the element.
	invTransform, err := box.Dimensions.Transform.Inverse()
	if err != nil {
		// Non-invertible transform, we can't accurately hit-test this element.
		return nil
	}
	transformedX, transformedY := invTransform.Apply(x, y)

	// Check if the node is actually visible and can be interacted with.
	if box.StyledNode != nil && !box.StyledNode.IsVisible() {
		return nil
	}

	// Ignore clicks on anonymous boxes, as they aren't real elements.
	if box.BoxType == layout.AnonymousBlockBox {
		return nil
	}

	// Respect the 'pointer-events: none' CSS property.
	if box.StyledNode != nil && box.StyledNode.Lookup("pointer-events", "auto") == "none" {
		return nil
	}

	// Perform the hit check against the untransformed border box.
	borderBox := box.Dimensions.BorderBox()
	isHit := transformedX >= borderBox.X &&
		transformedX < borderBox.X+borderBox.Width &&
		transformedY >= borderBox.Y &&
		transformedY < borderBox.Y+borderBox.Height

	if isHit {
		return box
	}

	return nil
}

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

// -- Internal Helper Functions --

func SetObjectData(rt *goja.Runtime, obj *goja.Object, data interface{}) error {
	wrappedData := rt.ToValue(data)
	return obj.DefineDataProperty("__native__", wrappedData, goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE)
}

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

func findParentForm(node *html.Node) *html.Node {
	curr := node
	for curr != nil {
		if curr.Type == html.ElementNode && strings.ToLower(curr.Data) == "form" {
			return curr
		}
		curr = curr.Parent
	}
	return nil
}

// submitForm orchestrates the form submission process, handling GET and POST methods.
// This function must be called while holding a write lock on the DOMBridge.
func (b *DOMBridge) submitForm(formNode, submitterNode *html.Node) {
	if b.browser == nil {
		return
	}

	// 1. Determine method, action, and encoding type
	method := strings.ToUpper(htmlquery.SelectAttr(formNode, "method"))
	if method != "POST" {
		method = "GET" // Default to GET
	}

	action := htmlquery.SelectAttr(formNode, "action")
	resolvedURL, err := b.browser.ResolveURL(action)
	if err != nil {
		b.logger.Warn("Could not resolve form action URL", zap.String("action", action), zap.Error(err))
		return
	}

	enctype := strings.ToLower(htmlquery.SelectAttr(formNode, "enctype"))
	if enctype == "" {
		enctype = "application/x-www-form-urlencoded" // Default enctype
	}

	// 2. Serialize form data based on method and enctype
	formData := b.serializeForm(formNode, submitterNode)

	b.logger.Info("Submitting form",
		zap.String("method", method),
		zap.String("action", resolvedURL.String()),
		zap.String("enctype", enctype))

	// 3. Execute the request
	if method == "GET" {
		// For GET requests, data is always in the URL, regardless of enctype.
		resolvedURL.RawQuery = formData.Encode()
		b.browser.JSNavigate(resolvedURL.String())
		return
	}

	// Handle POST requests
	var (
		requestBody []byte
		contentType string
	)

	if enctype == "multipart/form-data" {
		// Serialize as multipart
		body, ct, err := b.serializeMultipartForm(formData)
		if err != nil {
			b.logger.Error("Failed to serialize multipart form data", zap.Error(err))
			return
		}
		requestBody = body
		contentType = ct
	} else {
		// Default to urlencoded
		requestBody = []byte(formData.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	// Create and execute the fetch request for POST
	req := schemas.FetchRequest{
		URL:    resolvedURL.String(),
		Method: "POST",
		Headers: []schemas.NVPair{
			{Name: "Content-Type", Value: contentType},
		},
		Body: requestBody,
	}

	// The browser environment is responsible for executing this request
	// and handling the subsequent navigation or state update.
	if _, err := b.browser.ExecuteFetch(context.Background(), req); err != nil {
		b.logger.Error("Form POST submission failed", zap.Error(err))
	}
}

// serializeMultipartForm takes form values and encodes them as multipart/form-data.
// It returns the request body, the final Content-Type header (with boundary), and any error.
func (b *DOMBridge) serializeMultipartForm(values url.Values) ([]byte, string, error) {
	var bodyBuffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&bodyBuffer)

	// Iterate over the form values and write them to the multipart buffer
	for key, vals := range values {
		for _, val := range vals {
			fieldWriter, err := multipartWriter.CreateFormField(key)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create form field '%s': %w", key, err)
			}
			if _, err := io.WriteString(fieldWriter, val); err != nil {
				return nil, "", fmt.Errorf("failed to write value for field '%s': %w", key, err)
			}
		}
	}

	// Close the writer to finalize the body and write the trailing boundary
	if err := multipartWriter.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// The Content-Type header includes the unique boundary string
	contentType := multipartWriter.FormDataContentType()
	body := bodyBuffer.Bytes()

	return body, contentType, nil
}

func (b *DOMBridge) serializeForm(formNode, submitterNode *html.Node) url.Values {
	values := make(url.Values)

	elements, _ := htmlquery.QueryAll(formNode, ".//input|.//textarea|.//select|.//button")

	for _, el := range elements {
		if _, disabled := getAttribute(el, "disabled"); disabled {
			continue
		}

		name, hasName := getAttribute(el, "name")
		if !hasName || name == "" {
			continue
		}

		tagName := strings.ToLower(el.Data)

		if tagName == "input" {
			inputType := strings.ToLower(htmlquery.SelectAttr(el, "type"))
			_, isChecked := getAttribute(el, "checked")

			switch inputType {
			case "checkbox", "radio":
				if isChecked {
					val, _ := getAttribute(el, "value")
					values.Add(name, val)
				}
			case "submit", "button", "reset", "image":
				if el == submitterNode {
					val, _ := getAttribute(el, "value")
					values.Add(name, val)
				}
			default:
				val, _ := getAttribute(el, "value")
				values.Add(name, val)
			}
		} else if tagName == "textarea" {
			values.Add(name, htmlquery.InnerText(el))
		} else if tagName == "select" {
			options, _ := htmlquery.QueryAll(el, ".//option")
			var selected bool
			for _, opt := range options {
				if _, isSelected := getAttribute(opt, "selected"); isSelected {
					val, _ := getAttribute(opt, "value")
					values.Add(name, val)
					selected = true
				}
			}
			if !selected && len(options) > 0 {
				val, _ := getAttribute(options[0], "value")
				values.Add(name, val)
			}
		} else if tagName == "button" {
			if el == submitterNode {
				val, _ := getAttribute(el, "value")
				values.Add(name, val)
			}
		}
	}
	return values
}

func getAttribute(n *html.Node, key string) (string, bool) {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}
	return "", false
}