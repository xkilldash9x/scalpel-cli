// internal/browser/jsbind/dom_bridge.go
package jsbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/cascadia"
	"github.com/antchfx/htmlquery"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"go.uber.org/zap"
	"golang.org/x/net/html"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/layout"
)

// -- Constants --

// W3C DOM Node Type constants. These are required for compatibility
// with JavaScript expectations (e.g., document.nodeType === 9).
const (
	w3cElementNode  = 1
	w3cTextNode     = 3
	w3cCommentNode  = 8
	w3cDocumentNode = 9
	w3cDoctypeNode  = 10
)

// mapGoNodeTypeToW3C converts Go's html.NodeType to the standard W3C DOM NodeType integer.
func mapGoNodeTypeToW3C(goType html.NodeType) int {
	switch goType {
	case html.ElementNode:
		return w3cElementNode
	case html.TextNode:
		return w3cTextNode
	case html.CommentNode:
		return w3cCommentNode
	case html.DocumentNode:
		return w3cDocumentNode
	case html.DoctypeNode:
		return w3cDoctypeNode
	// html.ErrorNode (0) or others.
	default:
		return 0
	}
}

// -- Interfaces and Core Structs --

// BrowserEnvironment defines the callbacks the DOMBridge needs to interact with the Session.
type BrowserEnvironment interface {
	JSNavigate(targetURL string)
	NotifyURLChange(targetURL string)
	// ExecuteFetch handles network requests (Fetch API, XHR, Forms) using canonical schemas.
	ExecuteFetch(ctx context.Context, req schemas.FetchRequest) (*schemas.FetchResponse, error)
	AddCookieFromString(cookieStr string) error
	GetCookieString() (string, error)
	// History management using canonical schemas.
	PushHistory(state *schemas.HistoryState) error
	ReplaceHistory(state *schemas.HistoryState) error
	GetHistoryLength() int
	GetCurrentHistoryState() interface{}
	ResolveURL(targetURL string) (*url.URL, error)
}

// DOMBridge manages the synchronization between the *html.Node DOM representation and the Goja runtime.
type DOMBridge struct {
	// mu protects the entire state, ensuring thread safety.
	mu sync.RWMutex

	document *html.Node
	runtime  *goja.Runtime
	logger   *zap.Logger

	eventLoop *eventloop.EventLoop
	browser   BrowserEnvironment
	// persona holds the configuration for the simulated environment (UA, viewport, etc.).
	persona schemas.Persona

	// Stores the root of the computed layout tree for hit-testing.
	layoutRoot *layout.LayoutBox

	// Caches Goja object wrappers for html.Nodes for O(1) lookups.
	nodeMap map[*html.Node]*goja.Object

	localStorage   map[string]string
	sessionStorage map[string]string

	currentLocationState map[string]string
	eventListeners       map[*html.Node]map[string]*listenerGroup
}

// nativeNode is embedded within a Goja object to link it back to the Go *html.Node.
type nativeNode struct {
	bridge *DOMBridge
	node   *html.Node
}

// listenerGroup stores event listeners separated by phase (capturing vs. bubbling).
type listenerGroup struct {
	Capturing []goja.Value
	Bubbling  []goja.Value
}

// -- Constructor and Initialization --

// NewDOMBridge creates a new DOMBridge instance, initialized with a specific Persona.
func NewDOMBridge(logger *zap.Logger, eventLoop *eventloop.EventLoop, browserEnv BrowserEnvironment, persona schemas.Persona) *DOMBridge {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &DOMBridge{
		logger:               logger.Named("dom_bridge"),
		eventLoop:            eventLoop,
		browser:              browserEnv,
		persona:              persona,
		nodeMap:              make(map[*html.Node]*goja.Object),
		localStorage:         make(map[string]string),
		sessionStorage:       make(map[string]string),
		currentLocationState: make(map[string]string),
		eventListeners:       make(map[*html.Node]map[string]*listenerGroup),
	}
}

// BindToRuntime injects the DOM APIs and environment configuration into the Goja runtime.
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

	// Initialize Web APIs.
	b.initTimers()
	b.bindStorageAPIs()
	b.bindScrollAPIs()
	b.bindHistoryAPI()
	b.bindFetchAPI()
	b.bindXHRAPI()
	b.InitializeLocation(initialURL)
	b.bindNavigatorAPI()

	// Configure viewport dimensions based on the Persona.
	_ = global.Set("innerWidth", b.persona.Width)
	_ = global.Set("innerHeight", b.persona.Height)
	_ = global.Set("outerWidth", b.persona.Width)
	_ = global.Set("outerHeight", b.persona.Height)
	_ = global.Set("devicePixelRatio", 1.0) // Defaulting DPR.

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
func (b *DOMBridge) UpdateLayoutTree(root *layout.LayoutBox) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.layoutRoot = root
}

// Lock exposes the write lock for external synchronization.
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

	// Bind Node properties and methods.
	// Fix: Incorrect nodeType Mapping (Go vs W3C). Use the mapping function.
	_ = obj.Set("nodeType", mapGoNodeTypeToW3C(node.Type))
	_ = obj.Set("nodeName", strings.ToUpper(node.Data))

	// Fix: Missing textContent Property
	// Implement textContent getter and setter.
	b.DefineProperty(obj, "textContent", func() goja.Value {
		b.mu.RLock()
		defer b.mu.RUnlock()
		// Use htmlquery.InnerText to retrieve the text of an element and its descendants.
		return b.runtime.ToValue(htmlquery.InnerText(node))
	}, func(value goja.Value) {
		// Setting textContent replaces all children with a single text node.
		b.mu.Lock()
		defer b.mu.Unlock()
		// Remove all existing children.
		for c := node.FirstChild; c != nil; {
			next := c.NextSibling
			node.RemoveChild(c)
			c = next
		}
		// Add new text node if the value is not empty.
		if value.String() != "" {
			node.AppendChild(&html.Node{Type: html.TextNode, Data: value.String()})
		}
	})

	b.defineParentAndChildProperties(obj, node)
	_ = obj.Set("appendChild", b.jsAppendChild(native))
	_ = obj.Set("removeChild", b.jsRemoveChild(native))
	_ = obj.Set("insertBefore", b.jsInsertBefore(native))

	// Bind EventTarget methods.
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
	_ = obj.Set("cloneNode", b.jsCloneNode(native))

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
		// Common attributes mapped to properties.
		b.defineAttributeProperty(obj, node, "id", "id")
		b.defineAttributeProperty(obj, node, "className", "class")
		b.defineAttributeProperty(obj, node, "href", "href")
		b.defineAttributeProperty(obj, node, "src", "src")
		b.defineAttributeProperty(obj, node, "title", "title")
		b.defineAttributeProperty(obj, node, "alt", "alt")
		// Boolean attributes.
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
	// Fix: Incorrect parentNode Implementation.
	// The original implementation used obj.Set() with a function, which is incorrect.
	// We must use DefineProperty to create a dynamic getter.
	b.DefineProperty(obj, "parentNode", func() goja.Value {
		b.mu.Lock()
		defer b.mu.Unlock()
		// node.Parent might be nil (e.g., for the Document node itself).
		if node.Parent == nil {
			return goja.Null()
		}
		// Ensure the parent node is correctly wrapped and returned.
		if parent := b.wrapNode(node.Parent); parent != nil {
			return parent
		}
		return goja.Null()
	}, nil) // parentNode is read-only.

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
		if id == "" {
			return goja.Null()
		}
		// Build a robust CSS attribute selector.
		selector := fmt.Sprintf(`[id="%s"]`, strings.ReplaceAll(id, `"`, `\"`))

		sel, err := cascadia.Compile(selector)
		if err != nil {
			b.logger.Warn("Failed to compile selector for getElementById", zap.String("selector", selector), zap.Error(err))
			return goja.Null()
		}

		b.mu.Lock()
		defer b.mu.Unlock()

		node := cascadia.Query(b.document, sel)
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

// jsQuerySelector implements querySelector, throwing a JS exception on invalid selectors.
func (b *DOMBridge) jsQuerySelector(contextNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		selector := call.Argument(0).String()

		sel, err := cascadia.Compile(selector)
		if err != nil {
			// Throw a JS SyntaxError (DOMException) if the selector is invalid.
			b.logger.Warn("Invalid CSS selector in querySelector", zap.String("selector", selector), zap.Error(err))
			// Panic allows Goja to catch it and turn it into a JS exception.
			panic(b.runtime.NewGoError(fmt.Errorf("SyntaxError: '%s' is not a valid selector", selector)))
		}

		b.mu.Lock()
		defer b.mu.Unlock()
		node := cascadia.Query(contextNative.node, sel)
		if node == nil {
			return goja.Null()
		}
		return b.wrapNode(node)
	}
}

// jsQuerySelectorAll implements querySelectorAll, throwing a JS exception on invalid selectors.
func (b *DOMBridge) jsQuerySelectorAll(contextNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		selector := call.Argument(0).String()

		sel, err := cascadia.Compile(selector)
		if err != nil {
			b.logger.Warn("Invalid CSS selector in querySelectorAll", zap.String("selector", selector), zap.Error(err))
			panic(b.runtime.NewGoError(fmt.Errorf("SyntaxError: '%s' is not a valid selector", selector)))
		}

		b.mu.Lock()
		defer b.mu.Unlock()
		nodes := cascadia.QueryAll(contextNative.node, sel)
		results := make([]goja.Value, len(nodes))
		for i, node := range nodes {
			results[i] = b.wrapNode(node)
		}
		return b.runtime.ToValue(results)
	}
}

// jsClick implements element.click(), ensuring default actions respect event cancellation.
func (b *DOMBridge) jsClick(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		// Dispatch the standard JS events. DispatchEventOnNode handles its own locking.
		b.DispatchEventOnNode(native.node, "mousedown")
		b.DispatchEventOnNode(native.node, "mouseup")

		// Dispatch 'click' and capture whether it was canceled (preventDefault).
		canceled := b.DispatchEventOnNode(native.node, "click")

		// Perform the browser's default action ONLY if the event was not canceled.
		if !canceled {
			b.mu.Lock()
			// PerformDefaultClickAction relies on the lock being held.
			b.PerformDefaultClickAction(native.node)
			b.mu.Unlock()
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

func (b *DOMBridge) jsCloneNode(native *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		deep := false
		if len(call.Arguments) > 0 {
			deep = call.Argument(0).ToBoolean()
		}

		b.mu.Lock()
		defer b.mu.Unlock()

		clonedNode := cloneHTMLNode(native.node, deep)
		return b.wrapNode(clonedNode)
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
			panic(b.runtime.NewTypeError("Argument 1 is not a Node."))
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

// jsRemoveChild implements node.removeChild(), throwing JS exceptions on failure.
func (b *DOMBridge) jsRemoveChild(parentNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		childNative := unwrapNode(call.Argument(0))
		if childNative == nil {
			panic(b.runtime.NewTypeError("Argument 1 is not a Node."))
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if childNative.node.Parent == parentNative.node {
			parentNative.node.RemoveChild(childNative.node)
		} else {
			// Throw DOMException (NotFoundError).
			panic(b.runtime.NewGoError(errors.New("NotFoundError: The node to be removed is not a child of this node.")))
		}
		return call.Argument(0)
	}
}

// jsInsertBefore implements node.insertBefore(), throwing JS exceptions on failure.
func (b *DOMBridge) jsInsertBefore(parentNative *nativeNode) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		newNative := unwrapNode(call.Argument(0))
		refNative := unwrapNode(call.Argument(1))

		if newNative == nil {
			panic(b.runtime.NewTypeError("Argument 1 is not a Node."))
		}

		b.mu.Lock()
		defer b.mu.Unlock()

		if newNative.node.Parent != nil {
			newNative.node.Parent.RemoveChild(newNative.node)
		}

		if refNative == nil {
			// If referenceNode is null, appendChild.
			parentNative.node.AppendChild(newNative.node)
		} else {
			if refNative.node.Parent == parentNative.node {
				parentNative.node.InsertBefore(newNative.node, refNative.node)
			} else {
				// Throw DOMException (NotFoundError).
				panic(b.runtime.NewGoError(errors.New("NotFoundError: The reference node is not a child of this node.")))
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

	var targetList *[]goja.Value
	if useCapture {
		targetList = &group.Capturing
	} else {
		targetList = &group.Bubbling
	}

	foundIndex := -1
	for i, existingListener := range *targetList {
		if existingListener.SameAs(listenerVal) {
			foundIndex = i
			break
		}
	}

	if foundIndex != -1 {
		*targetList = append((*targetList)[:foundIndex], (*targetList)[foundIndex+1:]...)
	}

	if len(group.Capturing) == 0 && len(group.Bubbling) == 0 {
		delete(nodeListeners, eventType)
	}
	if len(nodeListeners) == 0 {
		delete(b.eventListeners, node)
	}
}

// DispatchEventOnNode is the public entry point for dispatching events. It manages locking.
// Returns true if the event was canceled (defaultPrevented).
func (b *DOMBridge) DispatchEventOnNode(targetNode *html.Node, eventType string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dispatchEventInternal(targetNode, eventType)
}

// dispatchEventInternal implements the standard DOM event flow (Capture, Target, Bubble).
// NOTE: Assumes the DOMBridge lock is already held.
func (b *DOMBridge) dispatchEventInternal(targetNode *html.Node, eventType string) bool {
	const (
		EventPhaseNone      = 0
		EventPhaseCapturing = 1
		EventPhaseAtTarget  = 2
		EventPhaseBubbling  = 3
	)

	if b.runtime == nil || targetNode == nil {
		return false
	}

	// Determine event properties.
	bubbles := true
	cancelable := true
	switch eventType {
	case "focus", "blur", "load", "scroll", "unload", "mouseenter", "mouseleave":
		bubbles = false
	}
	if eventType == "scroll" {
		cancelable = false
	}

	// 1. Build the propagation path (ancestors, root first).
	var propagationPath []*html.Node
	for n := targetNode.Parent; n != nil; n = n.Parent {
		propagationPath = append([]*html.Node{n}, propagationPath...)
	}

	// 2. Initialize Event Object and State.
	var (
		stopPropagation        bool
		stopImmediatePropagation bool
		defaultPrevented         bool
		currentPhase             uint16
		currentTarget            *html.Node
	)

	eventObj := b.runtime.NewObject()
	_ = eventObj.Set("type", eventType)
	_ = eventObj.Set("bubbles", bubbles)
	_ = eventObj.Set("cancelable", cancelable)
	_ = eventObj.Set("timeStamp", time.Now().UnixMilli())

	// Define dynamic properties using getters.
	b.DefineProperty(eventObj, "target", func() goja.Value { return b.wrapNode(targetNode) }, nil)
	b.DefineProperty(eventObj, "eventPhase", func() goja.Value { return b.runtime.ToValue(currentPhase) }, nil)
	b.DefineProperty(eventObj, "defaultPrevented", func() goja.Value { return b.runtime.ToValue(defaultPrevented) }, nil)
	b.DefineProperty(eventObj, "currentTarget", func() goja.Value {
		if currentTarget != nil {
			return b.wrapNode(currentTarget)
		}
		return goja.Null()
	}, nil)

	// Define methods.
	_ = eventObj.Set("stopPropagation", func() { stopPropagation = true })
	_ = eventObj.Set("stopImmediatePropagation", func() {
		stopPropagation = true
		stopImmediatePropagation = true
	})
	_ = eventObj.Set("preventDefault", func() {
		if cancelable {
			defaultPrevented = true
		}
	})

	// Helper function to invoke listeners.
	invokeListeners := func(node *html.Node, phase uint16) {
		currentTarget = node

		group, exists := b.eventListeners[node][eventType]
		if !exists {
			return
		}
		var listeners []goja.Value
		// Copy listeners slice to allow modification during iteration.
		if phase == EventPhaseCapturing {
			listeners = append([]goja.Value(nil), group.Capturing...)
		} else {
			listeners = append([]goja.Value(nil), group.Bubbling...)
		}

		thisObj := b.wrapNode(node) // 'this' context is the currentTarget.

		for _, listener := range listeners {
			if fn, ok := goja.AssertFunction(listener); ok {
				if _, err := fn(thisObj, eventObj); err != nil {
					b.logger.Error("Error executing event listener", zap.String("eventType", eventType), zap.Error(err))
				}
			}
			if stopImmediatePropagation {
				return
			}
		}
	}

	// 3. Event Flow.

	// Capturing Phase
	currentPhase = EventPhaseCapturing
	for _, node := range propagationPath {
		invokeListeners(node, EventPhaseCapturing)
		if stopPropagation {
			goto DispatchEnd
		}
	}

	// Target Phase
	currentPhase = EventPhaseAtTarget
	invokeListeners(targetNode, EventPhaseCapturing)
	if stopPropagation {
		goto DispatchEnd
	}
	invokeListeners(targetNode, EventPhaseBubbling)
	if stopPropagation {
		goto DispatchEnd
	}

	// Bubbling Phase
	if bubbles {
		currentPhase = EventPhaseBubbling
		for i := len(propagationPath) - 1; i >= 0; i-- {
			invokeListeners(propagationPath[i], EventPhaseBubbling)
			if stopPropagation {
				goto DispatchEnd
			}
		}
	}

DispatchEnd:
	// Reset state after dispatch.
	currentPhase = EventPhaseNone
	currentTarget = nil
	return defaultPrevented
}

// PerformDefaultClickAction handles default browser behavior for clicks.
// NOTE: Assumes a write lock is held.
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
			b.dispatchEventInternal(node, "change")
		case "radio":
			name := htmlquery.SelectAttr(node, "name")
			if name == "" {
				setAttr(node, "checked", "")
				b.dispatchEventInternal(node, "change")
				return
			}
			xpath := fmt.Sprintf("//input[@type='radio'][@name=%s]", xpathStringLiteral(name))
			radioGroup, _ := htmlquery.QueryAll(b.document, xpath)
			for _, radioNode := range radioGroup {
				if radioNode != node {
					removeAttr(radioNode, "checked")
				}
			}
			setAttr(node, "checked", "")
			b.dispatchEventInternal(node, "change")
		case "submit":
			if formNode := findParentForm(node); formNode != nil {
				b.submitFormInternal(formNode, node)
			}
		}

	case "button":
		buttonType := strings.ToLower(htmlquery.SelectAttr(node, "type"))
		if buttonType == "submit" || buttonType == "" {
			if formNode := findParentForm(node); formNode != nil {
				b.submitFormInternal(formNode, node)
			}
		}
	}
}

// -- Window APIs (Timers, Storage, Location, Network, etc.) --

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

// bindNavigatorAPI sets up window.navigator using the Persona data.
func (b *DOMBridge) bindNavigatorAPI() {
	if b.runtime == nil {
		return
	}
	navigator := b.runtime.NewObject()
	global := b.runtime.GlobalObject()

	// Core properties derived from the Persona.
	_ = navigator.Set("userAgent", b.persona.UserAgent)
	_ = navigator.Set("appVersion", strings.TrimPrefix(b.persona.UserAgent, "Mozilla/"))
	_ = navigator.Set("platform", b.persona.Platform)
	_ = navigator.Set("language", b.persona.Locale)
	_ = navigator.Set("languages", b.persona.Languages)

	// Standard properties.
	_ = navigator.Set("webdriver", false)
	_ = navigator.Set("cookieEnabled", true)

	_ = global.Set("navigator", navigator)
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

// -- Network APIs (Fetch and XHR) --

// bindFetchAPI injects the window.fetch function (Promise-based).
func (b *DOMBridge) bindFetchAPI() {
	if b.browser == nil {
		return
	}

	fetchFunc := func(call goja.FunctionCall) goja.Value {
		resource := call.Argument(0).String()
		optionsVal := call.Argument(1)

		method := "GET"
		headers := make(map[string]string)
		var body []byte
		credentials := "same-origin"

		if !goja.IsUndefined(optionsVal) && !goja.IsNull(optionsVal) {
			options := optionsVal.ToObject(b.runtime)
			if m := options.Get("method"); m != nil && !goja.IsUndefined(m) {
				method = strings.ToUpper(m.String())
			}
			if c := options.Get("credentials"); c != nil && !goja.IsUndefined(c) {
				credentials = c.String()
			}
			if h := options.Get("headers"); h != nil && !goja.IsUndefined(h) {
				headersObj := h.ToObject(b.runtime)
				for _, key := range headersObj.Keys() {
					val := headersObj.Get(key)
					headers[key] = val.String()
				}
			}
			if b := options.Get("body"); b != nil && !goja.IsUndefined(b) {
				body = []byte(b.String())
			}
		}

		resolvedURL, err := b.browser.ResolveURL(resource)
		if err != nil {
			promise, _, reject := b.runtime.NewPromise()
			reject(b.runtime.NewTypeError("Failed to resolve URL: %s", err.Error()))
			return b.runtime.ToValue(promise)
		}

		headerPairs := make([]schemas.NVPair, 0, len(headers))
		for k, v := range headers {
			headerPairs = append(headerPairs, schemas.NVPair{Name: k, Value: v})
		}

		req := schemas.FetchRequest{
			URL:         resolvedURL.String(),
			Method:      method,
			Headers:     headerPairs,
			Body:        body,
			Credentials: credentials,
		}

		promise, resolve, reject := b.runtime.NewPromise()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			resp, err := b.browser.ExecuteFetch(ctx, req)

			b.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
				if err != nil {
					reject(vm.NewTypeError("Network request failed: %s", err.Error()))
					return
				}
				responseObj := b.createJSResponseObject(vm, resp)
				resolve(responseObj)
			})
		}()

		return b.runtime.ToValue(promise)
	}

	b.runtime.GlobalObject().Set("fetch", fetchFunc)
}

// createJSResponseObject maps schemas.FetchResponse to a JS Response object.
func (b *DOMBridge) createJSResponseObject(vm *goja.Runtime, resp *schemas.FetchResponse) *goja.Object {
	obj := vm.NewObject()
	_ = obj.Set("ok", resp.Status >= 200 && resp.Status <= 299)
	_ = obj.Set("status", resp.Status)
	_ = obj.Set("statusText", resp.StatusText)
	_ = obj.Set("url", resp.URL)

	headersObj := vm.NewObject()
	for _, h := range resp.Headers {
		_ = headersObj.Set(strings.ToLower(h.Name), h.Value)
	}
	_ = obj.Set("headers", headersObj)

	_ = obj.Set("text", func() goja.Value {
		promise, resolve, _ := vm.NewPromise()
		resolve(vm.ToValue(string(resp.Body)))
		return vm.ToValue(promise)
	})

	_ = obj.Set("json", func() goja.Value {
		promise, resolve, reject := vm.NewPromise()
		var data interface{}
		if err := json.Unmarshal(resp.Body, &data); err != nil {
			reject(fmt.Errorf("SyntaxError: Failed to parse JSON response: %w", err))
		} else {
			resolve(vm.ToValue(data))
		}
		return vm.ToValue(promise)
	})

	_ = obj.Set("arrayBuffer", func() goja.Value {
		promise, resolve, _ := vm.NewPromise()
		resolve(vm.ToValue(vm.NewArrayBuffer(resp.Body)))
		return vm.ToValue(promise)
	})

	return obj
}

// bindXHRAPI injects the window.XMLHttpRequest constructor.
func (b *DOMBridge) bindXHRAPI() {
	if b.browser == nil {
		return
	}
	// XHR constructor function.
	xhrConstructor := func(call goja.ConstructorCall) *goja.Object {
		xhr := &xmlHttpRequest{
			bridge:       b,
			readyState:   0, // UNSENT
			headers:      make(map[string]string),
			jsObject:     call.This,
			responseBody: []byte{},
		}
		// Bind methods and properties to the new JS object ('this').
		xhr.bind()
		return nil
	}
	_ = b.runtime.GlobalObject().Set("XMLHttpRequest", xhrConstructor)
}

// xmlHttpRequest holds the state for a single XHR instance.
type xmlHttpRequest struct {
	bridge *DOMBridge
	mu     sync.Mutex // Protects the state of this specific XHR instance

	// JS-visible state
	readyState   int
	status       int
	statusText   string
	responseBody []byte
	headers      map[string]string
	method       string
	url          string
	async        bool

	jsObject *goja.Object // Reference to the JS 'this' object
}

// bind attaches methods and properties to the XHR JS object.
func (xhr *xmlHttpRequest) bind() {
	// Methods
	_ = xhr.jsObject.Set("open", xhr.open)
	_ = xhr.jsObject.Set("send", xhr.send)
	_ = xhr.jsObject.Set("setRequestHeader", xhr.setRequestHeader)

	// Properties
	b := xhr.bridge
	b.DefineProperty(xhr.jsObject, "readyState", func() goja.Value {
		xhr.mu.Lock()
		defer xhr.mu.Unlock()
		return b.runtime.ToValue(xhr.readyState)
	}, nil)
	b.DefineProperty(xhr.jsObject, "status", func() goja.Value {
		xhr.mu.Lock()
		defer xhr.mu.Unlock()
		return b.runtime.ToValue(xhr.status)
	}, nil)
	b.DefineProperty(xhr.jsObject, "statusText", func() goja.Value {
		xhr.mu.Lock()
		defer xhr.mu.Unlock()
		return b.runtime.ToValue(xhr.statusText)
	}, nil)
	b.DefineProperty(xhr.jsObject, "responseText", func() goja.Value {
		xhr.mu.Lock()
		defer xhr.mu.Unlock()
		return b.runtime.ToValue(string(xhr.responseBody))
	}, nil)
	b.DefineProperty(xhr.jsObject, "response", func() goja.Value {
		xhr.mu.Lock()
		defer xhr.mu.Unlock()
		return b.runtime.ToValue(string(xhr.responseBody))
	}, nil)
}

func (xhr *xmlHttpRequest) setReadyState(state int) {
	xhr.mu.Lock()
	if xhr.readyState == state {
		xhr.mu.Unlock()
		return
	}
	xhr.readyState = state
	xhr.mu.Unlock()

	// Schedule the onreadystatechange callback to run on the event loop.
	xhr.bridge.eventLoop.RunOnLoop(func(vm *goja.Runtime) {
		onReadyStateChange := xhr.jsObject.Get("onreadystatechange")
		if fn, ok := goja.AssertFunction(onReadyStateChange); ok {
			if _, err := fn(xhr.jsObject); err != nil {
				xhr.bridge.logger.Error("Error in onreadystatechange", zap.Error(err))
			}
		}
	})
}

func (xhr *xmlHttpRequest) open(method, url string, async goja.Value) {
	xhr.mu.Lock()
	defer xhr.mu.Unlock()
	xhr.method = strings.ToUpper(method)
	xhr.url = url
	xhr.async = true
	if async != nil && !goja.IsUndefined(async) {
		xhr.async = async.ToBoolean()
	}
	xhr.setReadyState(1) // OPENED
}

func (xhr *xmlHttpRequest) setRequestHeader(key, value string) {
	xhr.mu.Lock()
	defer xhr.mu.Unlock()
	xhr.headers[key] = value
}

func (xhr *xmlHttpRequest) send(body goja.Value) {
	xhr.mu.Lock()
	method := xhr.method
	rawURL := xhr.url
	headers := xhr.headers
	xhr.mu.Unlock()

	b := xhr.bridge
	resolvedURL, err := b.browser.ResolveURL(rawURL)
	if err != nil {
		b.logger.Error("XHR failed to resolve URL", zap.Error(err))
		xhr.setReadyState(4) // DONE (with error)
		return
	}

	headerPairs := make([]schemas.NVPair, 0, len(headers))
	for k, v := range headers {
		headerPairs = append(headerPairs, schemas.NVPair{Name: k, Value: v})
	}

	var bodyBytes []byte
	if body != nil && !goja.IsNull(body) && !goja.IsUndefined(body) {
		bodyBytes = []byte(body.String())
	}

	req := schemas.FetchRequest{
		URL:     resolvedURL.String(),
		Method:  method,
		Headers: headerPairs,
		Body:    bodyBytes,
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		resp, err := b.browser.ExecuteFetch(ctx, req)
		if err != nil {
			xhr.bridge.logger.Error("XHR execution failed", zap.Error(err))
			xhr.setReadyState(4) // DONE
			return
		}

		xhr.mu.Lock()
		xhr.status = resp.Status
		xhr.statusText = resp.StatusText
		xhr.responseBody = resp.Body
		xhr.mu.Unlock()

		xhr.setReadyState(2) // HEADERS_RECEIVED
		xhr.setReadyState(3) // LOADING
		xhr.setReadyState(4) // DONE
	}()
}

// -- Form Submission Logic --

// submitFormInternal orchestrates the form submission process.
// NOTE: This internal version is called when the DOMBridge lock is already held.
func (b *DOMBridge) submitFormInternal(formNode, submitterNode *html.Node) {
	if b.browser == nil {
		return
	}

	// 1. Dispatch the 'submit' event.
	canceled := b.dispatchEventInternal(formNode, "submit")
	if canceled {
		b.logger.Debug("Form submission canceled by 'submit' event listener")
		return
	}

	// 2. Determine method, action, and encoding type
	method := strings.ToUpper(htmlquery.SelectAttr(formNode, "method"))
	if method != "POST" {
		method = "GET"
	}
	action := htmlquery.SelectAttr(formNode, "action")
	resolvedURL, err := b.browser.ResolveURL(action)
	if err != nil {
		b.logger.Warn("Could not resolve form action URL", zap.String("action", action), zap.Error(err))
		return
	}
	enctype := strings.ToLower(htmlquery.SelectAttr(formNode, "enctype"))
	if enctype == "" {
		enctype = "application/x-www-form-urlencoded"
	}

	// 3. Serialize form data
	formData := b.serializeForm(formNode, submitterNode)

	// 4. Execute the request
	if method == "GET" {
		resolvedURL.RawQuery = formData.Encode()
		b.browser.JSNavigate(resolvedURL.String())
		return
	}

	var (
		requestBody []byte
		contentType string
	)
	if enctype == "multipart/form-data" {
		body, ct, err := b.serializeMultipartForm(formData)
		if err != nil {
			b.logger.Error("Failed to serialize multipart form data", zap.Error(err))
			return
		}
		requestBody = body
		contentType = ct
	} else {
		requestBody = []byte(formData.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	req := schemas.FetchRequest{
		URL:    resolvedURL.String(),
		Method: "POST",
		Headers: []schemas.NVPair{
			{Name: "Content-Type", Value: contentType},
		},
		Body:        requestBody,
		Credentials: "same-origin", // Form submissions typically include credentials.
	}

	// Execute the request asynchronously to avoid blocking the JS thread.
	go func() {
		if _, err := b.browser.ExecuteFetch(context.Background(), req); err != nil {
			b.logger.Error("Form POST submission failed during execution", zap.Error(err))
		}
	}()
}

// serializeMultipartForm encodes form values as multipart/form-data.
func (b *DOMBridge) serializeMultipartForm(values url.Values) ([]byte, string, error) {
	var bodyBuffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&bodyBuffer)

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

	if err := multipartWriter.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

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
					val, hasValue := getAttribute(el, "value")
					// Fix: Broken Form Submission (Data serialization)
					// HTML5 spec: If a checked checkbox/radio has no value attribute, it defaults to "on".
					if !hasValue {
						val = "on"
					}
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
			// Default selection (first option if none selected)
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

// -- Go-side Utilities --

// FindNodeAtPoint performs a hit-test on the layout tree.
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

func (b *DOMBridge) hitTestRecursive(box *layout.LayoutBox, x, y float64) *layout.LayoutBox {
	if box == nil {
		return nil
	}

	for i := len(box.Children) - 1; i >= 0; i-- {
		child := box.Children[i]
		if found := b.hitTestRecursive(child, x, y); found != nil {
			return found
		}
	}

	invTransform, err := box.Dimensions.Transform.Inverse()
	if err != nil {
		return nil
	}
	transformedX, transformedY := invTransform.Apply(x, y)

	if box.StyledNode != nil && !box.StyledNode.IsVisible() {
		return nil
	}
	if box.BoxType == layout.AnonymousBlockBox {
		return nil
	}
	if box.StyledNode != nil && box.StyledNode.Lookup("pointer-events", "auto") == "none" {
		return nil
	}

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

func xpathStringLiteral(s string) string {
	if !strings.Contains(s, "'") {
		return fmt.Sprintf("'%s'", s)
	}
	if !strings.Contains(s, "\"") {
		return fmt.Sprintf("\"%s\"", s)
	}
	var result strings.Builder
	result.WriteString("concat(")
	parts := strings.Split(s, "'")
	for i, part := range parts {
		if i > 0 {
			result.WriteString(", \"'\", ")
		}
		result.WriteString(fmt.Sprintf("'%s'", part))
	}
	result.WriteString(")")
	return result.String()
}

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
		_, exists := getAttribute(node, attrName)
		return b.runtime.ToValue(exists)
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

func getAttribute(n *html.Node, key string) (string, bool) {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}
	return "", false
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
	for curr := node; curr != nil; curr = curr.Parent {
		if curr.Type == html.ElementNode && strings.ToLower(curr.Data) == "form" {
			return curr
		}
	}
	return nil
}

func cloneHTMLNode(n *html.Node, deep bool) *html.Node {
	if n == nil {
		return nil
	}
	newNode := &html.Node{
		Type:      n.Type,
		DataAtom:  n.DataAtom,
		Data:      n.Data,
		Namespace: n.Namespace,
	}
	if len(n.Attr) > 0 {
		newNode.Attr = make([]html.Attribute, len(n.Attr))
		copy(newNode.Attr, n.Attr)
	}
	if deep {
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			newNode.AppendChild(cloneHTMLNode(child, deep))
		}
	}
	return newNode
}