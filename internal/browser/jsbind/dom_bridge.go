// internal/browser/jsbind/dom_bridge.go
package jsbind

import (
	"fmt"
	"strings"
	"sync"

	"github.com/dop251/goja"
	"github.com/antchfx/htmlquery"
	"golang.org/x/net/html"
	"go.uber.org/zap"
)

// DOMBridge manages the connection between the Goja runtime and the Go DOM representation.
type DOMBridge struct {
	vm     *goja.Runtime
	logger *zap.Logger

	// Reference to the current DOM root.
	// Access must be protected by the mutex.
	mu   sync.RWMutex
	root *html.Node

	window   *Window
	document *Document
}

// NewDOMBridge initializes the bridge and sets up the Goja runtime.
func NewDOMBridge(vm *goja.Runtime, logger *zap.Logger) *DOMBridge {
	if logger == nil {
		logger = zap.NewNop()
	}

	bridge := &DOMBridge{
		vm:     vm,
		logger: logger.Named("dom_bridge"),
	}

	// Initialize the core objects.
	bridge.document = newDocument(bridge)
	bridge.window = newWindow(bridge)

	// Expose the core objects to the Goja runtime.
	bridge.initializeRuntime()

	return bridge
}

// initializeRuntime sets the global variables (window, document) in the JS context.
func (b *DOMBridge) initializeRuntime() {
	// Expose the 'window' object as the global object itself and also as 'window' and 'self'.
	global := b.vm.GlobalObject()
	if err := global.Set("window", b.window.Object); err != nil {
		b.logger.Error("Failed to set 'window' global", zap.Error(err))
	}
    if err := global.Set("self", b.window.Object); err != nil {
		b.logger.Error("Failed to set 'self' global", zap.Error(err))
	}

	// Expose the 'document' object.
	if err := global.Set("document", b.document.Object); err != nil {
		b.logger.Error("Failed to set 'document' global", zap.Error(err))
	}

	// Implement basic console logging and timers.
	b.initConsole()
    b.initTimers()
}

// UpdateDOM sets the current DOM root used by the bridge.
func (b *DOMBridge) UpdateDOM(root *html.Node) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.root = root
	b.document.updateRoot(root)
}

// --- Window Object (Global Scope) ---

// Window represents the browser window object.
type Window struct {
	bridge *DOMBridge
	Object *goja.Object
}

func newWindow(bridge *DOMBridge) *Window {
	w := &Window{
		bridge: bridge,
	}
	w.Object = bridge.vm.NewObject()

	// Define basic properties and methods.
    // (FUTURE IMPROVEMENT: Implement full Location object).
	w.Object.Set("location", "about:blank")
	w.Object.Set("alert", w.Alert)
	w.Object.Set("confirm", w.Confirm)

	return w
}

func (w *Window) Alert(call goja.FunctionCall) goja.Value {
	message := call.Argument(0).String()
	w.bridge.logger.Info("[JS Alert]", zap.String("message", message))
	return goja.Undefined()
}

func (w *Window) Confirm(call goja.FunctionCall) goja.Value {
	message := call.Argument(0).String()
	w.bridge.logger.Info("[JS Confirm]", zap.String("message", message))
	return w.bridge.vm.ToValue(true) // Always confirm
}

// --- Document Object ---

// Document represents the HTML document object.
type Document struct {
	bridge *DOMBridge
	Object *goja.Object
	root   *html.Node
}

func newDocument(bridge *DOMBridge) *Document {
	d := &Document{
		bridge: bridge,
	}
	d.Object = bridge.vm.NewObject()

	// Define methods of the document object.
	d.Object.Set("querySelector", d.QuerySelector)
	d.Object.Set("querySelectorAll", d.QuerySelectorAll)
	d.Object.Set("getElementById", d.GetElementById)
    d.Object.Set("getElementsByTagName", d.GetElementsByTagName)
    d.Object.Set("getElementsByClassName", d.GetElementsByClassName)
    d.Object.Set("createElement", d.CreateElement)
    d.Object.Set("createTextNode", d.CreateTextNode)

	return d
}

func (d *Document) updateRoot(root *html.Node) {
	// Called under the bridge's write lock from UpdateDOM.
	d.root = root

    // Update document properties like body and head.
    if root != nil {
        bodyNode := htmlquery.FindOne(root, "//body")
        if bodyNode != nil {
            d.Object.Set("body", d.bridge.WrapNode(bodyNode))
        } else {
            d.Object.Set("body", goja.Null())
        }
        headNode := htmlquery.FindOne(root, "//head")
        if headNode != nil {
            d.Object.Set("head", d.bridge.WrapNode(headNode))
        } else {
            d.Object.Set("head", goja.Null())
        }
    } else {
        d.Object.Set("body", goja.Null())
        d.Object.Set("head", goja.Null())
    }
}

// QuerySelector finds the first element matching the CSS selector (translated to XPath).
func (d *Document) QuerySelector(call goja.FunctionCall) goja.Value {
	selector := call.Argument(0).String()

	// CRITICAL: Lock the DOM for reading during the query.
	d.bridge.mu.RLock()
	defer d.bridge.mu.RUnlock()

	if d.root == nil {
		return goja.Null()
	}

	xpath := translateCSSToXPath(selector)

	node, err := htmlquery.Query(d.root, xpath)
	if err != nil {
		// Throw a DOMException (SyntaxError) for invalid selectors.
		panic(d.bridge.vm.NewGoError(fmt.Errorf("invalid selector: %s", selector)))
	}

	if node == nil {
		return goja.Null()
	}

	return d.bridge.WrapNode(node)
}

// QuerySelectorAll finds all elements matching the CSS selector.
func (d *Document) QuerySelectorAll(call goja.FunctionCall) goja.Value {
	selector := call.Argument(0).String()

	d.bridge.mu.RLock()
	defer d.bridge.mu.RUnlock()

	if d.root == nil {
		return d.bridge.vm.NewArray()
	}

	xpath := translateCSSToXPath(selector)
	nodes, err := htmlquery.QueryAll(d.root, xpath)
	if err != nil {
		panic(d.bridge.vm.NewGoError(fmt.Errorf("invalid selector: %s", selector)))
	}

    return d.bridge.WrapNodeList(nodes)
}

// GetElementById finds an element by its ID.
func (d *Document) GetElementById(call goja.FunctionCall) goja.Value {
    id := call.Argument(0).String()
    // Basic protection against complex IDs that might break the simple XPath.
    if strings.Contains(id, "'") {
         return goja.Null()
    }
    xpath := fmt.Sprintf("//*[@id='%s']", id)

    d.bridge.mu.RLock()
    defer d.bridge.mu.RUnlock()

    if d.root == nil {
        return goja.Null()
    }

    node, err := htmlquery.Query(d.root, xpath)
    if err != nil || node == nil {
        return goja.Null()
    }

    return d.bridge.WrapNode(node)
}

func (d *Document) GetElementsByTagName(call goja.FunctionCall) goja.Value {
    tagName := strings.ToLower(call.Argument(0).String())
    xpath := fmt.Sprintf("//%s", tagName)

    d.bridge.mu.RLock()
    defer d.bridge.mu.RUnlock()

    if d.root == nil {
        return d.bridge.vm.NewArray()
    }

    nodes, _ := htmlquery.QueryAll(d.root, xpath)
    return d.bridge.WrapNodeList(nodes)
}

func (d *Document) GetElementsByClassName(call goja.FunctionCall) goja.Value {
    className := call.Argument(0).String()
    // XPath way to check for a class in a space-separated list.
    xpath := fmt.Sprintf("//*[contains(concat(' ', normalize-space(@class), ' '), ' %s ')]", className)

    d.bridge.mu.RLock()
    defer d.bridge.mu.RUnlock()

     if d.root == nil {
        return d.bridge.vm.NewArray()
    }

    nodes, _ := htmlquery.QueryAll(d.root, xpath)
    return d.bridge.WrapNodeList(nodes)
}


// CreateElement creates a new detached DOM node.
func (d *Document) CreateElement(call goja.FunctionCall) goja.Value {
    tagName := call.Argument(0).String()

    // Create the new node in Go. No lock needed as it's detached.
    newNode := &html.Node{
        Type: html.ElementNode,
        Data: strings.ToLower(tagName),
    }

    return d.bridge.WrapNode(newNode)
}

// CreateTextNode creates a new detached text node.
func (d *Document) CreateTextNode(call goja.FunctionCall) goja.Value {
    data := call.Argument(0).String()

    newNode := &html.Node{
        Type: html.TextNode,
        Data: data,
    }

    return d.bridge.WrapNode(newNode)
}


// --- Element Object (and Node interface) ---

// Element represents a DOM element wrapper.
type Element struct {
	bridge *DOMBridge
	Node   *html.Node
	Object *goja.Object
}

// WrapNodeList converts a slice of *html.Node into a JS Array (NodeList equivalent).
func (b *DOMBridge) WrapNodeList(nodes []*html.Node) goja.Value {
    wrappedNodes := make([]goja.Value, len(nodes))
	for i, node := range nodes {
		wrappedNodes[i] = b.WrapNode(node)
	}
	return b.vm.NewArray(wrappedNodes...)
}

// WrapNode converts an *html.Node into a JS Element object.
func (b *DOMBridge) WrapNode(node *html.Node) goja.Value {
	if node == nil {
		return goja.Null()
	}

    // (FUTURE IMPROVEMENT: Implement an Identity Map (e.g., map[*html.Node]*goja.Object) for consistency).

	e := &Element{
		bridge: b,
		Node:   node,
	}
    // Create the JS object representation.
	e.Object = b.vm.NewObject()

    // Store a reference back to the Go struct internally for unwrapping.
    // Use a non-enumerable property name.
    e.Object.DefineDataProperty("__go_node_wrapper__", b.vm.ToValue(e), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_TRUE)


	// Define core Node properties and methods.
    e.Object.Set("nodeType", e.NodeType())
    e.Object.Set("nodeName", e.NodeName())

    // Use getters for dynamic relationship properties.
	e.defineGetter("parentNode", e.ParentNode)
	e.defineGetter("childNodes", e.ChildNodes)
    e.defineGetter("firstChild", e.FirstChild)
    e.defineGetter("lastChild", e.LastChild)
    e.defineGetter("nextSibling", e.NextSibling)
    e.defineGetter("previousSibling", e.PreviousSibling)

    e.Object.Set("appendChild", e.AppendChild)
    e.Object.Set("removeChild", e.RemoveChild)
    e.Object.Set("insertBefore", e.InsertBefore)
    e.Object.Set("cloneNode", e.CloneNode)

    // Define type-specific properties and methods.
    if node.Type == html.ElementNode {
	    e.Object.Set("tagName", strings.ToUpper(node.Data))
	    e.defineGetter("id", e.GetId)
	    e.defineSetter("id", e.SetId)
        e.defineGetter("className", e.GetClassName)
        e.defineSetter("className", e.SetClassName)

	    // Getters/setters for content manipulation.
	    e.defineGetter("innerHTML", e.InnerHTML)
	    e.defineSetter("innerHTML", e.SetInnerHTML)
	    e.defineGetter("outerHTML", e.OuterHTML)
        e.defineGetter("textContent", e.TextContent)
        e.defineSetter("textContent", e.SetTextContent)

        // Attribute methods
        e.Object.Set("getAttribute", e.GetAttribute)
        e.Object.Set("setAttribute", e.SetAttribute)
        e.Object.Set("removeAttribute", e.RemoveAttribute)

        // Query methods (scoped)
        e.Object.Set("querySelector", e.QuerySelector)
        e.Object.Set("querySelectorAll", e.QuerySelectorAll)
        e.Object.Set("getElementsByTagName", e.GetElementsByTagName)
        e.Object.Set("getElementsByClassName", e.GetElementsByClassName)


        // Basic EventTarget implementation (Dummy for compatibility)
        e.Object.Set("addEventListener", e.AddEventListener)
        e.Object.Set("removeEventListener", e.RemoveEventListener)
        e.Object.Set("dispatchEvent", e.DispatchEvent)

    } else if node.Type == html.TextNode || node.Type == html.CommentNode {
        // Properties for text/comment nodes.
        e.defineGetter("textContent", e.NodeValue)
        e.defineSetter("textContent", e.SetNodeValue)
        e.defineGetter("nodeValue", e.NodeValue)
        e.defineSetter("nodeValue", e.SetNodeValue)
        e.defineGetter("data", e.NodeValue)
        e.defineSetter("data", e.SetNodeValue)
    }

	return e.Object
}

// Helper to define a getter property.
func (e *Element) defineGetter(name string, getter func() goja.Value) {
    getterFunc := e.bridge.vm.ToValue(func(call goja.FunctionCall) goja.Value {
        return getter()
    })
    // Configurable: false, Enumerable: true
	err := e.Object.DefineAccessorProperty(name, getterFunc, goja.Undefined(), goja.FLAG_FALSE, goja.FLAG_TRUE)
	if err != nil {
		e.bridge.logger.Error("Failed to define getter", zap.String("property", name), zap.Error(err))
	}
}

// Helper to define a setter property.
func (e *Element) defineSetter(name string, setter func(goja.Value)) {
    setterFunc := e.bridge.vm.ToValue(func(call goja.FunctionCall) goja.Value {
        setter(call.Argument(0))
        return goja.Undefined()
    })
	err := e.Object.DefineAccessorProperty(name, goja.Undefined(), setterFunc, goja.FLAG_FALSE, goja.FLAG_TRUE)
	if err != nil {
		e.bridge.logger.Error("Failed to define setter", zap.String("property", name), zap.Error(err))
	}
}

// --- Node Properties Implementation ---

func (e *Element) NodeType() int {
    // Standard DOM node types.
    switch e.Node.Type {
    case html.ElementNode:
        return 1 // ELEMENT_NODE
    case html.TextNode:
        return 3 // TEXT_NODE
    case html.CommentNode:
        return 8 // COMMENT_NODE
    case html.DocumentNode:
        return 9 // DOCUMENT_NODE
    default:
        return 0
    }
}

func (e *Element) NodeName() string {
    if e.Node.Type == html.ElementNode {
        return strings.ToUpper(e.Node.Data)
    }
    if e.Node.Type == html.TextNode {
        return "#text"
    }
    if e.Node.Type == html.CommentNode {
        return "#comment"
    }
    return ""
}

func (e *Element) ParentNode() goja.Value {
	e.bridge.mu.RLock()
	defer e.bridge.mu.RUnlock()

	if e.Node.Parent != nil {
		return e.bridge.WrapNode(e.Node.Parent)
	}
	return goja.Null()
}

func (e *Element) ChildNodes() goja.Value {
	e.bridge.mu.RLock()
	defer e.bridge.mu.RUnlock()

	var children []*html.Node
	for c := e.Node.FirstChild; c != nil; c = c.NextSibling {
        children = append(children, c)
	}
	return e.bridge.WrapNodeList(children)
}

func (e *Element) FirstChild() goja.Value {
    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()
    return e.bridge.WrapNode(e.Node.FirstChild)
}

func (e *Element) LastChild() goja.Value {
    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()
    return e.bridge.WrapNode(e.Node.LastChild)
}

func (e *Element) NextSibling() goja.Value {
    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()
    return e.bridge.WrapNode(e.Node.NextSibling)
}

func (e *Element) PreviousSibling() goja.Value {
    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()
    return e.bridge.WrapNode(e.Node.PrevSibling)
}

func (e *Element) NodeValue() goja.Value {
    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()
    if e.Node.Type == html.TextNode || e.Node.Type == html.CommentNode {
        return e.bridge.vm.ToValue(e.Node.Data)
    }
    return goja.Null()
}

func (e *Element) SetNodeValue(val goja.Value) {
    e.bridge.mu.Lock()
    defer e.bridge.mu.Unlock()
    if e.Node.Type == html.TextNode || e.Node.Type == html.CommentNode {
        e.Node.Data = val.String()
    }
}


// --- Element Properties Implementation ---

func (e *Element) GetId() goja.Value {
    return e.GetAttributeValue("id")
}

func (e *Element) SetId(val goja.Value) {
    e.SetAttributeValue("id", val.String())
}

func (e *Element) GetClassName() goja.Value {
    return e.GetAttributeValue("class")
}

func (e *Element) SetClassName(val goja.Value) {
    e.SetAttributeValue("class", val.String())
}


// InnerHTML returns the serialized HTML of the element's children.
func (e *Element) InnerHTML() goja.Value {
	e.bridge.mu.RLock()
	defer e.bridge.mu.RUnlock()

    return e.bridge.vm.ToValue(renderInnerHTML(e.Node))
}

func renderInnerHTML(node *html.Node) string {
    var sb strings.Builder
	for c := node.FirstChild; c != nil; c = c.NextSibling {
		// Use the rendering function from golang.org/x/net/html
		if err := html.Render(&sb, c); err != nil {
            // Errors during rendering are difficult to handle here.
		}
	}
    return sb.String()
}

// SetInnerHTML parses the provided HTML string and replaces the element's children.
func (e *Element) SetInnerHTML(val goja.Value) {
	htmlContent := val.String()

	// Parse the HTML fragment. The context node (e.Node) is required for correct parsing rules.
	newNodes, err := html.ParseFragment(strings.NewReader(htmlContent), e.Node)
	if err != nil {
		// Throw a DOMException (SyntaxError).
		panic(e.bridge.vm.NewGoError(fmt.Errorf("failed to parse HTML: %w", err)))
	}

	// CRITICAL: Lock the DOM for writing.
	e.bridge.mu.Lock()
	defer e.bridge.mu.Unlock()

	// 1. Remove all existing children.
	for c := e.Node.FirstChild; c != nil; {
		next := c.NextSibling
		e.Node.RemoveChild(c)
		c = next
	}

	// 2. Append the new nodes.
	for _, newNode := range newNodes {
		e.Node.AppendChild(newNode)
	}
}

// OuterHTML returns the serialized HTML of the element itself and its children.
func (e *Element) OuterHTML() goja.Value {
	e.bridge.mu.RLock()
	defer e.bridge.mu.RUnlock()

	var sb strings.Builder
	if err := html.Render(&sb, e.Node); err != nil {
		return e.bridge.vm.ToValue("")
	}
	return e.bridge.vm.ToValue(sb.String())
}

// TextContent returns the concatenated text content of the element and its descendants.
func (e *Element) TextContent() goja.Value {
    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()

    // Use htmlquery's InnerText helper.
    text := htmlquery.InnerText(e.Node)
    return e.bridge.vm.ToValue(text)
}

// SetTextContent replaces the children of the element with a single text node.
func (e *Element) SetTextContent(val goja.Value) {
    text := val.String()

    e.bridge.mu.Lock()
    defer e.bridge.mu.Unlock()

    // 1. Remove all existing children.
    for c := e.Node.FirstChild; c != nil; {
        next := c.NextSibling
        e.Node.RemoveChild(c)
        c = next
    }

    // 2. Create and append the new text node.
    textNode := &html.Node{
        Type: html.TextNode,
        Data: text,
    }
    e.Node.AppendChild(textNode)
}


// --- Node Methods Implementation (DOM Manipulation) ---

// Helper to unwrap a JS Element/Node object back to the Go *Element wrapper.
func (b *DOMBridge) unwrapElement(val goja.Value) (*Element, error) {
    if val == nil || goja.IsNull(val) || goja.IsUndefined(val) {
        return nil, fmt.Errorf("node is null or undefined")
    }

    obj := val.ToObject(b.vm)
    if obj == nil {
        return nil, fmt.Errorf("value is not an object")
    }

    // Retrieve the hidden property that holds the reference to the Go struct.
    wrapperVal := obj.Get("__go_node_wrapper__")
    if wrapperVal == nil || goja.IsUndefined(wrapperVal) {
         return nil, fmt.Errorf("value is not a recognized DOM Node wrapper")
    }

    // Export the value back to the Go struct.
    if element, ok := wrapperVal.Export().(*Element); ok {
         return element, nil
    }

    return nil, fmt.Errorf("failed to export wrapper back to Go struct")
}

func (e *Element) AppendChild(call goja.FunctionCall) goja.Value {
    newChildVal := call.Argument(0)
    newChildWrapper, err := e.bridge.unwrapElement(newChildVal)

    if err != nil {
        // DOMException (TypeError)
        panic(e.bridge.vm.NewGoError(fmt.Errorf("appendChild: invalid argument: %w", err)))
    }

    nodeToAppend := newChildWrapper.Node

    e.bridge.mu.Lock()
    defer e.bridge.mu.Unlock()

    // Detach from any previous parent (DOM spec requirement).
    if nodeToAppend.Parent != nil {
        nodeToAppend.Parent.RemoveChild(nodeToAppend)
    }

    e.Node.AppendChild(nodeToAppend)

    // Returns the appended child.
    return newChildVal
}

func (e *Element) RemoveChild(call goja.FunctionCall) goja.Value {
    childVal := call.Argument(0)
    childWrapper, err := e.bridge.unwrapElement(childVal)

    if err != nil {
        panic(e.bridge.vm.NewGoError(fmt.Errorf("removeChild: invalid argument: %w", err)))
    }

    nodeToRemove := childWrapper.Node

    e.bridge.mu.Lock()
    defer e.bridge.mu.Unlock()

    // Check if the node is actually a child of this element.
    if nodeToRemove.Parent != e.Node {
        // DOMException (NotFoundError)
        panic(e.bridge.vm.NewGoError(fmt.Errorf("removeChild: The node to be removed is not a child of this node")))
    }

    e.Node.RemoveChild(nodeToRemove)

    return childVal
}

func (e *Element) InsertBefore(call goja.FunctionCall) goja.Value {
    newChildVal := call.Argument(0)
    refChildVal := call.Argument(1)

    newChildWrapper, err := e.bridge.unwrapElement(newChildVal)
    if err != nil {
        panic(e.bridge.vm.NewGoError(fmt.Errorf("insertBefore: invalid newChild argument: %w", err)))
    }
    nodeToInsert := newChildWrapper.Node

    var refNode *html.Node
    if !goja.IsNull(refChildVal) && !goja.IsUndefined(refChildVal) {
        refChildWrapper, err := e.bridge.unwrapElement(refChildVal)
        if err != nil {
            panic(e.bridge.vm.NewGoError(fmt.Errorf("insertBefore: invalid refChild argument: %w", err)))
        }
        refNode = refChildWrapper.Node

        // Validate refNode parent.
        if refNode.Parent != e.Node {
             panic(e.bridge.vm.NewGoError(fmt.Errorf("insertBefore: The reference node is not a child of this node")))
        }
    }

    e.bridge.mu.Lock()
    defer e.bridge.mu.Unlock()

    // Detach from any previous parent.
    if nodeToInsert.Parent != nil {
        nodeToInsert.Parent.RemoveChild(nodeToInsert)
    }

    // If refNode is nil, insertBefore acts like appendChild.
    e.Node.InsertBefore(nodeToInsert, refNode)

    return newChildVal
}

func (e *Element) CloneNode(call goja.FunctionCall) goja.Value {
    deep := call.Argument(0).ToBoolean()

    e.bridge.mu.RLock()
    clonedNode := cloneHTMLNode(e.Node, deep)
    e.bridge.mu.RUnlock()

    return e.bridge.WrapNode(clonedNode)
}

// Helper function to deep or shallow clone an *html.Node.
func cloneHTMLNode(n *html.Node, deep bool) *html.Node {
    if n == nil {
        return nil
    }
    clone := &html.Node{
        Type:     n.Type,
        DataAtom: n.DataAtom,
        Data:     n.Data,
        Namespace: n.Namespace,
        Attr:     make([]html.Attribute, len(n.Attr)),
    }
    copy(clone.Attr, n.Attr)

    if deep {
        for c := n.FirstChild; c != nil; c = c.NextSibling {
            clone.AppendChild(cloneHTMLNode(c, true))
        }
    }
    return clone
}


// --- Element Methods Implementation (Attributes) ---

func (e *Element) GetAttribute(call goja.FunctionCall) goja.Value {
	name := call.Argument(0).String()
    return e.GetAttributeValue(name)
}

func (e *Element) GetAttributeValue(name string) goja.Value {
    e.bridge.mu.RLock()
	defer e.bridge.mu.RUnlock()

	for _, attr := range e.Node.Attr {
		if attr.Key == name {
			return e.bridge.vm.ToValue(attr.Val)
		}
	}
	return goja.Null()
}


func (e *Element) SetAttribute(call goja.FunctionCall) goja.Value {
	name := call.Argument(0).String()
	value := call.Argument(1).String()
    e.SetAttributeValue(name, value)
	return goja.Undefined()
}

func (e *Element) SetAttributeValue(name, value string) {
    e.bridge.mu.Lock()
	defer e.bridge.mu.Unlock()

	// Update existing attribute.
	for i, attr := range e.Node.Attr {
		if attr.Key == name {
			e.Node.Attr[i].Val = value
			return
		}
	}

	// Add new attribute.
	e.Node.Attr = append(e.Node.Attr, html.Attribute{Key: name, Val: value})
}

func (e *Element) RemoveAttribute(call goja.FunctionCall) goja.Value {
	name := call.Argument(0).String()

	e.bridge.mu.Lock()
	defer e.bridge.mu.Unlock()

	for i, attr := range e.Node.Attr {
		if attr.Key == name {
			e.Node.Attr = append(e.Node.Attr[:i], e.Node.Attr[i+1:]...)
			return goja.Undefined()
		}
	}
	return goja.Undefined()
}

// QuerySelector (scoped to the element)
func (e *Element) QuerySelector(call goja.FunctionCall) goja.Value {
    selector := call.Argument(0).String()
    xpath := translateCSSToXPath(selector)

    // Ensure the XPath is relative to the current element.
    if !strings.HasPrefix(xpath, ".") {
        xpath = "." + xpath
    }

    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()

    node, err := htmlquery.Query(e.Node, xpath)
    if err != nil {
        panic(e.bridge.vm.NewGoError(fmt.Errorf("invalid selector: %s", selector)))
    }

    if node == nil {
        return goja.Null()
    }

    return e.bridge.WrapNode(node)
}

// QuerySelectorAll (scoped to the element)
func (e *Element) QuerySelectorAll(call goja.FunctionCall) goja.Value {
    selector := call.Argument(0).String()
    xpath := translateCSSToXPath(selector)

    if !strings.HasPrefix(xpath, ".") {
        xpath = "." + xpath
    }

    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()

    nodes, err := htmlquery.QueryAll(e.Node, xpath)
    if err != nil {
        panic(e.bridge.vm.NewGoError(fmt.Errorf("invalid selector: %s", selector)))
    }

	return e.bridge.WrapNodeList(nodes)
}

func (e *Element) GetElementsByTagName(call goja.FunctionCall) goja.Value {
    tagName := strings.ToLower(call.Argument(0).String())
    xpath := fmt.Sprintf(".//%s", tagName)

    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()

    nodes, _ := htmlquery.QueryAll(e.Node, xpath)
    return e.bridge.WrapNodeList(nodes)
}

func (e *Element) GetElementsByClassName(call goja.FunctionCall) goja.Value {
    className := call.Argument(0).String()
    xpath := fmt.Sprintf(".//*[contains(concat(' ', normalize-space(@class), ' '), ' %s ')]", className)

    e.bridge.mu.RLock()
    defer e.bridge.mu.RUnlock()

    nodes, _ := htmlquery.QueryAll(e.Node, xpath)
    return e.bridge.WrapNodeList(nodes)
}


// --- EventTarget Implementation (Basic/Dummy) ---

// Basic implementation allows scripts to register listeners without erroring.
// A proper event system requires an event loop and management (FUTURE IMPROVEMENT).

func (e *Element) AddEventListener(call goja.FunctionCall) goja.Value {
    // eventType := call.Argument(0).String()
    return goja.Undefined()
}

func (e *Element) RemoveEventListener(call goja.FunctionCall) goja.Value {
    return goja.Undefined()
}

func (e *Element) DispatchEvent(call goja.FunctionCall) goja.Value {
    return e.bridge.vm.ToValue(true) // Indicates event was dispatched.
}


// --- Helpers ---

// translateCSSToXPath provides a rudimentary translation of simple CSS selectors to XPath.
func translateCSSToXPath(css string) string {
	// This is highly simplified and only handles basic cases (tag, id, class).

	// Trim whitespace and handle universal selector.
	css = strings.TrimSpace(css)
	if css == "*" {
		return "//*"
	}

    // If it looks like XPath, use it directly.
    if strings.HasPrefix(css, "/") || strings.HasPrefix(css, "./") || strings.HasPrefix(css, "(") {
        return css
    }

	var xpath strings.Builder
	xpath.WriteString("//")

	// Basic tokenization (assumes space is always descendant selector).
	parts := strings.Fields(css)
	for i, part := range parts {
		if i > 0 {
			xpath.WriteString("//") // Descendant selector (space)
		}

		tagName := "*"
		var predicates []string
        hasExplicitTag := false

		// Extract components (ID, classes, tag name).
		currentToken := part

		for len(currentToken) > 0 {
			if strings.HasPrefix(currentToken, "#") {
				// ID
				idEnd := strings.IndexAny(currentToken[1:], ".#")
				if idEnd == -1 {
					idEnd = len(currentToken)
				} else {
					idEnd += 1
				}
				id := currentToken[1:idEnd]
                // Basic handling for simple IDs.
                if !strings.Contains(id, "'") {
				    predicates = append(predicates, fmt.Sprintf("@id='%s'", id))
                }
				currentToken = currentToken[idEnd:]
			} else if strings.HasPrefix(currentToken, ".") {
				// Class
				classEnd := strings.IndexAny(currentToken[1:], ".#")
				if classEnd == -1 {
					classEnd = len(currentToken)
				} else {
					classEnd += 1
				}
				className := currentToken[1:classEnd]
                 if !strings.Contains(className, "'") {
				    predicates = append(predicates, fmt.Sprintf("contains(concat(' ', normalize-space(@class), ' '), ' %s ')", className))
                }
				currentToken = currentToken[classEnd:]
			} else if !hasExplicitTag {
				// Tag name
				tagEnd := strings.IndexAny(currentToken, ".#")
				if tagEnd == -1 {
					tagEnd = len(currentToken)
				}
				tagName = currentToken[:tagEnd]
                hasExplicitTag = true
				currentToken = currentToken[tagEnd:]
			} else {
                // Unexpected token
                break
            }
		}

		xpath.WriteString(tagName)
		if len(predicates) > 0 {
			xpath.WriteString("[")
			xpath.WriteString(strings.Join(predicates, " and "))
			xpath.WriteString("]")
		}
	}

	return xpath.String()
}

// initConsole implements a basic console object.
func (b *DOMBridge) initConsole() {
    console := b.vm.NewObject()
    logFunc := func(level zap.Level) func(goja.FunctionCall) goja.Value {
        return func(call goja.FunctionCall) goja.Value {
            args := make([]string, len(call.Arguments))
            for i, arg := range call.Arguments {
                // Attempt to use JSON.stringify for objects/arrays if available.
                if obj := arg.ToObject(b.vm); obj != nil {
                     if jsJSON := b.vm.Get("JSON"); jsJSON != nil && !goja.IsUndefined(jsJSON) {
                         if stringify, ok := goja.AssertFunction(jsJSON.ToObject(b.vm).Get("stringify")); ok {
                            if result, err := stringify(goja.Undefined(), arg); err == nil {
                                args[i] = result.String()
                                continue
                            }
                        }
                     }
                }
                args[i] = arg.String()
            }
            b.logger.Log(level, "[JS Console]", zap.String("message", strings.Join(args, " ")))
            return goja.Undefined()
        }
    }

    console.Set("log", logFunc(zap.InfoLevel))
    console.Set("info", logFunc(zap.InfoLevel))
    console.Set("warn", logFunc(zap.WarnLevel))
    console.Set("error", logFunc(zap.ErrorLevel))
    console.Set("debug", logFunc(zap.DebugLevel))

    b.vm.GlobalObject().Set("console", console)
}

// initTimers implements synchronous placeholders for setTimeout/clearTimeout.
func (b *DOMBridge) initTimers() {
    // Synchronous setTimeout (executes immediately).
    // This is a limitation as we lack a full event loop integration.
    setTimeout := func(call goja.FunctionCall) goja.Value {
        callback := call.Argument(0)

        if cb, ok := goja.AssertFunction(callback); ok {
            // Execute immediately (synchronously).
            _, err := cb(goja.Undefined())
            if err != nil {
                // Errors within the callback are caught by the runtime.
            }
        }
        // Return a dummy timer ID.
        return b.vm.ToValue(1)
    }

    clearTimeout := func(call goja.FunctionCall) goja.Value {
        // No-op.
        return goja.Undefined()
    }

    b.vm.GlobalObject().Set("setTimeout", setTimeout)
    b.vm.GlobalObject().Set("clearTimeout", clearTimeout)
}
