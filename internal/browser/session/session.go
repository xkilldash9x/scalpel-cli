// internal/browser/session/session.go
package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/net/html"

	// Custom browser modules
    "github.com/xkilldash9x/scalpel-cli/internal/browser/dom"
    "github.com/xkilldash9x/scalpel-cli/internal/browser/jsexec"
    "github.com/xkilldash9x/scalpel-cli/internal/browser/network"

	// User specific imports
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
)

// Session represents a single browsing session (Pure Go implementation).
// It implements dom.CorePagePrimitives and schemas.SessionContext.
type Session struct {
	id     string
	ctx    context.Context
	cancel context.CancelFunc
	logger *zap.Logger
	cfg    *config.Config
	persona schemas.Persona

	// Core functional components
	client     *http.Client
	jsRuntime  *jsexec.Runtime
	interactor *dom.Interactor
	harvester  *Harvester

	// Humanoid configuration parameters (basic simulation supported in Pure Go)
	humanoidCfg *humanoid.Config

	// State management
	mu         sync.RWMutex
	currentURL *url.URL
	// The parsed DOM representation. In this implementation, the DOM is stateful across interactions until navigation.
	currentDOM *html.Node

	findingsChan chan<- schemas.Finding
	onClose      func()
	closeOnce    sync.Once
}

// Ensure Session implements required interfaces.
var _ dom.CorePagePrimitives = (*Session)(nil)
var _ schemas.SessionContext = (*Session)(nil)

// NewSession initializes a new browsing session.
func NewSession(
	parentCtx context.Context,
	cfg *config.Config,
	persona schemas.Persona,
	logger *zap.Logger,
	jsRuntime *jsexec.Runtime,
	findingsChan chan<- schemas.Finding,
) (*Session, error) {

	sessionID := uuid.New().String()
	log := logger.With(zap.String("session_id", sessionID), zap.String("mode", "PureGo"))

	// Create a context specific to this session.
	ctx, cancel := context.WithCancel(parentCtx)

	s := &Session{
		id:           sessionID,
		ctx:          ctx,
		cancel:       cancel,
		logger:       log,
		cfg:          cfg,
		persona:      persona,
		jsRuntime:    jsRuntime,
		findingsChan: findingsChan,
	}

	// 1. Configure Humanoid behavior.
	var domHCfg dom.HumanoidConfig

	if cfg.Browser.Humanoid.Enabled {
		// Create a copy of the config for the session.
		cfgCopy := cfg.Browser.Humanoid
		// We need an RNG for the session's humanoid behavior if not provided.
		if cfgCopy.Rng == nil {
			source := rand.NewSource(time.Now().UnixNano())
			cfgCopy.Rng = rand.New(source)
		}
		// Finalize the persona parameters for this specific session instance.
		cfgCopy.FinalizeSessionPersona(cfgCopy.Rng)
		s.humanoidCfg = &cfgCopy

		// Map to the format expected by the dom package (which only uses timing parameters).
		domHCfg = dom.HumanoidConfig{
			Enabled:        true,
			KeyHoldMeanMs:  s.humanoidCfg.KeyHoldMeanMs,
			ClickHoldMinMs: int(s.humanoidCfg.ClickHoldMinMs),
			ClickHoldMaxMs: int(s.humanoidCfg.ClickHoldMaxMs),
		}
	}

	// 2. Initialize the Network Stack.
	if err := s.initializeNetworkStack(log); err != nil {
        cancel()
		return nil, fmt.Errorf("failed to initialize network stack: %w", err)
	}

	// 3. Define the stabilization function.
	stabilizeFn := func(ctx context.Context) error {
		quietPeriod := 1500 * time.Millisecond // Default stabilization time
		if s.cfg.Network.PostLoadWait > 0 {
			quietPeriod = s.cfg.Network.PostLoadWait
		}
		// Stabilization means waiting for network requests initiated by the last action to complete.
		return s.stabilize(ctx, quietPeriod)
	}

	// 4. Initialize the Interactor.
    // We pass the adapted logger and the session itself as the CorePagePrimitives implementation.
	s.interactor = dom.NewInteractor(NewZapAdapter(log.Named("interactor")), domHCfg, stabilizeFn, s)

	return s, nil
}

// Initialize handles final setup.
// The parameters (browserInstance, taintTemplate, taintConfig) are ignored in the Pure Go implementation.
func (s *Session) Initialize(ctx context.Context, _ interface{}, _, _ string) error {
    if s.cfg.IAST.Enabled {
        s.logger.Warn("IAST is enabled in config but not supported in Pure Go browser mode.")
    }
    s.logger.Info("Session initialized.")
    return nil
}

// initializeNetworkStack sets up the http.Client, Transport, CookieJar, and Harvester middleware.
func (s *Session) initializeNetworkStack(log *zap.Logger) error {
	netConfig := network.NewBrowserClientConfig()
	netConfig.Logger = NewZapAdapter(log.Named("network"))

	// Apply configuration overrides.
	netConfig.InsecureSkipVerify = s.cfg.Browser.IgnoreTLSErrors || s.cfg.Network.IgnoreTLSErrors

    if s.cfg.Network.NavigationTimeout > 0 {
        netConfig.RequestTimeout = s.cfg.Network.NavigationTimeout
    } else {
        netConfig.RequestTimeout = 60 * time.Second // Default navigation timeout
    }

	// Initialize Cookie Jar (if not already initialized by NewBrowserClientConfig).
    if netConfig.CookieJar == nil {
	    jar, _ := cookiejar.New(nil)
	    netConfig.CookieJar = jar
    }

	// 1. Base Transport
	transport := network.NewHTTPTransport(netConfig)

	// 2. Compression Middleware (Wraps Base Transport)
	compressionTransport := network.NewCompressionMiddleware(transport)

	// 3. Harvester (Wraps Compression Transport)
	s.harvester = NewHarvester(compressionTransport, log.Named("harvester"), s.cfg.Network.CaptureResponseBodies)

	// 4. The Client
	s.client = &http.Client{
		Transport: s.harvester, // The top-level transport is the Harvester.
		Timeout:   netConfig.RequestTimeout,
		Jar:       netConfig.CookieJar,
		// Handle redirects manually to ensure full control over navigation flow and state updates.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nil
}

// ID returns the session ID.
func (s *Session) ID() string {
	return s.id
}

// GetContext returns the session's lifecycle context.
func (s *Session) GetContext() context.Context {
	return s.ctx
}

// SetOnClose sets the callback function to be executed when the session is closed.
func (s *Session) SetOnClose(callback func()) {
    s.onClose = callback
}

// Close terminates the session.
func (s *Session) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.logger.Info("Closing session.")
		s.cancel() // Cancel the session context.

		// Clean up resources (e.g., closing idle connections).
        if s.client != nil {
            s.client.CloseIdleConnections()
        }

		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

// stabilize waits for the network to be idle using the Harvester.
func (s *Session) stabilize(ctx context.Context, quietPeriod time.Duration) error {
	if s.harvester == nil {
		return nil
	}
    // Combine the session context and the operation context.
    stabCtx, stabCancel := CombineContext(s.ctx, ctx)
    defer stabCancel()

	return s.harvester.WaitNetworkIdle(stabCtx, quietPeriod)
}

// -- Navigation and Execution --

// Navigate loads a URL and updates the session state.
func (s *Session) Navigate(ctx context.Context, targetURL string) error {
    navCtx, navCancel := CombineContext(s.ctx, ctx)
    defer navCancel()

	// 1. Resolve URL against the current URL.
	resolvedURL, err := s.resolveURL(targetURL)
	if err != nil {
		return fmt.Errorf("failed to resolve URL '%s': %w", targetURL, err)
	}

    s.logger.Info("Navigating", zap.String("url", resolvedURL.String()))

	// 2. Create the request.
	req, err := http.NewRequestWithContext(navCtx, http.MethodGet, resolvedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for '%s': %w", resolvedURL.String(), err)
	}
	s.prepareRequestHeaders(req)

	// 3. Execute the request (handles redirects and updates state).
	if err := s.executeRequest(navCtx, req); err != nil {
		return err
	}

	// 4. Stabilization after navigation.
	if err := s.stabilize(navCtx, s.cfg.Network.PostLoadWait); err != nil {
		if navCtx.Err() != nil {
			return navCtx.Err()
		}
		s.logger.Debug("Stabilization finished with potential issues after navigation.", zap.Error(err))
	}

    // 5. Cognitive pause (if enabled).
    if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
        // Simulate reading time after page load. Uses utility from timing.go
        if err := hesitate(navCtx, 500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond); err != nil {
            return err
        }
    }

	return nil
}

// executeRequest sends the HTTP request, handles redirects, and updates state.
func (s *Session) executeRequest(ctx context.Context, req *http.Request) error {
	const maxRedirects = 10
	currentReq := req

	for i := 0; i < maxRedirects; i++ {
		s.logger.Debug("Executing request", zap.String("method", currentReq.Method), zap.String("url", currentReq.URL.String()))

		// Send the request via the client (which includes the Harvester).
		resp, err := s.client.Do(currentReq)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}

		// Check for redirects (3xx status codes).
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			nextReq, err := s.handleRedirect(ctx, resp, currentReq)
			// Ensure the previous response body is closed. The Harvester handles the closure tracking.
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("failed to handle redirect: %w", err)
			}
			currentReq = nextReq
			continue
		}

		// Process the final response.
		return s.processResponse(resp)
	}

	return fmt.Errorf("maximum number of redirects (%d) exceeded", maxRedirects)
}

// handleRedirect processes a redirect response and prepares the next request.
func (s *Session) handleRedirect(ctx context.Context, resp *http.Response, originalReq *http.Request) (*http.Request, error) {
	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("redirect response missing Location header")
	}

	nextURL, err := originalReq.URL.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redirect Location '%s': %w", location, err)
	}

	// Determine the method for the next request according to HTTP specifications.
	method := originalReq.Method
	var body io.ReadCloser

    // 301, 302, 303 should typically change POST/PUT to GET.
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
        if method != http.MethodHead {
		    method = http.MethodGet
        }
		body = nil
	} else if originalReq.GetBody != nil {
		// For temporary redirects (307/308), reuse the body if possible.
		body, err = originalReq.GetBody()
		if err != nil {
			return nil, fmt.Errorf("failed to get body for redirect reuse: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, nextURL.String(), body)
	if err != nil {
		return nil, err
	}

	// Prepare headers for the next request.
	s.prepareRequestHeaders(req)
    // Set the Referer header to the URL of the original request.
	req.Header.Set("Referer", originalReq.URL.String())

	return req, nil
}

// processResponse handles the final response body, parses the DOM, and updates the session state.
func (s *Session) processResponse(resp *http.Response) error {
    // The body MUST be closed. The Harvester's wrapper ensures this triggers the completion logic.
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.logger.Warn("Request resulted in error status code", zap.Int("status", resp.StatusCode), zap.String("url", resp.Request.URL.String()))
	}

    // We primarily care about HTML content for DOM interaction.
    contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		s.logger.Debug("Response is not HTML, skipping DOM parsing.", zap.String("content_type", contentType))
		s.updateState(resp.Request.URL, nil)
		return nil
	}

	// Parse the HTML body. This consumes the response body.
	doc, err := htmlquery.Parse(resp.Body)
	if err != nil {
		// If parsing fails, update the URL but leave the DOM empty.
		s.updateState(resp.Request.URL, nil)
		return fmt.Errorf("failed to parse HTML response from '%s': %w", resp.Request.URL.String(), err)
	}

	s.updateState(resp.Request.URL, doc)
	return nil
}

// updateState updates the session's current URL, DOM, and informs the Harvester.
func (s *Session) updateState(newURL *url.URL, doc *html.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.currentURL = newURL
	s.currentDOM = doc

	title := ""
	if doc != nil {
		if titleNode := htmlquery.FindOne(doc, "//title"); titleNode != nil {
			title = strings.TrimSpace(htmlquery.InnerText(titleNode))
		}
	}

	s.logger.Debug("Session state updated", zap.String("url", newURL.String()), zap.String("title", title))

	if s.harvester != nil {
        // Update the Harvester's page context.
		s.harvester.SetPageContext(title)
	}
}

// -- Implementation of dom.CorePagePrimitives --

// GetCurrentURL returns the URL of the current page state.
func (s *Session) GetCurrentURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentURL != nil {
		return s.currentURL.String()
	}
	return ""
}

// GetDOMSnapshot fetches the current HTML body for parsing.
func (s *Session) GetDOMSnapshot(ctx context.Context) (io.Reader, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentDOM == nil {
        // Return a basic empty HTML structure if DOM is nil.
		return bytes.NewBufferString("<html><head></head><body></body></html>"), nil
	}

	// Serialize the current DOM back to HTML.
	var buf bytes.Buffer
	if err := html.Render(&buf, s.currentDOM); err != nil {
		return nil, fmt.Errorf("failed to render DOM snapshot: %w", err)
	}

	return &buf, nil
}

// ExecuteClick simulates a click action on an element identified by XPath.
func (s *Session) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
    actionCtx, actionCancel := CombineContext(s.ctx, ctx)
    defer actionCancel()

	// 1. Find the element.
	element, err := s.findElement(selector)
	if err != nil {
		return err
	}

    // 2. Simulate click timing (if enabled). Uses utility from timing.go
    if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
        if err := simulateClickTiming(actionCtx, minMs, maxMs); err != nil {
            return err
        }
    }

	// 3. Determine the consequence of the click (navigation or submission).
	return s.handleClickConsequence(actionCtx, element)
}

// ExecuteType simulates typing text into an element identified by XPath.
func (s *Session) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
    actionCtx, actionCancel := CombineContext(s.ctx, ctx)
    defer actionCancel()

	// 1. Find the element.
	element, err := s.findElement(selector)
	if err != nil {
		return err
	}

    // 2. Validate element type.
    tagName := strings.ToLower(element.Data)
    if tagName != "input" && tagName != "textarea" {
        // Basic contenteditable support is complex to simulate accurately without a layout engine.
        return fmt.Errorf("element '%s' is not a supported text input type", selector)
    }

    // 3. Simulate typing timing (if enabled). Uses utility from timing.go
    if s.humanoidCfg != nil && s.humanoidCfg.Enabled && holdMeanMs > 0 {
        if err := simulateTyping(actionCtx, text, holdMeanMs); err != nil {
            return err
        }
    }

	// 4. Update the element's value in the DOM representation.
    // We need a write lock as we are modifying the DOM state.
    s.mu.Lock()
    defer s.mu.Unlock()

    if tagName == "textarea" {
        // For textarea, the value is the child text node. Clear and replace.
        for c := element.FirstChild; c != nil; {
            next := c.NextSibling
            element.RemoveChild(c)
            c = next
        }
        element.AppendChild(&html.Node{
            Type: html.TextNode,
            Data: text,
        })
    } else {
        // For input, the value is the 'value' attribute.
        setAttr(element, "value", text)
    }

	return nil
}

// ExecuteSelect handles dropdown selection by value.
func (s *Session) ExecuteSelect(ctx context.Context, selector string, value string) error {
    actionCtx, actionCancel := CombineContext(s.ctx, ctx)
    defer actionCancel()

	// 1. Find the element.
	element, err := s.findElement(selector)
	if err != nil {
		return err
	}

    if strings.ToLower(element.Data) != "select" {
        return fmt.Errorf("element '%s' is not a select element", selector)
    }

    // 2. Simulate interaction timing.
    if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
        if err := simulateClickTiming(actionCtx, 100, 300); err != nil {
            return err
        }
    }

	// 3. Update the select element state in the DOM.
    // We need a write lock as we are modifying the DOM state.
    s.mu.Lock()
    defer s.mu.Unlock()

    found := false
    // Iterate over options (including those inside optgroup) and set 'selected' attribute.
    options, err := htmlquery.QueryAll(element, ".//option")
    if err != nil {
        return fmt.Errorf("failed to query options for select element '%s': %w", selector, err)
    }

    for _, opt := range options {
        optValue := htmlquery.SelectAttr(opt, "value")
        // If value attribute is missing, the text content is the value.
        if optValue == "" {
            optValue = strings.TrimSpace(htmlquery.InnerText(opt))
        }

        isSelected := optValue == value
        if isSelected {
            found = true
        }

        // Update the 'selected' attribute using helpers.
        if isSelected {
            setAttr(opt, "selected", "selected")
        } else {
            removeAttr(opt, "selected")
        }
    }

    if !found {
        return fmt.Errorf("option with value '%s' not found in select element '%s'", value, selector)
    }

	return nil
}

// -- High-Level Interaction Methods (Implementing schemas.SessionContext) --

// Interact triggers the automated recursive interaction logic.
func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
    if s.interactor == nil {
        return fmt.Errorf("interactor not initialized")
    }

    // Map schema config to dom config.
    domConfig := dom.InteractionConfig{
        MaxDepth:                config.MaxDepth,
        MaxInteractionsPerDepth: config.MaxInteractionsPerDepth,
        InteractionDelayMs:      config.InteractionDelayMs,
        PostInteractionWaitMs:   config.PostInteractionWaitMs,
    }

    return s.interactor.RecursiveInteract(ctx, domConfig)
}

// Click is the high-level click command.
func (s *Session) Click(ctx context.Context, selector string) error {
    minMs, maxMs := 0, 0
    if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
        minMs = int(s.humanoidCfg.ClickHoldMinMs)
        maxMs = int(s.humanoidCfg.ClickHoldMaxMs)
    }
    // Selector is assumed to be XPath as required by dom.Interactor/CorePagePrimitives.
    return s.ExecuteClick(ctx, selector, minMs, maxMs)
}

// Type is the high-level type command.
func (s *Session) Type(ctx context.Context, selector string, text string) error {
    holdMeanMs := 0.0
    if s.humanoidCfg != nil && s.humanoidCfg.Enabled {
        holdMeanMs = s.humanoidCfg.KeyHoldMeanMs
    }
    return s.ExecuteType(ctx, selector, text, holdMeanMs)
}

// Submit attempts to submit the form associated with the given selector.
func (s *Session) Submit(ctx context.Context, selector string) error {
    // 1. Find the element.
	element, err := s.findElement(selector)
	if err != nil {
		return err
	}

    // 2. Find the associated form.
    form := findParentForm(element)

    if form == nil {
        return fmt.Errorf("element '%s' is not associated with a form", selector)
    }

    // 3. Simulate the submission.
    return s.submitForm(ctx, form)
}

// ScrollPage is not implemented in the Pure Go version (no layout engine).
func (s *Session) ScrollPage(ctx context.Context, direction string, amount int) error {
	s.logger.Debug("ScrollPage called but is ignored in Pure Go mode.")
	return nil
}

// WaitForAsync waits for the network to become idle (stabilization).
func (s *Session) WaitForAsync(ctx context.Context, timeout time.Duration) error {
    // Use the configured stabilization period if timeout is not specified.
    if timeout == 0 {
        timeout = s.cfg.Network.PostLoadWait
        if timeout == 0 {
            timeout = 2 * time.Second
        }
    }
	return s.stabilize(ctx, timeout)
}

// -- Artifact Collection and Management --

// CollectArtifacts gathers the HAR log and other relevant data from the session.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.SessionArtifacts, error) {
	artifacts := &schemas.SessionArtifacts{
        // ConsoleLogs and Screenshots are not available in this implementation.
    }

	if s.harvester != nil {
		artifacts.HAR = s.harvester.GenerateHAR()
	}

    // Add final URL and DOM snapshot.
    artifacts.FinalURL = s.GetCurrentURL()
    domSnapshot, err := s.GetDOMSnapshot(ctx)
    if err == nil {
        if snapshotBytes, err := io.ReadAll(domSnapshot); err == nil {
            artifacts.FinalDOM = string(snapshotBytes)
        }
    }

	return artifacts, nil
}

// AddFinding reports a finding discovered during the session.
func (s *Session) AddFinding(finding schemas.Finding) {
	if s.findingsChan != nil {
		select {
		case s.findingsChan <- finding:
		default:
			s.logger.Warn("Findings channel buffer full. Dropping finding.", zap.String("title", finding.Title))
		}
	}
}

// ExecuteScript runs a snippet of JavaScript using the sandboxed Goja runtime.
// Note: Goja does NOT have access to the live DOM or browser APIs in this implementation.
func (s *Session) ExecuteScript(ctx context.Context, script string, res interface{}) error {
    if s.jsRuntime == nil {
        return fmt.Errorf("JavaScript runtime not initialized")
    }

    execCtx, execCancel := CombineContext(s.ctx, ctx)
    defer execCancel()

    // Keep the scope simple for sandboxed execution.
    args := map[string]interface{}{}

    result, err := s.jsRuntime.ExecuteScript(execCtx, script, args)
    if err != nil {
        return err
    }

    if res != nil {
        // Marshal the result from Goja (interface{}) to JSON, then unmarshal into the target struct.
        data, err := json.Marshal(result)
        if err != nil {
            return fmt.Errorf("failed to marshal JS result: %w", err)
        }
        if err := json.Unmarshal(data, res); err != nil {
            return fmt.Errorf("failed to unmarshal JS result into target type: %w", err)
        }
    }

	return nil
}

// -- Helpers and Utilities --

// resolveURL resolves a potentially relative URL against the current session URL.
func (s *Session) resolveURL(targetURL string) (*url.URL, error) {
	s.mu.RLock()
	currentURL := s.currentURL
	s.mu.RUnlock()

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

    // Handle empty or anchor-only URLs.
    if targetURL == "" || strings.HasPrefix(targetURL, "#") {
        if currentURL != nil {
            return currentURL.ResolveReference(parsedURL), nil
        }
        return nil, fmt.Errorf("cannot resolve relative URL '%s' without a base URL", targetURL)
    }

	if currentURL != nil && !parsedURL.IsAbs() {
		return currentURL.ResolveReference(parsedURL), nil
	}

    if !parsedURL.IsAbs() {
        return nil, fmt.Errorf("initial navigation target must be an absolute URL: '%s'", targetURL)
    }

	return parsedURL, nil
}

// prepareRequestHeaders sets standard browser headers based on the persona.
func (s *Session) prepareRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", s.persona.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
    if len(s.persona.Languages) > 0 {
	    req.Header.Set("Accept-Language", strings.Join(s.persona.Languages, ","))
    }
    // Ensure the compression header is set.
    if req.Header.Get("Accept-Encoding") == "" {
        req.Header.Set("Accept-Encoding", "gzip, deflate, br")
    }
    // Set Referer if we have a current URL (basic implementation).
    if s.currentURL != nil && req.Header.Get("Referer") == "" {
         req.Header.Set("Referer", s.currentURL.String())
    }
}

// findElement locates a single element in the current DOM using XPath.
func (s *Session) findElement(selector string) (*html.Node, error) {
    s.mu.RLock()
    dom := s.currentDOM
    s.mu.RUnlock()

    if dom == nil {
        return nil, fmt.Errorf("DOM is empty, cannot find element '%s'", selector)
    }

    // Use htmlquery (XPath engine) to find the element.
    element, err := htmlquery.Query(dom, selector)
    if err != nil {
        return nil, fmt.Errorf("invalid XPath selector '%s': %w", selector, err)
    }
    if element == nil {
        return nil, fmt.Errorf("element not found matching selector '%s'", selector)
    }
    return element, nil
}

// handleClickConsequence determines the action resulting from a click.
func (s *Session) handleClickConsequence(ctx context.Context, element *html.Node) error {
    tagName := strings.ToLower(element.Data)

    // Handle Anchor links (<a>)
    if tagName == "a" {
        href := htmlquery.SelectAttr(element, "href")
        // Basic filtering for non-navigational links.
        if href != "" && !strings.HasPrefix(strings.ToLower(href), "javascript:") {
            // Navigate to the link. This will trigger stabilization within the Navigate call.
            return s.Navigate(ctx, href)
        }
    }

    // Handle Form Submission
    inputType := strings.ToLower(htmlquery.SelectAttr(element, "type"))
    isSubmit := (tagName == "button" && (inputType == "submit" || inputType == "")) ||
                (tagName == "input" && inputType == "submit")

    if isSubmit {
        form := findParentForm(element)
        if form != nil {
            return s.submitForm(ctx, form)
        }
    }

    // Handle State Changes (Checkboxes/Radios)
    if tagName == "input" {
        if inputType == "checkbox" {
            s.mu.Lock()
            if htmlquery.SelectAttr(element, "checked") != "" {
                removeAttr(element, "checked")
            } else {
                setAttr(element, "checked", "checked")
            }
            s.mu.Unlock()
            return nil
        }
        if inputType == "radio" {
            s.handleRadioSelection(element)
            return nil
        }
    }


    // Other elements (JS handlers) are ignored as we lack a full JS engine integration with the DOM.
    s.logger.Debug("Click consequence ignored for element (no navigation or submission detected)", zap.String("tag", tagName))
    return nil
}

// submitForm handles the serialization and submission of a form element.
func (s *Session) submitForm(ctx context.Context, form *html.Node) error {
    action := htmlquery.SelectAttr(form, "action")
    method := strings.ToUpper(htmlquery.SelectAttr(form, "method"))

    if method != http.MethodPost {
        method = http.MethodGet // Default HTML form method
    }

    // Resolve the action URL.
    targetURL, err := s.resolveURL(action)
    if err != nil || action == "" {
        // If action is empty or invalid, resolve against current URL.
        targetURL, _ = s.resolveURL("")
        if targetURL == nil {
             return fmt.Errorf("failed to determine form submission URL")
        }
    }

    // Serialize form data.
    formData := url.Values{}
    // We must lock the DOM while querying as the state (values, checked status) might change.
    s.mu.RLock()
    inputs, err := htmlquery.QueryAll(form, ".//input | .//textarea | .//select")
    s.mu.RUnlock()

    if err != nil {
        return fmt.Errorf("failed to query form elements: %w", err)
    }

    // Standard form serialization logic.
    for _, input := range inputs {
        name := htmlquery.SelectAttr(input, "name")
        if name == "" {
            continue
        }
        tagName := strings.ToLower(input.Data)
        inputType := strings.ToLower(htmlquery.SelectAttr(input, "type"))

        switch tagName {
        case "input":
            switch inputType {
            case "checkbox", "radio":
                if htmlquery.SelectAttr(input, "checked") != "" {
                    value := htmlquery.SelectAttr(input, "value")
                    if value == "" { value = "on" }
                    formData.Add(name, value)
                }
            case "submit", "button", "image", "reset", "file":
                // Ignore.
            default:
                // text, password, hidden, etc.
                value := htmlquery.SelectAttr(input, "value")
                formData.Add(name, value)
            }
        case "textarea":
            value := htmlquery.InnerText(input)
            formData.Add(name, value)
        case "select":
            // Find the selected option(s).
            selectedOptions, _ := htmlquery.QueryAll(input, ".//option[@selected]")
            for _, opt := range selectedOptions {
                value := htmlquery.SelectAttr(opt, "value")
                if value == "" { value = htmlquery.InnerText(opt) }
                formData.Add(name, value)
            }
        }
    }

    // Prepare and execute the request.
    var req *http.Request
    if method == http.MethodPost {
        encodedData := formData.Encode()
        req, err = http.NewRequestWithContext(ctx, method, targetURL.String(), strings.NewReader(encodedData))
        if err != nil {
            return err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    } else {
        // GET request: Append data to the URL's query string.
        targetURLCopy := *targetURL
        if targetURLCopy.RawQuery == "" {
            targetURLCopy.RawQuery = formData.Encode()
        } else {
            targetURLCopy.RawQuery += "&" + formData.Encode()
        }
        req, err = http.NewRequestWithContext(ctx, method, targetURLCopy.String(), nil)
        if err != nil {
            return err
        }
    }

    s.prepareRequestHeaders(req)
    // Ensure Referer is set correctly for form submission.
    req.Header.Set("Referer", s.GetCurrentURL())

    // Execute the request (handles navigation and subsequent stabilization).
    return s.executeRequest(ctx, req)
}

// handleRadioSelection ensures only one radio button in a group is checked.
func (s *Session) handleRadioSelection(element *html.Node) {
    s.mu.Lock()
    defer s.mu.Unlock()

    name := htmlquery.SelectAttr(element, "name")
    if name == "" {
        setAttr(element, "checked", "checked")
        return
    }

    // Find the root of the document (or the containing form) to search for others in the group.
    root := findParentForm(element)
    if root == nil {
        root = element
        for root.Parent != nil {
            root = root.Parent
        }
    }


    xpath := fmt.Sprintf(".//input[@type='radio' and @name='%s']", name)
    radios := htmlquery.Find(root, xpath)

    for _, radio := range radios {
        if radio == element {
            setAttr(radio, "checked", "checked")
        } else {
            removeAttr(radio, "checked")
        }
    }
}


// Helper functions for DOM attribute manipulation (used internally).
func removeAttr(n *html.Node, key string) {
    for i, attr := range n.Attr {
        if attr.Key == key {
            n.Attr = append(n.Attr[:i], n.Attr[i+1:]...)
            return
        }
    }
}

func setAttr(n *html.Node, key, val string) {
    for i, attr := range n.Attr {
        if attr.Key == key {
            n.Attr[i].Val = val
            return
        }
    }
    n.Attr = append(n.Attr, html.Attribute{Key: key, Val: val})
}

func findParentForm(element *html.Node) *html.Node {
    form := element.Parent
    for form != nil {
        if form.Type == html.ElementNode && strings.ToLower(form.Data) == "form" {
            return form
        }
        form = form.Parent
    }
    return nil
}

// CombineContext creates a new context that is canceled when either parentCtx or secondaryCtx is canceled.
// This utility is crucial for ensuring operations respect both session lifecycle and specific request deadlines.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	combinedCtx, cancel := context.WithCancel(parentCtx)

	go func() {
        // Use a select statement to monitor both contexts.
		select {
		case <-secondaryCtx.Done():
			// If the secondary context is canceled, cancel the combined context.
			cancel()
		case <-combinedCtx.Done():
			// The combined context was already canceled (likely from the parent), so exit.
		}
	}()

	return combinedCtx, cancel
}
