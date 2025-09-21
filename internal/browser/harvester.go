// internal/browser/harvester.go
package browser

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

const networkIdleCheckFrequency = 250 * time.Millisecond

// requestState holds the information for a single network request throughout its lifecycle.
type requestState struct {
	request      *network.EventRequestWillBeSent
	responses    []*network.EventResponseReceived // Handles redirects
	body         []byte
	err          error
	finished     bool
	isDataURL    bool
	wallTime     time.Time
	monotonicTime cdp.MonotonicTime
}

// Harvester listens to browser network events and console logs to build a HAR file.
type Harvester struct {
	ctx           context.Context
	cancel        context.CancelFunc
	logger        *zap.Logger
	captureBodies bool

	mu            sync.RWMutex
	requests      map[network.RequestID]*requestState
	consoleLogs   []schemas.ConsoleLog
	pageID        string
	pageTitle     string
	startTime     time.Time
	onLoadTime    float64
	onContentLoad float64
	activeReqs    int64 // Counter for active requests for idle calculation

	wg sync.WaitGroup // To wait for all body-fetching goroutines
}

// NewHarvester creates a new network harvester instance.
func NewHarvester(ctx context.Context, logger *zap.Logger, captureBodies bool) *Harvester {
	hCtx, hCancel := context.WithCancel(ctx)
	return &Harvester{
		ctx:           hCtx,
		cancel:        hCancel,
		logger:        logger.Named("harvester"),
		captureBodies: captureBodies,
		requests:      make(map[network.RequestID]*requestState),
		consoleLogs:   make([]schemas.ConsoleLog, 0),
		startTime:     time.Now(),
	}
}

// Start begins listening to network and console events from the browser context.
func (h *Harvester) Start(ctx context.Context) error {
	// This context is the session context, which is what we need to listen on
	h.listen(ctx)
	return nil
}

// Stop halts the event listeners and returns the collected artifacts (HAR and console logs).
func (h *Harvester) Stop(ctx context.Context) (*schemas.HAR, []schemas.ConsoleLog) {
	h.cancel()  // Signal the listener goroutine to stop
	h.wg.Wait() // Wait for any outstanding body-fetching goroutines to complete

	h.mu.Lock()
	defer h.mu.Unlock()

	har := h.generateHAR()
	logs := h.consoleLogs
	h.consoleLogs = make([]schemas.ConsoleLog, 0) // Clear logs for safety

	return har, logs
}

// listen sets up the CDP event listeners.
func (h *Harvester) listen(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		// Use a select to ensure we don't process events after the harvester is stopped
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		switch ev := ev.(type) {
		// -- Network Events --
		case *network.EventRequestWillBeSent:
			h.handleRequestWillBeSent(ev)
		case *network.EventResponseReceived:
			h.handleResponseReceived(ev)
		case *network.EventLoadingFinished:
			h.handleLoadingFinished(ev)
		case *network.EventLoadingFailed:
			h.handleLoadingFailed(ev)
		// -- Page Lifecycle Events --
		case *page.EventLifecycleEvent:
			h.handlePageLifecycleEvent(ev)
		// -- Console Events --
		case *log.EventEntryAdded:
			h.handleConsoleLog(ev)
		}
	})
}

// WaitNetworkIdle blocks until the network has been quiet for a specified duration.
func (h *Harvester) WaitNetworkIdle(ctx context.Context, quietPeriod time.Duration) error {
	h.logger.Debug("Waiting for network to become idle.")
	timer := time.NewTimer(quietPeriod)
	defer timer.Stop()

	ticker := time.NewTicker(networkIdleCheckFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.ctx.Done():
			return h.ctx.Err()
		case <-ticker.C:
			h.mu.RLock()
			active := h.activeReqs
			h.mu.RUnlock()

			if active == 0 {
				// Reset the timer only if it's not already running
				if !timer.Stop() {
					// Drain the channel if Stop() returns false
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(quietPeriod)
			}
		case <-timer.C:
			// Timer fired, meaning network was idle for the quiet period
			h.logger.Debug("Network is idle.")
			return nil
		}
	}
}

// -- Event Handlers --

func (h *Harvester) handleRequestWillBeSent(ev *network.EventRequestWillBeSent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.activeReqs++

	if _, exists := h.requests[ev.RequestID]; !exists {
		h.requests[ev.RequestID] = &requestState{
			isDataURL: strings.HasPrefix(ev.Request.URL, "data:"),
		}
	}
	h.requests[ev.RequestID].request = ev
	h.requests[ev.RequestID].wallTime = ev.WallTime.Time()
	
	// FIX: Dereference the pointer after a nil check.
	if ev.Timestamp != nil {
		h.requests[ev.RequestID].monotonicTime = *ev.Timestamp
	}

	// Capture the initial page ID if not set
	if h.pageID == "" && ev.Type == network.ResourceTypeDocument {
		h.pageID = ev.FrameID.String()
	}
}

func (h *Harvester) handleResponseReceived(ev *network.EventResponseReceived) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req, ok := h.requests[ev.RequestID]; ok {
		req.responses = append(req.responses, ev)
		// Try to fetch the body now if configured
		if h.captureBodies && ev.HasExtraInfo {
			h.fetchBody(ev.RequestID)
		}
	}
}

func (h *Harvester) handleLoadingFinished(ev *network.EventLoadingFinished) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req, ok := h.requests[ev.RequestID]; ok {
		req.finished = true
		// Try fetching body again, in case extra info wasn't available before
		if h.captureBodies && len(req.responses) > 0 && req.body == nil && !req.isDataURL {
			h.fetchBody(ev.RequestID)
		}
	}
	h.activeReqs--
}

func (h *Harvester) handleLoadingFailed(ev *network.EventLoadingFailed) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req, ok := h.requests[ev.RequestID]; ok {
		req.finished = true
		req.err = fmt.Errorf("request failed: %s", ev.ErrorText)
	}
	h.activeReqs--
}

func (h *Harvester) handlePageLifecycleEvent(ev *page.EventLifecycleEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.pageID == "" {
		h.pageID = ev.FrameID.String()
	}

	delta := ev.Timestamp.Time().Sub(h.startTime).Seconds() * 1000

	switch ev.Name {
	case "load":
		h.onLoadTime = delta
	case "DOMContentLoaded":
		h.onContentLoad = delta
	case "init":
		h.startTime = ev.Timestamp.Time()
	}
}

func (h *Harvester) handleConsoleLog(ev *log.EventEntryAdded) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.consoleLogs = append(h.consoleLogs, schemas.ConsoleLog{
		Type:      string(ev.Entry.Level),
		Timestamp: ev.Entry.Timestamp.Time(),
		Text:      ev.Entry.Text,
		Source:    string(ev.Entry.Source),
		URL:       ev.Entry.URL,
		Line:      ev.Entry.LineNumber,
	})
}

// -- Body Fetching Logic --

func (h *Harvester) fetchBody(reqID network.RequestID) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()

		var body []byte
		// FIX: Corrected the chromedp.Run call to avoid the multiple-value error.
		err := chromedp.Run(h.ctx,
			chromedp.ActionFunc(func(c context.Context) error {
				var err error
				body, err = network.GetResponseBody(reqID).Do(c)
				return err
			}),
		)

		h.mu.Lock()
		defer h.mu.Unlock()
		if req, ok := h.requests[reqID]; ok {
			if err != nil {
				// Don't log context canceled errors as they are expected on shutdown.
				if h.ctx.Err() == nil {
					h.logger.Debug("Failed to fetch response body.", zap.String("reqID", string(reqID)), zap.Error(err))
				}
				req.err = err
			} else {
				req.body = body
			}
		}
	}()
}

// -- HAR Generation --

func (h *Harvester) generateHAR() *schemas.HAR {
	har := schemas.NewHAR()

	har.Log.Pages = append(har.Log.Pages, schemas.Page{
		StartedDateTime: h.startTime,
		ID:              h.pageID,
		Title:           h.pageTitle,
		PageTimings: schemas.PageTimings{
			OnContentLoad: h.onContentLoad,
			OnLoad:        h.onLoadTime,
		},
	})

	for _, reqState := range h.requests {
		if reqState.request == nil || len(reqState.responses) == 0 {
			continue // Skip incomplete entries
		}
		finalResp := reqState.responses[len(reqState.responses)-1]
		
		totalTime := finalResp.Timestamp.Time().Sub(reqState.monotonicTime.Time()).Seconds() * 1000

		entry := schemas.Entry{
			Pageref:         h.pageID,
			StartedDateTime: reqState.wallTime,
			Time:            totalTime,
			Request:         h.buildHARRequest(reqState.request),
			Response:        h.buildHARResponse(finalResp, reqState.body),
			Cache:           struct{}{},
			// FIX: Access the Timing field via the nested Response struct.
			Timings:         convertCDPTimings(finalResp.Response.Timing),
		}
		har.Log.Entries = append(har.Log.Entries, entry)
	}
	return har
}

func (h *Harvester) buildHARRequest(req *network.EventRequestWillBeSent) schemas.Request {
	u, _ := url.Parse(req.Request.URL)
	qs := make([]schemas.NVPair, 0)
	for k, v := range u.Query() {
		for _, val := range v {
			qs = append(qs, schemas.NVPair{Name: k, Value: val})
		}
	}

	harReq := schemas.Request{
		Method:      req.Request.Method,
		URL:         req.Request.URL,
		HTTPVersion: "HTTP/1.1", // Often a guess
		// FIX: Use helper to get header value and handle type assertion.
		Cookies:     convertCDPCookies(getHeader(req.Request.Headers, "Cookie")),
		Headers:     convertCDPHeaders(req.Request.Headers),
		QueryString: qs,
		HeadersSize: calculateHeaderSize(req.Request.Headers),
		BodySize:    int64(len(req.Request.PostData)),
	}

	if req.Request.PostData != "" {
		harReq.PostData = &schemas.PostData{
			// FIX: Use helper to get header value.
			MimeType: getHeader(req.Request.Headers, "Content-Type"),
			Text:     req.Request.PostData,
		}
	}

	return harReq
}

func (h *Harvester) buildHARResponse(resp *network.EventResponseReceived, body []byte) schemas.Response {
	content := schemas.Content{
		Size:     int64(len(body)),
		MimeType: resp.Response.MimeType,
	}

	if isTextMime(resp.Response.MimeType) {
		content.Text = string(body)
	} else if len(body) > 0 {
		content.Encoding = "base64"
		content.Text = base64.StdEncoding.EncodeToString(body)
	}

	return schemas.Response{
		Status:      int(resp.Response.Status),
		StatusText:  resp.Response.StatusText,
		HTTPVersion: resp.Response.Protocol,
		// FIX: Use helper to get header value.
		Cookies:     convertCDPCookies(getHeader(resp.Response.Headers, "Set-Cookie")),
		Headers:     convertCDPHeaders(resp.Response.Headers),
		Content:     content,
		// FIX: Use helper to get header value.
		RedirectURL: getHeader(resp.Response.Headers, "Location"),
		HeadersSize: calculateHeaderSize(resp.Response.Headers),
		// FIX: Cast float64 to int64.
		BodySize:    int64(resp.Response.EncodedDataLength),
	}
}

// -- Helpers --

// getHeader performs a case-insensitive search for a header and returns its string value.
func getHeader(headers network.Headers, key string) string {
	for h, v := range headers {
		if strings.EqualFold(h, key) {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// convertCDPTimings converts network.ResourceTiming to HAR Timings format.
func convertCDPTimings(t *network.ResourceTiming) schemas.Timings {
	if t == nil {
		return schemas.Timings{}
	}
	// Helper to convert CDP timing (milliseconds) to HAR timing, handling negative values.
	toHARTime := func(v float64) float64 {
		if v < 0 {
			return -1
		}
		return v
	}

	// Calculate HAR timings based on the CDP structure.
	dns := toHARTime(t.DNSEnd - t.DNSStart)
	connect := toHARTime(t.ConnectEnd - t.ConnectStart)
	ssl := toHARTime(t.SslEnd - t.SslStart)
	send := toHARTime(t.SendEnd - t.SendStart)

	// Blocked time approximation.
	blocked := t.RequestTime*1000 - t.ProxyEnd
	if blocked < 0 {
		blocked = 0
	}

	// Wait time (Time To First Byte - TTFB).
	wait := toHARTime(t.ReceiveHeadersEnd - t.SendEnd)
	// Receive time is complex to calculate perfectly without the total duration event, defaulting to 0.
	receive := float64(0)

	return schemas.Timings{
		Blocked: blocked,
		DNS:     dns,
		Connect: connect,
		Send:    send,
		Wait:    wait,
		Receive: receive,
		SSL:     ssl,
	}
}

func isTextMime(mimeType string) bool {
	lowerMime := strings.ToLower(mimeType)
	return strings.HasPrefix(lowerMime, "text/") ||
		strings.Contains(lowerMime, "javascript") ||
		strings.Contains(lowerMime, "json") ||
		strings.Contains(lowerMime, "xml")
}

func calculateHeaderSize(headers network.Headers) int64 {
	var size int64
	for k, v := range headers {
		if val, ok := v.(string); ok {
			// Add size of key, value, plus separators like ": " and "\r\n"
			size += int64(len(k) + len(val) + 4)
		}
	}
	return size
}

func convertCDPHeaders(headers network.Headers) []schemas.NVPair {
	pairs := make([]schemas.NVPair, 0, len(headers))
	for k, v := range headers {
		if val, ok := v.(string); ok {
			pairs = append(pairs, schemas.NVPair{Name: k, Value: val})
		}
	}
	return pairs
}

func convertCDPCookies(cookieHeader string) []schemas.Cookie {
	// A simple parser; a more robust one might be needed for complex cases.
	if cookieHeader == "" {
		return []schemas.Cookie{}
	}
	parts := strings.Split(cookieHeader, ";")
	cookies := make([]schemas.Cookie, len(parts))
	for i, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			cookies[i] = schemas.Cookie{Name: kv[0], Value: kv[1]}
		}
	}
	return cookies
}
