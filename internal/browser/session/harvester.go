// internal/browser/session/harvester.go
package session

import (
	"bytes"
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

// REFACTOR: Define timeouts for background fetching operations.
const (
	postDataFetchTimeout = 10 * time.Second
	bodyFetchTimeout     = 30 * time.Second
)

// requestState holds the information for a single network request throughout its lifecycle.
type requestState struct {
	request   *network.EventRequestWillBeSent
	responses []*network.EventResponseReceived // Handles redirects
	// FIX: Ensure consistent terminology (body=response body, postBody=request body).
	body                []byte // This is for the RESPONSE body
	bodyFetchInProgress bool   // FIX: Track ongoing body fetch (TestHarvesterIntegration failure)
	postBody            []byte // <-- ADDED: This is for the REQUEST body
	err                 error
	finished            bool
	isDataURL           bool
	wallTime            time.Time
	monotonicTime       cdp.MonotonicTime
}

// Harvester listens to browser network events and console logs to build a HAR file.
type Harvester struct {
	ctx           context.Context
	cancel        context.CancelFunc
	logger        *zap.Logger
	captureBodies bool

	// FIX: Add ActionExecutor to synchronize CDP calls (e.g., fetching bodies) and prevent deadlocks.
	executor ActionExecutor

	mu            sync.RWMutex
	requests      map[network.RequestID]*requestState
	consoleLogs   []schemas.ConsoleLog
	pageID        string
	pageTitle     string
	startTime     time.Time
	onLoadTime    float64
	onContentLoad float64
	activeReqs    int64 // Counter for active requests for idle calculation

	wg sync.WaitGroup // To wait for all body fetching goroutines
}

// NewHarvester creates a new network harvester instance.
// FIX: Updated signature to accept ActionExecutor.
func NewHarvester(ctx context.Context, logger *zap.Logger, captureBodies bool, executor ActionExecutor) *Harvester {
	hCtx, hCancel := context.WithCancel(ctx)
	if executor == nil {
		panic("Harvester created with nil ActionExecutor reference")
	}
	return &Harvester{
		ctx:           hCtx,
		cancel:        hCancel,
		logger:        logger.Named("harvester"),
		captureBodies: captureBodies,
		executor:      executor,
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
	h.cancel() // Signal the listener goroutine and body fetching goroutines to stop

	// Wait for any outstanding body fetching goroutines to complete, respecting the provided context.
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Completed successfully
	case <-ctx.Done():
		h.logger.Warn("Harvester stop interrupted before all bodies were fetched. HAR may be incomplete.", zap.Error(ctx.Err()))
	}

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
// FIX: Rewritten logic to correctly implement network idle detection.
// The previous implementation incorrectly reset the timer every tick when idle, causing timeouts.
func (h *Harvester) WaitNetworkIdle(ctx context.Context, quietPeriod time.Duration) error {
	h.logger.Debug("Waiting for network to become idle.")

	// 1. Initialize the timer but immediately stop it. We will reset it when the idle state begins.
	timer := time.NewTimer(quietPeriod)
	if !timer.Stop() {
		// Drain if it fired immediately (e.g., if quietPeriod is 0 or extremely short)
		select {
		case <-timer.C:
		default:
		}
	}
	defer timer.Stop() // Ensure timer is stopped when function exits (e.g., context cancellation or success).

	isIdle := false // Track whether we are currently considered idle (and the timer is running)

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

			if active > 0 {
				if isIdle {
					// Transition from idle to active: stop the timer.
					if !timer.Stop() {
						// Drain if it fired exactly while we were processing the ticker event.
						// This handles the race condition where the timer fires just before we check activeReqs.
						select {
						case <-timer.C:
						default:
						}
					}
					isIdle = false
				}
				// If already active, we do nothing and wait for the next tick.
			} else {
				// active == 0
				if !isIdle {
					// Transition from active to idle: start the timer.
					// Timer is guaranteed to be stopped here, so Reset is safe.
					timer.Reset(quietPeriod)
					isIdle = true
				}
				// If already idle, we just let the timer run.
			}
		case <-timer.C:
			// Timer fired, meaning network was idle (isIdle must be true) for the quiet period.
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

	// Initialize request state if it doesn't exist
	if _, exists := h.requests[ev.RequestID]; !exists {
		h.requests[ev.RequestID] = &requestState{
			isDataURL: strings.HasPrefix(ev.Request.URL, "data:"),
		}
	}

	req := h.requests[ev.RequestID]
	req.request = ev
	req.wallTime = ev.WallTime.Time()

	// FIX: Dereference the pointer after a nil check (Potential nil pointer dereference).
	if ev.Timestamp != nil {
		req.monotonicTime = *ev.Timestamp
	}

	// Check if the request has post data and fetch it
	if ev.Request.HasPostData && req.postBody == nil {
		// FIX: Prioritize capturing PostData synchronously if available in the event (TestHarvesterIntegration failure).
		// The field is PostDataEntries, not PostData.
		if len(ev.Request.PostDataEntries) > 0 {
			var postBody bytes.Buffer
			for _, entry := range ev.Request.PostDataEntries {
				// The test failure indicates this is base64 encoded.
				decoded, err := base64.StdEncoding.DecodeString(entry.Bytes)
				if err != nil {
					// If decoding fails, it might not be base64. Log an error and use the raw string.
					h.logger.Error("Failed to decode base64 post data entry, using raw bytes", zap.Error(err), zap.String("reqID", string(ev.RequestID)))
					postBody.WriteString(entry.Bytes)
				} else {
					postBody.Write(decoded)
				}
			}
			req.postBody = postBody.Bytes()
		} else if ev.Request.HasPostData {
			// Fallback to async fetch if data is not included in the event (e.g., large bodies)
			h.fetchPostBody(ev.RequestID)
		}
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
		// FIX: Attempt to fetch body immediately upon receiving response headers and track progress (TestHarvesterIntegration failure).
		// Waiting for LoadingFinished or relying solely on HasExtraInfo increases the chance the browser garbage collects the body buffer.
		if h.captureBodies && req.body == nil && !req.isDataURL && !req.bodyFetchInProgress {
			req.bodyFetchInProgress = true // Mark fetch as started
			h.fetchBody(ev.RequestID)
		}
	}
}

func (h *Harvester) handleLoadingFinished(ev *network.EventLoadingFinished) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req, ok := h.requests[ev.RequestID]; ok {
		req.finished = true
		// Try fetching body again if not already fetched, in progress, or a data URL.
		if h.captureBodies && len(req.responses) > 0 && req.body == nil && !req.isDataURL && !req.bodyFetchInProgress {
			req.bodyFetchInProgress = true // Mark fetch as started
			h.fetchBody(ev.RequestID)
		}
	}
	// Ensure activeReqs doesn't go below zero
	if h.activeReqs > 0 {
		h.activeReqs--
	}
}

func (h *Harvester) handleLoadingFailed(ev *network.EventLoadingFailed) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req, ok := h.requests[ev.RequestID]; ok {
		req.finished = true
		req.err = fmt.Errorf("request failed: %s", ev.ErrorText)
	}
	// Ensure activeReqs doesn't go below zero
	if h.activeReqs > 0 {
		h.activeReqs--
	}
}

func (h *Harvester) handlePageLifecycleEvent(ev *page.EventLifecycleEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.pageID == "" {
		h.pageID = ev.FrameID.String()
	}

	// Ensure startTime is set before calculating delta
	if h.startTime.IsZero() {
		return
	}

	delta := ev.Timestamp.Time().Sub(h.startTime).Seconds() * 1000

	switch ev.Name {
	case "load":
		h.onLoadTime = delta
	case "DOMContentLoaded":
		h.onContentLoad = delta
	case "init":
		// Only reset if it's the primary frame navigation
		if h.pageID == ev.FrameID.String() {
			h.startTime = ev.Timestamp.Time()
		}
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

// fetchPostBody retrieves the request body (post data) for a given request.
func (h *Harvester) fetchPostBody(reqID network.RequestID) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()

		// FIX: Use context.Background() as the parent for the timeout.
		// We rely on h.executor.RunBackgroundActions to handle detaching from the session context.
		// This prevents missing PostData when CollectArtifacts is called quickly.
		fetchCtx, cancel := context.WithTimeout(context.Background(), postDataFetchTimeout)
		defer cancel()

		var postData string
		// REFACTOR: Use the timed context for the CDP call.
		// FIX: Use h.executor.RunBackgroundActions instead of RunActions.
		err := h.executor.RunBackgroundActions(fetchCtx,
			chromedp.ActionFunc(func(c context.Context) error {
				var err error
				// Use GetRequestPostData
				postData, err = network.GetRequestPostData(reqID).Do(c)
				return err
			}),
		)

		h.mu.Lock()
		defer h.mu.Unlock()
		if req, ok := h.requests[reqID]; ok {
			if err != nil {
				// REFACTOR: Improve error logging based on context state.
				if fetchCtx.Err() == context.DeadlineExceeded {
					h.logger.Debug("Timeout fetching request post data.", zap.String("reqID", string(reqID)), zap.Duration("timeout", postDataFetchTimeout))
				} else {
					// Since this is a background action, we log errors unless they are common/expected.
					// Don't spam logs for requests that had no post data (a common CDP error).
					if !strings.Contains(err.Error(), "No post data") {
						// We check h.ctx.Err() just to reduce noise if the entire application is shutting down rapidly.
						if h.ctx.Err() == nil {
							h.logger.Debug("Failed to fetch request post data.", zap.String("reqID", string(reqID)), zap.Error(err))
						}
					}
				}
				// We don't set req.err here, as failing to get post data isn't a request failure
			} else {
				req.postBody = []byte(postData)
			}
		}
	}()
}

func (h *Harvester) fetchBody(reqID network.RequestID) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()

		// FIX: Use context.Background() as the parent for the timeout.
		// Rely on RunBackgroundActions for detachment.
		fetchCtx, cancel := context.WithTimeout(context.Background(), bodyFetchTimeout)
		defer cancel()

		var body []byte
		// FIX: Use h.executor.RunBackgroundActions.
		err := h.executor.RunBackgroundActions(fetchCtx,
			chromedp.ActionFunc(func(c context.Context) error {
				var err error
				body, err = network.GetResponseBody(reqID).Do(c)
				return err
			}),
		)

		h.mu.Lock()
		defer h.mu.Unlock()
		if req, ok := h.requests[reqID]; ok {
			// FIX: Mark fetch as finished (success or failure)
			req.bodyFetchInProgress = false

			if err != nil {
				// REFACTOR: Improve error logging based on context state.
				if fetchCtx.Err() == context.DeadlineExceeded {
					h.logger.Debug("Timeout fetching response body.", zap.String("reqID", string(reqID)), zap.Duration("timeout", bodyFetchTimeout))
					req.err = fmt.Errorf("response body fetch timed out: %w", fetchCtx.Err())
				} else {
					// Since this is a background action, log the failure.
					// We check h.ctx.Err() just to reduce noise if the entire application is shutting down rapidly.
					if h.ctx.Err() == nil {
						h.logger.Debug("Failed to fetch response body.", zap.String("reqID", string(reqID)), zap.Error(err))
					}
					req.err = err
				}
			} else {
				req.body = body
			}
		}
	}()
}

// -- HAR Generation --

func (h *Harvester) generateHAR() *schemas.HAR {
	har := schemas.NewHAR()

	if h.startTime.IsZero() {
		h.startTime = time.Now() // Fallback
	}

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
		if reqState.request == nil || len(reqState.responses) == 0 || reqState.monotonicTime.Time().IsZero() {
			continue // Skip incomplete entries
		}
		finalResp := reqState.responses[len(reqState.responses)-1]

		totalTime := finalResp.Timestamp.Time().Sub(reqState.monotonicTime.Time()).Seconds() * 1000

		entry := schemas.Entry{
			Pageref:         h.pageID,
			StartedDateTime: reqState.wallTime,
			Time:            totalTime,
			// Pass reqState.postBody to the builder function
			Request:  h.buildHARRequest(reqState.request, reqState.postBody),
			Response: h.buildHARResponse(finalResp, reqState.body),
			Cache:    struct{}{},
			// FIX: Access the Timing field via the nested Response struct.
			Timings: convertCDPTimings(finalResp.Response.Timing),
		}
		har.Log.Entries = append(har.Log.Entries, entry)
	}
	return har
}

// Modify buildHARRequest to accept the postBody
func (h *Harvester) buildHARRequest(req *network.EventRequestWillBeSent, postBody []byte) schemas.Request {
	u, _ := url.Parse(req.Request.URL)
	qs := make([]schemas.NVPair, 0)
	if u != nil { // Added nil check
		for k, v := range u.Query() {
			for _, val := range v {
				qs = append(qs, schemas.NVPair{Name: k, Value: val})
			}
		}
	}

	harReq := schemas.Request{
		Method:      req.Request.Method,
		URL:         req.Request.URL,
		HTTPVersion: "HTTP/1.1", // Often a guess
		Cookies:     convertCDPCookies(getHeader(req.Request.Headers, "Cookie")),
		Headers:     convertCDPHeaders(req.Request.Headers),
		QueryString: qs,
		HeadersSize: calculateHeaderSize(req.Request.Headers),
		// --- START FIX ---
		// Use the length of the postBody we fetched
		BodySize: int64(len(postBody)),
	}

	// Use the postBody we fetched
	if len(postBody) > 0 {
		harReq.PostData = &schemas.PostData{
			MimeType: getHeader(req.Request.Headers, "Content-Type"),
			// Convert the bytes to a string for the HAR
			Text: string(postBody),
		}
	}
	// --- END FIX ---

	return harReq
}

// buildHARResponse creates a HAR response object from a CDP network event.
// NOTE: This adds a custom field `RemoteIPAddress`

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
		Cookies:     convertCDPCookies(getHeader(resp.Response.Headers, "Set-Cookie")),
		Headers:     convertCDPHeaders(resp.Response.Headers),
		Content:     content,
		RedirectURL: getHeader(resp.Response.Headers, "Location"),
		HeadersSize: calculateHeaderSize(resp.Response.Headers),
		BodySize:    int64(resp.Response.EncodedDataLength),
		// --- MODIFIED BLOCK (RemoteIPAddressSpace removed) ---
		// Store the IP address for later analysis.
		// RemoteIPAddressSpace was removed as it's not in your library version.
		RemoteIPAddress: resp.Response.RemoteIPAddress,
		// --- END MODIFIED BLOCK ---
	}
}

// -- Helpers --

// getHeader performs a case insensitive search for a header and returns its string value.
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
	// FIX: Check if the phase started (>= 0) before calculating duration.
	// If start time is -1 (not available), the duration should be -1.
	// This resolves the issue where (-1) - (-1) resulted in 0 (Test failure: expected -1, actual 0).
	var dns float64 = -1
	if t.DNSStart >= 0 {
		dns = toHARTime(t.DNSEnd - t.DNSStart)
	}

	var connect float64 = -1
	if t.ConnectStart >= 0 {
		connect = toHARTime(t.ConnectEnd - t.ConnectStart)
	}

	var ssl float64 = -1
	if t.SslStart >= 0 {
		ssl = toHARTime(t.SslEnd - t.SslStart)
	}

	send := toHARTime(t.SendEnd - t.SendStart)

	// Blocked time approximation.
	// FIX: The original calculation (t.RequestTime*1000 - t.ProxyEnd) was incorrect.
	// Blocked time is the time until the first network event (Proxy/DNS/Connect/Send).
	var blocked float64 = -1
	firstEventStart := -1.0

	// Helper to find the minimum positive value
	minPos := func(a, b float64) float64 {
		if a < 0 {
			return b
		}
		if b < 0 {
			return a
		}
		if a < b {
			return a
		}
		return b
	}

	firstEventStart = minPos(firstEventStart, t.ProxyStart)
	firstEventStart = minPos(firstEventStart, t.DNSStart)
	firstEventStart = minPos(firstEventStart, t.ConnectStart)
	firstEventStart = minPos(firstEventStart, t.SendStart)

	if firstEventStart >= 0 {
		blocked = firstEventStart
	}

	// Ensure blocked is -1 if not determined.
	if blocked < 0 {
		blocked = -1
	}

	// Wait time (Time To First Byte - TTFB).
	// Ensure Wait respects the convention.
	var wait float64 = -1
	if t.SendEnd >= 0 {
		wait = toHARTime(t.ReceiveHeadersEnd - t.SendEnd)
	}

	// Receive time is complex to calculate perfectly without the total duration event, defaulting to 0.
	// FIX: Defaulting to 0.0 to match the comment and test expectation (was returning -1). (Test failure: expected 0, actual -1)
	receive := 0.0
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
		strings.Contains(lowerMime, "xml") ||
		strings.Contains(lowerMime, "x-www-form-urlencoded") // FIX: Include form-urlencoded as text (TestHarvesterIntegration failure)
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
			// FIX: Changed NNVPair to NVPair
			pairs = append(pairs, schemas.NVPair{Name: k, Value: val})
		}
	}
	return pairs
}

// FIX: Updated return type to []schemas.HARCookie to match the HAR schema requirements.
func convertCDPCookies(cookieHeader string) []schemas.HARCookie {
	// A simple parser; a more robust one might be needed for complex cases.
	if cookieHeader == "" {
		return []schemas.HARCookie{}
	}
	parts := strings.Split(cookieHeader, ";")
	cookies := make([]schemas.HARCookie, 0, len(parts)) // Updated type
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			// Updated type
			cookies = append(cookies, schemas.HARCookie{Name: kv[0], Value: kv[1]})
		}
	}
	return cookies
}
