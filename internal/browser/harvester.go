package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/har"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// Harvester is responsible for actively collecting data artifacts (Network traffic, Console logs)
// during a browser session by listening to CDP events.
type Harvester struct {
	logger     *zap.Logger
	sessionCtx context.Context

	captureBodies bool
	maxBodySize   int64

	// Synchronization and data storage.
	mu              sync.Mutex
	consoleLogs     []schemas.ConsoleLog
	pageLoadEvent   *page.EventLoadEventFired
	domContentEvent *page.EventDomContentEventFired

	// Map to track the lifecycle of network requests.
	requests map[network.RequestID]*requestData
}

// requestData stores information about a network request during its lifecycle.
type requestData struct {
	RequestID network.RequestID
	// Raw CDP events
	requestSent     *network.EventRequestWillBeSent
	responseReceived *network.EventResponseReceived
	loadingFinished *network.EventLoadingFinished
	loadingFailed   *network.EventLoadingFailed

	// Body content
	bodyContent   []byte
	bodyIsBase64  bool
	bodyFetchDone bool
}

// NewHarvester creates a new Harvester instance for a specific session.
func NewHarvester(sessionCtx context.Context, logger *zap.Logger, captureBodies bool) *Harvester {
	return &Harvester{
		logger:        logger.With(zap.String("component", "Harvester")),
		sessionCtx:    sessionCtx,
		captureBodies: captureBodies,
		maxBodySize:   5 * 1024 * 1024, // 5MB default limit for bodies
		requests:      make(map[network.RequestID]*requestData),
		consoleLogs:   make([]schemas.ConsoleLog, 0, 128),
	}
}

// Start begins listening to CDP events on the session context.
func (h *Harvester) Start() {
	h.logger.Debug("Harvester starting event listeners.")

	// Register the event listener function with the chromedp context.
	chromedp.ListenTarget(h.sessionCtx, h.eventListener)

	// Enable necessary CDP domains.
	err := chromedp.Run(h.sessionCtx,
		network.Enable(),
		page.Enable(),
		runtime.Enable(), // For console logs and exceptions
	)
	if err != nil {
		h.logger.Error("Failed to enable necessary CDP domains for harvesting.", zap.Error(err))
	}
}

// Stop processes the collected data into a HAR file and console logs.
func (h *Harvester) Stop(ctx context.Context) (*har.HAR, []schemas.ConsoleLog) {
	h.logger.Debug("Harvester stopping.")

	// Fetch bodies for requests that finished.
	if h.captureBodies {
		h.fetchBodies(ctx)
	}

	// Process events into HAR.
	h.logger.Debug("Generating HAR file.")
	harData := h.generateHAR()

	h.mu.Lock()
	// Create a copy of the logs slice.
	logs := make([]schemas.ConsoleLog, len(h.consoleLogs))
	copy(logs, h.consoleLogs)
	h.mu.Unlock()

	return harData, logs
}

// eventListener is the central handler for all CDP events.
func (h *Harvester) eventListener(ev interface{}) {
	// Protect access to the data structures.
	h.mu.Lock()
	defer h.mu.Unlock()

	// Dispatch event based on type.
	switch e := ev.(type) {
	// --- Network Events ---
	case *network.EventRequestWillBeSent:
		h.handleRequestWillBeSent(e)
	case *network.EventResponseReceived:
		h.handleResponseReceived(e)
	case *network.EventLoadingFinished:
		h.handleLoadingFinished(e)
	case *network.EventLoadingFailed:
		h.handleLoadingFailed(e)

	// --- Page Events (for HAR timings) ---
	case *page.EventLoadEventFired:
		h.pageLoadEvent = e
	case *page.EventDomContentEventFired:
		h.domContentEvent = e

	// --- Runtime/Console Events ---
	case *runtime.EventConsoleAPICalled:
		h.handleConsoleAPICalled(e)
	case *runtime.EventExceptionThrown:
		h.handleExceptionThrown(e)
	}
}

// --- Network Event Handlers (Must be called under h.mu lock) ---

func (h *Harvester) handleRequestWillBeSent(e *network.EventRequestWillBeSent) {
	// Handle redirects: The new request reuses the RequestID.
	if rd, exists := h.requests[e.RequestID]; exists {
		// If it's a redirect, finalize the previous request data.
		if e.RedirectResponse != nil {
			rd.responseReceived = &network.EventResponseReceived{
				RequestID: e.RequestID,
				Response:  e.RedirectResponse,
				Timestamp: e.Timestamp,
			}
			rd.loadingFinished = &network.EventLoadingFinished{
				RequestID: e.RequestID,
				Timestamp: e.Timestamp,
			}
			rd.bodyFetchDone = true // Redirects don't have bodies to fetch.
		}
	}

	// Initialize tracking for the new request (or the redirected request).
	h.requests[e.RequestID] = &requestData{
		RequestID:   e.RequestID,
		requestSent: e,
	}
}

func (h *Harvester) handleResponseReceived(e *network.EventResponseReceived) {
	if rd, exists := h.requests[e.RequestID]; exists {
		rd.responseReceived = e
	}
}

func (h *Harvester) handleLoadingFinished(e *network.EventLoadingFinished) {
	if rd, exists := h.requests[e.RequestID]; exists {
		rd.loadingFinished = e
	}
}

func (h *Harvester) handleLoadingFailed(e *network.EventLoadingFailed) {
	if rd, exists := h.requests[e.RequestID]; exists {
		rd.loadingFailed = e
		rd.bodyFetchDone = true // Cannot fetch body if loading failed.
	}
}

// --- Console Event Handlers (Must be called under h.mu lock) ---

func (h *Harvester) handleConsoleAPICalled(e *runtime.EventConsoleAPICalled) {
	logEntry := schemas.ConsoleLog{
		Timestamp: e.Timestamp.Time(),
		Level:     string(e.Type),
		Source:    "console-api",
		Text:      h.formatConsoleArgs(e.Args),
	}
	// Add stack trace if available.
	if e.StackTrace != nil && len(e.StackTrace.CallFrames) > 0 {
		frame := e.StackTrace.CallFrames[0]
		logEntry.URL = frame.URL
		logEntry.Line = int64(frame.LineNumber)
	}
	h.consoleLogs = append(h.consoleLogs, logEntry)
}

func (h *Harvester) handleExceptionThrown(e *runtime.EventExceptionThrown) {
	details := e.ExceptionDetails
	text := details.Text
	if details.Exception != nil && details.Exception.Description != "" {
		text = details.Exception.Description
	}

	logEntry := schemas.ConsoleLog{
		Timestamp: e.Timestamp.Time(),
		Level:     "error",
		Source:    "javascript",
		Text:      text,
		URL:       details.URL,
		Line:      details.LineNumber,
	}
	h.consoleLogs = append(h.consoleLogs, logEntry)
}

func (h *Harvester) formatConsoleArgs(args []*runtime.RemoteObject) string {
	var parts []string
	for _, arg := range args {
		if arg.Value != nil {
			// arg.Value is json.RawMessage ([]byte).
			// Attempt to unmarshal simple values for readability.
			var val interface{}
			if err := json.Unmarshal(arg.Value, &val); err == nil {
				parts = append(parts, fmt.Sprintf("%v", val))
			} else {
				parts = append(parts, string(arg.Value))
			}
		} else if arg.Description != "" {
			parts = append(parts, arg.Description)
		} else {
			parts = append(parts, fmt.Sprintf("<%s>", arg.Type))
		}
	}
	return strings.Join(parts, " ")
}

// --- Body Fetching ---

// fetchBodies retrieves the response bodies for captured requests concurrently.
func (h *Harvester) fetchBodies(ctx context.Context) {
	h.mu.Lock()
	// Create a snapshot of requests that need fetching.
	var requestsToFetch []*requestData
	for _, rd := range h.requests {
		if rd.responseReceived == nil || rd.loadingFinished == nil || rd.bodyFetchDone {
			continue
		}
		// Check size limit.
		if rd.loadingFinished.EncodedDataLength > h.maxBodySize {
			h.logger.Debug("Skipping body fetch due to size limit.", zap.Int64("size", rd.loadingFinished.EncodedDataLength))
			rd.bodyFetchDone = true
			continue
		}
		requestsToFetch = append(requestsToFetch, rd)
	}
	h.mu.Unlock()

	if len(requestsToFetch) == 0 {
		return
	}

	// Concurrency management.
	var wg sync.WaitGroup
	concurrencyLimit := 10
	sem := make(chan struct{}, concurrencyLimit)

	// Get the executor associated with the session context.
	executor := chromedp.FromContext(h.sessionCtx)
	if executor == nil {
		h.logger.Warn("Could not get executor from session context. Cannot fetch response bodies.")
		return
	}

	for _, rd := range requestsToFetch {
		wg.Add(1)
		sem <- struct{}{}
		go func(data *requestData) {
			defer wg.Done()
			defer func() { <-sem }()

			// Use a timeout for individual fetch, respecting the overall Stop context.
			fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var body []byte
			var base64Encoded bool

			// Execute the CDP command using the specific executor.
			err := chromedp.Run(chromedp.WithExecutor(fetchCtx, executor), chromedp.ActionFunc(func(c context.Context) error {
				var err error
				body, base64Encoded, err = network.GetResponseBody(data.RequestID).Do(c)
				return err
			}))

			h.mu.Lock()
			defer h.mu.Unlock()

			data.bodyFetchDone = true

			if err != nil {
				// Log error if it wasn't just a context cancellation during shutdown.
				if fetchCtx.Err() == nil && ctx.Err() == nil {
					h.logger.Debug("Failed to get response body", zap.String("request_id", string(data.RequestID)), zap.Error(err))
				}
				return
			}

			data.bodyContent = body
			data.bodyIsBase64 = base64Encoded
		}(rd)
	}
	wg.Wait()
}

// --- HAR Generation ---

// generateHAR constructs the HAR structure from the collected request data.
func (h *Harvester) generateHAR() *har.HAR {
	h.mu.Lock()
	defer h.mu.Unlock()

	entries := make([]*har.Entry, 0, len(h.requests))
	var earliestTime cdp.TimeSinceEpoch

	for _, rd := range h.requests {
		entry := h.processRequestDataToEntry(rd)
		if entry != nil {
			entries = append(entries, entry)
			// Track the earliest start time for the page definition.
			if earliestTime.Time().IsZero() || rd.requestSent.WallTime.Time().Before(earliestTime.Time()) {
				earliestTime = rd.requestSent.WallTime
			}
		}
	}

	if earliestTime.Time().IsZero() {
		// No requests captured.
		return &har.HAR{Log: &har.Log{Version: "1.2", Entries: entries}}
	}

	// Sort entries by start time (required by HAR spec).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].StartedDateTime < entries[j].StartedDateTime
	})

	// Calculate page timings relative to the earliest request.
	var onContentLoad, onLoad float64
	if h.domContentEvent != nil {
		onContentLoad = float64(h.domContentEvent.Timestamp.Time().Sub(earliestTime.Time()).Milliseconds())
	}
	if h.pageLoadEvent != nil {
		onLoad = float64(h.pageLoadEvent.Timestamp.Time().Sub(earliestTime.Time()).Milliseconds())
	}

	return &har.HAR{
		Log: &har.Log{
			Version: "1.2",
			Creator: &har.Creator{
				Name:    "Scalpel-CLI Harvester",
				Version: "0.1",
			},
			Pages: []*har.Page{
				{
					StartedDateTime: earliestTime.Time().Format(time.RFC3339Nano),
					ID:              "page_1",
					Title:           "Analysis Session",
					PageTimings: &har.PageTimings{
						OnContentLoad: onContentLoad,
						OnLoad:        onLoad,
					},
				},
			},
			Entries: entries,
		},
	}
}

func (h *Harvester) processRequestDataToEntry(rd *requestData) *har.Entry {
	if rd.requestSent == nil || rd.requestSent.Request == nil {
		return nil
	}

	req := rd.requestSent.Request
	entry := &har.Entry{
		Pageref:         "page_1", // Simplified: assuming single page context.
		StartedDateTime: rd.requestSent.WallTime.Time().Format(time.RFC3339Nano),
		Request:         h.buildHarRequest(req),
		Response:        &har.Response{}, // Initialize response
		Cache:           &har.Cache{},
		Timings:         &har.Timings{},
	}

	// Process Response details.
	if rd.responseReceived != nil {
		h.updateEntryWithResponse(entry, rd.responseReceived.Response, rd)
	}

	// Process completion details (Finished or Failed).
	var endTime cdp.TimeSinceEpoch
	if rd.loadingFinished != nil {
		endTime = rd.loadingFinished.Timestamp
		if entry.Response != nil {
			entry.Response.BodySize = rd.loadingFinished.EncodedDataLength
		}
	} else if rd.loadingFailed != nil {
		endTime = rd.loadingFailed.Timestamp
		// Handle failure status if no response was received.
		if rd.responseReceived == nil {
			entry.Response.Status = 0 // Indicates failure (e.g., CORS, network error)
			entry.Response.StatusText = rd.loadingFailed.ErrorText
			if rd.loadingFailed.BlockedReason != "" {
				entry.Response.Comment = fmt.Sprintf("Blocked: %s", rd.loadingFailed.BlockedReason)
			}
		}
	}

	// Calculate total duration (Time).
	if !endTime.Time().IsZero() {
		duration := endTime.Time().Sub(rd.requestSent.WallTime.Time()).Milliseconds()
		if duration > 0 {
			entry.Time = float64(duration)
		}
	}

	// Finalize Timings (Receive time).
	h.finalizeTimings(entry)

	return entry
}

func (h *Harvester) updateEntryWithResponse(entry *har.Entry, resp *network.Response, rd *requestData) {
	entry.Response.Status = resp.Status
	entry.Response.StatusText = resp.StatusText
	entry.Response.HTTPVersion = resp.Protocol
	entry.Response.Headers = headersToHAR(resp.Headers)
	entry.Response.RedirectURL = resp.Headers.Get("Location")
	entry.Response.HeadersSize = resp.HeadersSize
	entry.Response.BodySize = resp.EncodedDataLength // Initial estimate

	// Update Request HTTP version if available now.
	if entry.Request.HTTPVersion == "unknown" {
		entry.Request.HTTPVersion = resp.Protocol
	}

	// Handle Content and Body fetching results.
	content := &har.Content{
		Size:     0,
		MimeType: resp.MimeType,
	}
	if rd.bodyFetchDone {
		if rd.bodyContent != nil {
			content.Size = int64(len(rd.bodyContent))
			if rd.bodyIsBase64 {
				// If CDP provided raw bytes for binary data, encode them for the HAR JSON.
				content.Text = base64.StdEncoding.EncodeToString(rd.bodyContent)
				content.Encoding = "base64"
			} else {
				content.Text = string(rd.bodyContent)
			}
		} else if h.captureBodies {
			content.Comment = "Failed to fetch body or body was empty."
		}
	}
	entry.Response.Content = content

	// Calculate detailed timings if available.
	if resp.Timing != nil {
		t := resp.Timing
		// CDP timings are in milliseconds relative to resource fetch start (RequestTime).

		// Helper to calculate duration, ensuring non-negative results.
		calcDuration := func(start, end float64) float64 {
			if start >= 0 && end >= start {
				return (end - start)
			}
			return -1 // HAR spec uses -1 for unavailable timings.
		}

		entry.Timings.DNS = calcDuration(t.DNSStart, t.DNSEnd)
		entry.Timings.Connect = calcDuration(t.ConnectStart, t.ConnectEnd)
		entry.Timings.Ssl = calcDuration(t.SslStart, t.SslEnd)
		entry.Timings.Send = calcDuration(t.SendStart, t.SendEnd)
		// Wait (TTFB) is time from SendEnd to ReceiveHeadersEnd.
		entry.Timings.Wait = calcDuration(t.SendEnd, t.ReceiveHeadersEnd)
		
		// Blocked time requires complex analysis, setting placeholder.
		entry.Timings.Blocked = t.PushStart
		if entry.Timings.Blocked <= 0 {
			entry.Timings.Blocked = -1
		}
	}
}

func (h *Harvester) finalizeTimings(entry *har.Entry) {
	if entry.Time > 0 && entry.Timings != nil {
		// Calculate Receive time (Total time - time spent before receiving data).
		timingsSum := 0.0
		// Helper to sum positive timings.
		addTiming := func(t float64) {
			if t > 0 {
				timingsSum += t
			}
		}
		addTiming(entry.Timings.Blocked)
		addTiming(entry.Timings.DNS)
		addTiming(entry.Timings.Connect) // Includes SSL time
		addTiming(entry.Timings.Send)
		addTiming(entry.Timings.Wait)

		if receiveTime := entry.Time - timingsSum; receiveTime > 0 {
			entry.Timings.Receive = receiveTime
		} else {
			entry.Timings.Receive = 0
		}
	}
}


func (h *Harvester) buildHarRequest(req *network.Request) *har.Request {
	harReq := &har.Request{
		Method:      req.Method,
		URL:         req.URL,
		HTTPVersion: "unknown", // Default, updated later if response is received.
		Cookies:     []*har.Cookie{},
		Headers:     headersToHAR(req.Headers),
		QueryString: []*har.NameValuePair{},
		HeadersSize: -1,
		BodySize:    -1,
	}

	if req.PostData != "" {
		contentType := req.Headers.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		harReq.PostData = &har.PostData{
			MimeType: contentType,
			Text:     req.PostData,
		}
		harReq.BodySize = int64(len(req.PostData))
	}
	return harReq
}

// headersToHAR converts network.Headers (map[string]interface{}) to HAR NameValuePair slice.
func headersToHAR(headers network.Headers) []*har.NameValuePair {
	var result []*har.NameValuePair
	for k, vInterface := range headers {
		// CDP Headers values can be strings or arrays of strings (e.g., multiple Set-Cookie headers).
		if valStr, ok := vInterface.(string); ok {
			result = append(result, &har.NameValuePair{Name: k, Value: valStr})
		} else if valSlice, ok := vInterface.([]interface{}); ok {
			for _, val := range valSlice {
				if s, ok := val.(string); ok {
					result = append(result, &har.NameValuePair{Name: k, Value: s})
				} else {
					// Fallback for non-string values
					result = append(result, &har.NameValuePair{Name: k, Value: fmt.Sprintf("%v", val)})
				}
			}
		} else {
			// Fallback for other types
			result = append(result, &har.NameValuePair{Name: k, Value: fmt.Sprintf("%v", vInterface)})
		}
	}
	return result
}