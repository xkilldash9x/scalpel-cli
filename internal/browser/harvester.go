// Package browser provides the tools to interact with and gather data from a headless browser instance.
package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// requestState tracks the lifecycle of a network request.
type requestState struct {
	Request       *network.Request
	Response      *network.Response
	StartTS       *cdp.TimeSinceEpoch // Wall time for HAR StartedDateTime
	StartMonoTS   *cdp.MonotonicTime   // Monotonic time for accurate duration calculation
	EndTS         *cdp.MonotonicTime
	ResponseReady chan struct{} // Signals when response headers are received
	Body          []byte
	IsComplete    bool
}

// Harvester listens to browser events, collecting network traffic,
// console logs, and exceptions to build a comprehensive record.
type Harvester struct {
	logger        *zap.Logger
	captureBodies bool
	sessionCtx    context.Context

	// listenerCtx controls the lifecycle of the main listener goroutine.
	// It is a child of sessionCtx.
	listenerCtx    context.Context
	cancelListener context.CancelFunc

	requests         map[network.RequestID]*requestState
	inflightRequests map[network.RequestID]bool
	consoleLogs      []schemas.ConsoleLog
	lock             sync.RWMutex
	bodyFetchWG      sync.WaitGroup
	isStarted        bool
}

// NewHarvester creates a new artifact harvester for a given session.
func NewHarvester(sessionCtx context.Context, logger *zap.Logger, captureBodies bool) *Harvester {
	return &Harvester{
		sessionCtx:       sessionCtx,
		logger:           logger.Named("harvester"),
		captureBodies:    captureBodies,
		requests:         make(map[network.RequestID]*requestState),
		inflightRequests: make(map[network.RequestID]bool),
		consoleLogs:      make([]schemas.ConsoleLog, 0),
	}
}

// Start initiates the event listening process.
func (h *Harvester) Start() error {
	h.lock.Lock()
	defer h.lock.Unlock()

	if h.isStarted {
		return nil
	}

	h.listenerCtx, h.cancelListener = context.WithCancel(h.sessionCtx)
	go h.listen()

	err := chromedp.Run(h.sessionCtx,
		network.Enable(),
		runtime.Enable(),
		log.Enable(),
	)

	if err != nil {
		// If the session context is already done, this error is expected.
		if h.sessionCtx.Err() != nil {
			return nil
		}
		h.cancelListener() // Clean up if enabling domains fails.
		return err
	}

	h.isStarted = true
	h.logger.Debug("Harvester started and is listening for events.")
	return nil
}

// listen is the main event loop that processes CDP events.
func (h *Harvester) listen() {
	chromedp.ListenTarget(h.listenerCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			h.handleRequestWillBeSent(e)
		case *network.EventResponseReceived:
			h.handleResponseReceived(e)
		case *network.EventLoadingFinished:
			h.handleLoadingFinished(e)
		case *network.EventLoadingFailed:
			h.handleLoadingFailed(e)
		case *runtime.EventConsoleAPICalled:
			h.handleConsoleAPICalled(e)
		case *log.EventEntryAdded:
			h.handleLogEntryAdded(e)
		case *runtime.EventExceptionThrown:
			h.handleExceptionThrown(e)
		}
	})
}

// Stop halts event collection, waits for any pending operations to complete,
// and returns the collected artifacts.
func (h *Harvester) Stop(ctx context.Context) (*schemas.HAR, []schemas.ConsoleLog) {
	h.lock.Lock()
	if !h.isStarted {
		h.lock.Unlock()
		return h.generateHAR(), h.getConsoleLogs()
	}

	if h.cancelListener != nil {
		h.cancelListener()
	}
	h.isStarted = false
	h.lock.Unlock()

	h.logger.Debug("Harvester stopped. Waiting for pending body fetches to complete.")

	// It is crucial to wait here to ensure all asynchronous body fetches have
	// completed or timed out before generating the HAR file. This prevents data loss.
	h.waitForPendingFetches(ctx)

	return h.generateHAR(), h.getConsoleLogs()
}

// WaitNetworkIdle polls until there are no in flight network requests for a specified duration.
func (h *Harvester) WaitNetworkIdle(ctx context.Context, quietPeriod time.Duration) error {
	ticker := time.NewTicker(quietPeriod / 2)
	defer ticker.Stop()

	lastActivity := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			h.lock.RLock()
			inflightCount := len(h.inflightRequests)
			h.lock.RUnlock()

			if inflightCount > 0 {
				lastActivity = time.Now()
			} else if time.Since(lastActivity) >= quietPeriod {
				return nil
			}
		}
	}
}

// -- Event Handlers --

func (h *Harvester) handleRequestWillBeSent(e *network.EventRequestWillBeSent) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.inflightRequests[e.RequestID] = true

	if e.RedirectResponse != nil {
		if prevState, ok := h.requests[e.RequestID]; ok && !prevState.IsComplete {
			prevState.Response = e.RedirectResponse
			prevState.IsComplete = true
			prevState.EndTS = e.Timestamp
			close(prevState.ResponseReady)
		}
	}

	h.requests[e.RequestID] = &requestState{
		Request:       e.Request,
		StartTS:       e.WallTime,
		StartMonoTS:   e.Timestamp,
		ResponseReady: make(chan struct{}),
	}
}

func (h *Harvester) handleResponseReceived(e *network.EventResponseReceived) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if state, ok := h.requests[e.RequestID]; ok {
		state.Response = e.Response
		// Signal that headers are received, unblocking any pending body fetch.
		close(state.ResponseReady)
	}
}

func (h *Harvester) handleLoadingFinished(e *network.EventLoadingFinished) {
	h.lock.Lock()
	delete(h.inflightRequests, e.RequestID)

	state, ok := h.requests[e.RequestID]
	if !ok {
		h.lock.Unlock()
		return
	}

	state.EndTS = e.Timestamp
	state.IsComplete = true

	if h.captureBodies && h.shouldCaptureBody(state.Response) {
		h.bodyFetchWG.Add(1)
		h.lock.Unlock()
		go h.fetchBody(e.RequestID)
	} else {
		h.lock.Unlock()
	}
}

func (h *Harvester) handleLoadingFailed(e *network.EventLoadingFailed) {
	h.lock.Lock()
	defer h.lock.Unlock()

	delete(h.inflightRequests, e.RequestID)

	if state, ok := h.requests[e.RequestID]; ok {
		state.EndTS = e.Timestamp
		state.IsComplete = true
		select {
		case <-state.ResponseReady:
		default:
			close(state.ResponseReady)
		}
	}
}

// -- Console and Log Handlers --

func (h *Harvester) handleConsoleAPICalled(e *runtime.EventConsoleAPICalled) {
	var textBuilder strings.Builder
	for i, arg := range e.Args {
		if i > 0 {
			textBuilder.WriteString(" ")
		}
		var val interface{}
		if arg.Value != nil && json.Unmarshal(arg.Value, &val) == nil {
			textBuilder.WriteString(fmt.Sprintf("%v", val))
		} else if arg.Description != "" {
			textBuilder.WriteString(arg.Description)
		} else {
			textBuilder.WriteString(fmt.Sprintf("[%s]", arg.Type))
		}
	}

	logEntry := schemas.ConsoleLog{
		Timestamp: e.Timestamp.Time(),
		Type:      string(e.Type),
		Text:      textBuilder.String(),
		Source:    "console-api",
	}

	h.lock.Lock()
	h.consoleLogs = append(h.consoleLogs, logEntry)
	h.lock.Unlock()
}

func (h *Harvester) handleLogEntryAdded(e *log.EventEntryAdded) {
	if e.Entry == nil {
		return
	}
	logEntry := schemas.ConsoleLog{
		Type:      string(e.Entry.Level),
		Text:      e.Entry.Text,
		Timestamp: e.Entry.Timestamp.Time(),
		Source:    string(e.Entry.Source),
	}
	h.lock.Lock()
	h.consoleLogs = append(h.consoleLogs, logEntry)
	h.lock.Unlock()
}

func (h *Harvester) handleExceptionThrown(e *runtime.EventExceptionThrown) {
	if e.ExceptionDetails == nil {
		return
	}
	text := e.ExceptionDetails.Text
	if e.ExceptionDetails.Exception != nil && e.ExceptionDetails.Exception.Description != "" {
		text = e.ExceptionDetails.Exception.Description
	}

	logEntry := schemas.ConsoleLog{
		Type:      "exception",
		Text:      text,
		Timestamp: e.Timestamp.Time(),
		Source:    "runtime",
	}
	h.lock.Lock()
	h.consoleLogs = append(h.consoleLogs, logEntry)
	h.lock.Unlock()
}

// -- Body Fetching Logic --

func (h *Harvester) shouldCaptureBody(response *network.Response) bool {
	if response == nil {
		return false
	}
	return isTextMime(response.MimeType)
}

// fetchBody retrieves a response body in a detached goroutine.
func (h *Harvester) fetchBody(requestID network.RequestID) {
	defer h.bodyFetchWG.Done()

	// This is a critical pattern. The body fetch operation must be able to outlive
	// the context of the navigation that triggered it. We create a "detached" context
	// using valueOnlyContext, which inherits values (like the CDP target) but not
	// the cancellation signal. We then apply our own timeout to this detached context.
	ctx, cancel := context.WithTimeout(valueOnlyContext{h.sessionCtx}, 15*time.Second)
	defer cancel()

	h.lock.RLock()
	state, ok := h.requests[requestID]
	h.lock.RUnlock()

	if !ok {
		return
	}

	select {
	case <-state.ResponseReady:
	case <-ctx.Done():
		return
	}

	body, err := network.GetResponseBody(requestID).Do(ctx)
	if err != nil {
		// Suppress logging if the error is due to an expected cancellation.
		if h.sessionCtx.Err() != nil || ctx.Err() != nil {
			return
		}
		h.logger.Warn("Failed to fetch response body", zap.String("request_id", string(requestID)), zap.Error(err))
		return
	}

	h.lock.Lock()
	if state, ok := h.requests[requestID]; ok {
		state.Body = body
	}
	h.lock.Unlock()
}

func (h *Harvester) waitForPendingFetches(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		h.bodyFetchWG.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		h.logger.Warn("Timed out waiting for all response bodies to be fetched.", zap.Error(ctx.Err()))
	}
}

// -- Artifact Accessors and HAR Generation --

func (h *Harvester) getConsoleLogs() []schemas.ConsoleLog {
	h.lock.RLock()
	defer h.lock.RUnlock()
	logs := make([]schemas.ConsoleLog, len(h.consoleLogs))
	copy(logs, h.consoleLogs)
	return logs
}

func (h *Harvester) generateHAR() *schemas.HAR {
	h.lock.RLock()
	defer h.lock.RUnlock()

	entries := make([]schemas.Entry, 0, len(h.requests))
	for _, state := range h.requests {
		if !state.IsComplete || state.Request == nil || state.StartTS == nil {
			continue
		}

		startTime := state.StartTS.Time()
		var duration float64

		if state.StartMonoTS != nil && state.EndTS != nil {
			duration = state.EndTS.Time().Sub(state.StartMonoTS.Time()).Seconds() * 1000
			if duration < 0 {
				duration = 0
			}
		}

		entry := schemas.Entry{
			StartedDateTime: startTime,
			Time:            duration,
			Request:         h.convertRequest(state.Request),
			Response:        h.convertResponse(state.Response, state.Body),
		}
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].StartedDateTime.Before(entries[j].StartedDateTime)
	})

	return &schemas.HAR{
		Log: schemas.HARLog{
			Version: "1.2",
			Creator: schemas.Creator{Name: "Scalpel CLI Harvester", Version: "0.1.0"},
			Entries: entries,
		},
	}
}

// -- Conversion Helpers --

func (h *Harvester) convertRequest(req *network.Request) schemas.Request {
	headers := convertHeaders(req.Headers)
	queryString := convertQueryString(req.URL)

	var postData *schemas.PostData
	bodySize := int64(-1)

	// FINAL FIX: The `network.Request` struct does not have a `PostData` field.
	// The post body must be constructed from the `PostDataEntries` slice.
	// This logic now correctly reads from the available fields.
	if req.HasPostData && req.PostDataEntries != nil && len(req.PostDataEntries) > 0 {
		var postDataTextBuilder strings.Builder
		for _, entry := range req.PostDataEntries {
			if entry.Bytes != "" {
				postDataTextBuilder.WriteString(entry.Bytes)
			}
		}
		postDataText := postDataTextBuilder.String()

		if postDataText != "" {
			bodySize = int64(len(postDataText))
			postData = &schemas.PostData{
				MimeType: getHeader(req.Headers, "Content-Type"),
				Text:     postDataText,
			}
		}
	}

	return schemas.Request{
		Method:      req.Method,
		URL:         req.URL,
		HTTPVersion: "HTTP/1.1",
		Headers:     headers,
		QueryString: queryString,
		PostData:    postData,
		BodySize:    bodySize,
		HeadersSize: calculateHeaderSize(headers),
	}
}

func (h *Harvester) convertResponse(resp *network.Response, body []byte) schemas.Response {
	if resp == nil {
		return schemas.Response{Status: 0, StatusText: "Failed (No Response)", BodySize: -1, HeadersSize: -1}
	}

	headers := convertHeaders(resp.Headers)
	content := schemas.Content{
		Size:     int64(len(body)),
		MimeType: resp.MimeType,
	}

	if len(body) > 0 {
		if isTextMime(resp.MimeType) {
			content.Text = string(body)
		} else {
			content.Text = base64.StdEncoding.EncodeToString(body)
			content.Encoding = "base64"
		}
	}

	headersSize := calculateHeaderSize(headers)
	bodySizeFromDataLength := int64(resp.EncodedDataLength) - headersSize
	if bodySizeFromDataLength < 0 {
		bodySizeFromDataLength = content.Size
	}

	return schemas.Response{
		Status:      int(resp.Status),
		StatusText:  resp.StatusText,
		HTTPVersion: resp.Protocol,
		Headers:     headers,
		Content:     content,
		RedirectURL: getHeader(resp.Headers, "Location"),
		BodySize:    bodySizeFromDataLength,
		HeadersSize: headersSize,
	}
}

func getHeader(headers network.Headers, key string) string {
	for h, v := range headers {
		if strings.EqualFold(h, key) {
			if valStr, ok := v.(string); ok {
				return strings.Split(valStr, "\n")[0]
			}
		}
	}
	return ""
}

func convertHeaders(headers network.Headers) []schemas.NVPair {
	nvps := make([]schemas.NVPair, 0, len(headers))
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		value := headers[name]
		if valStr, ok := value.(string); ok {
			for _, v := range strings.Split(valStr, "\n") {
				nvps = append(nvps, schemas.NVPair{Name: name, Value: v})
			}
		}
	}
	return nvps
}

func convertQueryString(urlStr string) []schemas.NVPair {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}
	nvps := make([]schemas.NVPair, 0)
	query := u.Query()
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		for _, value := range query[name] {
			nvps = append(nvps, schemas.NVPair{Name: name, Value: value})
		}
	}
	return nvps
}

func calculateHeaderSize(headers []schemas.NVPair) int64 {
	var size int64 = 20 // Estimate for status line
	for _, h := range headers {
		size += int64(len(h.Name) + 2 + len(h.Value) + 2) // Name: Value\r\n
	}
	size += 2 // Final \r\n
	return size
}

func isTextMime(mimeType string) bool {
	mime := strings.ToLower(mimeType)
	return strings.HasPrefix(mime, "text/") ||
		strings.Contains(mime, "json") ||
		strings.Contains(mime, "javascript") ||
		strings.Contains(mime, "xml") ||
		strings.Contains(mime, "x-www-form-urlencoded")
}

