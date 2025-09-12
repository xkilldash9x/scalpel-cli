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

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// requestData stores information about a single network request's lifecycle.
type requestData struct {
	RequestID network.RequestID
	// Raw CDP events that make up a request's life.
	requestSent      *network.EventRequestWillBeSent
	responseReceived *network.EventResponseReceived
	loadingFinished  *network.EventLoadingFinished
	loadingFailed    *network.EventLoadingFailed

	// Body content, fetched after the fact.
	bodyContent   []byte
	bodyIsBase64  bool
	bodyFetchDone bool
	postData      string
}

// Harvester listens to browser events and collects network traffic (HAR) and console logs.
type Harvester struct {
	logger        *zap.Logger
	sessionCtx    context.Context
	captureBodies bool
	maxBodySize   int64

	// Sync and data storage.
	mu              sync.Mutex
	consoleLogs     []schemas.ConsoleLog
	pageLoadEvent   *page.EventLoadEventFired
	domContentEvent *page.EventDomContentEventFired

	// Map to track the lifecycle of all network requests.
	requests map[network.RequestID]*requestData
}

// NewHarvester creates a new harvester instance.
func NewHarvester(sessionCtx context.Context, logger *zap.Logger, captureBodies bool) *Harvester {
	return &Harvester{
		logger:        logger.Named("harvester"),
		sessionCtx:    sessionCtx,
		captureBodies: captureBodies,
		maxBodySize:   5 * 1024 * 1024, // A sensible 5MB default limit for bodies.
		requests:      make(map[network.RequestID]*requestData),
		consoleLogs:   make([]schemas.ConsoleLog, 0, 128),
	}
}

// Start begins listening to CDP events for network, page, and console activity.
func (h *Harvester) Start() {
	h.logger.Debug("Harvester starting event listeners.")

	// Listen for all the events we care about.
	chromedp.ListenTarget(h.sessionCtx, func(ev interface{}) {
		switch e := ev.(type) {
		// -- Network Events --
		case *network.EventRequestWillBeSent:
			h.onRequestWillBeSent(e)
		case *network.EventResponseReceived:
			h.onResponseReceived(e)
		case *network.EventLoadingFinished:
			h.onLoadingFinished(e)
		case *network.EventLoadingFailed:
			h.onLoadingFailed(e)
		// -- Page Events (for HAR timings) --
		case *page.EventLoadEventFired:
			h.onPageLoad(e)
		case *page.EventDomContentEventFired:
			h.onDOMContentEvent(e)
		// -- Runtime/Console Events --
		case *runtime.EventConsoleAPICalled:
			h.onConsoleAPICalled(e)
		case *runtime.EventExceptionThrown:
			h.onExceptionThrown(e)
		}
	})

	// Enable the necessary CDP domains to get the events.
	err := chromedp.Run(h.sessionCtx,
		network.Enable(),
		page.Enable(),
		runtime.Enable(),
	)
	if err != nil {
		h.logger.Error("Failed to enable necessary CDP domains for harvesting.", zap.Error(err))
	}
}

// Stop ceases event collection, processes the data, and returns the final artifacts.
func (h *Harvester) Stop(ctx context.Context) (*schemas.HAR, []schemas.ConsoleLog) {
	h.logger.Debug("Harvester stopping and processing data.")

	if h.captureBodies {
		h.fetchBodies(ctx)
	}

	h.fetchPostData(ctx)

	h.logger.Debug("Generating HAR log.")
	har := h.generateHAR()

	h.mu.Lock()
	logs := make([]schemas.ConsoleLog, len(h.consoleLogs))
	copy(logs, h.consoleLogs)
	h.mu.Unlock()

	return har, logs
}

// -- Event Handlers --

func (h *Harvester) onRequestWillBeSent(ev *network.EventRequestWillBeSent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if rd, exists := h.requests[ev.RequestID]; exists {
		if ev.RedirectResponse != nil {
			rd.responseReceived = &network.EventResponseReceived{
				RequestID: ev.RequestID,
				Response:  ev.RedirectResponse,
				Timestamp: ev.Timestamp,
			}
			rd.loadingFinished = &network.EventLoadingFinished{
				RequestID: ev.RequestID,
				Timestamp: ev.Timestamp,
			}
			rd.bodyFetchDone = true
		}
	}

	h.requests[ev.RequestID] = &requestData{
		RequestID:   ev.RequestID,
		requestSent: ev,
	}
}

func (h *Harvester) onResponseReceived(ev *network.EventResponseReceived) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if rd, exists := h.requests[ev.RequestID]; exists {
		rd.responseReceived = ev
	}
}

func (h *Harvester) onLoadingFinished(ev *network.EventLoadingFinished) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if rd, exists := h.requests[ev.RequestID]; exists {
		rd.loadingFinished = ev
	}
}

func (h *Harvester) onLoadingFailed(ev *network.EventLoadingFailed) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if rd, exists := h.requests[ev.RequestID]; exists {
		rd.loadingFailed = ev
		rd.bodyFetchDone = true
	}
}

func (h *Harvester) onPageLoad(ev *page.EventLoadEventFired) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pageLoadEvent = ev
}

func (h *Harvester) onDOMContentEvent(ev *page.EventDomContentEventFired) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.domContentEvent = ev
}

func (h *Harvester) onConsoleAPICalled(ev *runtime.EventConsoleAPICalled) {
	h.mu.Lock()
	defer h.mu.Unlock()

	logEntry := schemas.ConsoleLog{
		Timestamp: ev.Timestamp.Time(),
		Type:      string(ev.Type),
		Source:    "console-api",
		Text:      h.formatConsoleArgs(ev.Args),
	}
	if ev.StackTrace != nil && len(ev.StackTrace.CallFrames) > 0 {
		frame := ev.StackTrace.CallFrames[0]
		logEntry.URL = frame.URL
		logEntry.Line = int64(frame.LineNumber)
	}
	h.consoleLogs = append(h.consoleLogs, logEntry)
}

func (h *Harvester) onExceptionThrown(ev *runtime.EventExceptionThrown) {
	h.mu.Lock()
	defer h.mu.Unlock()

	details := ev.ExceptionDetails
	text := details.Text
	if details.Exception != nil && details.Exception.Description != "" {
		text = details.Exception.Description
	}

	logEntry := schemas.ConsoleLog{
		Timestamp: ev.Timestamp.Time(),
		Type:      "error",
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

// -- Body Fetching --

func (h *Harvester) fetchPostData(ctx context.Context) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Concurrency limit

	h.mu.Lock()
	requestsToFetch := make([]*requestData, 0)
	for _, rd := range h.requests {
		if rd.requestSent != nil && rd.requestSent.Request.HasPostData && rd.postData == "" {
			requestsToFetch = append(requestsToFetch, rd)
		}
	}
	h.mu.Unlock()

	for _, rd := range requestsToFetch {
		wg.Add(1)
		sem <- struct{}{}
		go func(data *requestData) {
			defer wg.Done()
			defer func() { <-sem }()

			var postDataString string
			err := chromedp.Run(h.sessionCtx,
				chromedp.ActionFunc(func(c context.Context) error {
					var err error
					postDataString, err = network.GetRequestPostData(data.RequestID).Do(c)
					return err
				}),
			)
			if err == nil {
				h.mu.Lock()
				data.postData = postDataString
				h.mu.Unlock()
			}
		}(rd)
	}
	wg.Wait()
}

func (h *Harvester) fetchBodies(ctx context.Context) {
	h.mu.Lock()
	var requestsToFetch []*requestData
	for _, rd := range h.requests {
		if rd.responseReceived == nil || rd.loadingFinished == nil || rd.bodyFetchDone {
			continue
		}
		if int64(rd.loadingFinished.EncodedDataLength) > h.maxBodySize {
			h.logger.Debug("Skipping body fetch due to size limit.", zap.Int64("size", int64(rd.loadingFinished.EncodedDataLength)))
			rd.bodyFetchDone = true
			continue
		}
		requestsToFetch = append(requestsToFetch, rd)
	}
	h.mu.Unlock()

	if len(requestsToFetch) == 0 {
		return
	}

	var wg sync.WaitGroup
	concurrencyLimit := 10
	sem := make(chan struct{}, concurrencyLimit)

	for _, rd := range requestsToFetch {
		wg.Add(1)
		sem <- struct{}{}
		go func(data *requestData) {
			defer wg.Done()
			defer func() { <-sem }()

			fetchCtx, cancel := context.WithTimeout(h.sessionCtx, 10*time.Second)
			defer cancel()

			var body []byte
			err := chromedp.Run(fetchCtx, chromedp.ActionFunc(func(c context.Context) error {
				var err error
				body, err = network.GetResponseBody(data.RequestID).Do(c)
				return err
			}))

			h.mu.Lock()
			defer h.mu.Unlock()

			data.bodyFetchDone = true

			if err != nil {
				if fetchCtx.Err() == nil && ctx.Err() == nil {
					h.logger.Debug("Failed to get response body", zap.String("request_id", string(data.RequestID)), zap.Error(err))
				}
				return
			}
			data.bodyContent = body
			if data.responseReceived != nil && data.responseReceived.Response != nil {
				mime := data.responseReceived.Response.MimeType
				if !strings.HasPrefix(mime, "text/") &&
					!strings.Contains(mime, "javascript") &&
					!strings.Contains(mime, "json") {
					data.bodyIsBase64 = true
				}
			}
		}(rd)
	}
	wg.Wait()
}

// -- HAR Generation --

func (h *Harvester) generateHAR() *schemas.HAR {
	h.mu.Lock()
	defer h.mu.Unlock()

	entries := make([]schemas.Entry, 0, len(h.requests))
	var earliestTime time.Time

	for _, rd := range h.requests {
		entry := h.processRequestDataToEntry(rd)
		if entry != nil {
			entries = append(entries, *entry)
			if rd.requestSent != nil {
				if earliestTime.IsZero() || rd.requestSent.WallTime.Time().Before(earliestTime) {
					earliestTime = rd.requestSent.WallTime.Time()
				}
			}
		}
	}

	harLog := schemas.HARLog{
		Version: "1.2",
		Creator: schemas.Creator{
			Name:    "Scalpel-CLI Harvester",
			Version: "0.1",
		},
	}

	if earliestTime.IsZero() {
		harLog.Entries = make([]schemas.Entry, 0)
		return &schemas.HAR{Log: harLog}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].StartedDateTime.Before(entries[j].StartedDateTime)
	})
	harLog.Entries = entries

	var onContentLoad, onLoad float64 = -1, -1
	if h.domContentEvent != nil {
		onContentLoad = float64(h.domContentEvent.Timestamp.Time().Sub(earliestTime).Milliseconds())
	}
	if h.pageLoadEvent != nil {
		onLoad = float64(h.pageLoadEvent.Timestamp.Time().Sub(earliestTime).Milliseconds())
	}

	harLog.Pages = []schemas.Page{
		{
			StartedDateTime: earliestTime,
			ID:              "page_1",
			Title:           "Analysis Session",
			PageTimings: schemas.PageTimings{
				OnContentLoad: onContentLoad,
				OnLoad:        onLoad,
			},
		},
	}

	return &schemas.HAR{Log: harLog}
}

func (h *Harvester) processRequestDataToEntry(rd *requestData) *schemas.Entry {
	if rd.requestSent == nil || rd.requestSent.Request == nil {
		return nil
	}

	req := rd.requestSent.Request
	entry := &schemas.Entry{
		Pageref:         "page_1",
		StartedDateTime: rd.requestSent.WallTime.Time(),
		Request:         h.buildHarRequest(req, rd),
		Response:        schemas.Response{},
		Cache:           struct{}{},
		Timings:         schemas.Timings{},
	}

	if rd.responseReceived != nil {
		h.updateEntryWithResponse(entry, rd.responseReceived.Response, rd)
	}

	var endTime time.Time
	if rd.loadingFinished != nil {
		endTime = rd.loadingFinished.Timestamp.Time()
		entry.Response.BodySize = int64(rd.loadingFinished.EncodedDataLength)
	} else if rd.loadingFailed != nil {
		endTime = rd.loadingFailed.Timestamp.Time()
		if rd.responseReceived == nil {
			entry.Response.Status = 0
			entry.Response.StatusText = rd.loadingFailed.ErrorText
		}
	}

	if !endTime.IsZero() {
		duration := endTime.Sub(rd.requestSent.WallTime.Time()).Milliseconds()
		if duration >= 0 {
			entry.Time = float64(duration)
		}
	}

	h.finalizeTimings(entry)
	return entry
}

func (h *Harvester) updateEntryWithResponse(entry *schemas.Entry, resp *network.Response, rd *requestData) {
	entry.Response.Status = int(resp.Status)
	entry.Response.StatusText = resp.StatusText
	entry.Response.HTTPVersion = resp.Protocol
	entry.Response.Headers = headersToSchema(resp.Headers)
	entry.Response.RedirectURL = getHeader(resp.Headers, "Location")
	entry.Response.HeadersSize = -1
	entry.Response.BodySize = int64(resp.EncodedDataLength)

	if entry.Request.HTTPVersion == "unknown" {
		entry.Request.HTTPVersion = resp.Protocol
	}

	content := schemas.Content{
		Size:     0,
		MimeType: resp.MimeType,
	}
	if rd.bodyFetchDone {
		if len(rd.bodyContent) > 0 {
			content.Size = int64(len(rd.bodyContent))
			if rd.bodyIsBase64 {
				content.Text = base64.StdEncoding.EncodeToString(rd.bodyContent)
				content.Encoding = "base64"
			} else {
				content.Text = string(rd.bodyContent)
			}
		}
	}
	entry.Response.Content = content

	if resp.Timing != nil {
		t := resp.Timing
		calcDuration := func(start, end float64) float64 {
			if start >= 0 && end >= start {
				return end - start
			}
			return -1
		}
		entry.Timings.DNS = calcDuration(t.DNSStart, t.DNSEnd)
		entry.Timings.Connect = calcDuration(t.ConnectStart, t.ConnectEnd)
		entry.Timings.SSL = calcDuration(t.SslStart, t.SslEnd)
		entry.Timings.Send = calcDuration(t.SendStart, t.SendEnd)
		entry.Timings.Wait = calcDuration(t.SendEnd, t.ReceiveHeadersEnd)
		entry.Timings.Blocked = t.RequestTime
	}
}

func (h *Harvester) finalizeTimings(entry *schemas.Entry) {
	if entry.Time > 0 {
		timingsSum := 0.0
		add := func(t float64) {
			if t > 0 {
				timingsSum += t
			}
		}
		add(entry.Timings.Blocked)
		add(entry.Timings.DNS)
		add(entry.Timings.Connect)
		add(entry.Timings.Send)
		add(entry.Timings.Wait)

		if receiveTime := entry.Time - timingsSum; receiveTime > 0 {
			entry.Timings.Receive = receiveTime
		} else {
			entry.Timings.Receive = 0
		}
	}
}

func (h *Harvester) buildHarRequest(req *network.Request, rd *requestData) schemas.Request {
	harReq := schemas.Request{
		Method:      req.Method,
		URL:         req.URL,
		HTTPVersion: "unknown",
		Cookies:     []schemas.Cookie{},
		Headers:     headersToSchema(req.Headers),
		QueryString: []schemas.NVPair{},
		HeadersSize: -1,
		BodySize:    -1,
	}

	if req.HasPostData {
		contentType := getHeader(req.Headers, "Content-Type")
		harReq.PostData = &schemas.PostData{
			MimeType: contentType,
			Text:     rd.postData,
		}
		harReq.BodySize = int64(len(rd.postData))
	}
	return harReq
}

func getHeader(headers network.Headers, key string) string {
	if val, ok := headers[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	lowerKey := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == lowerKey {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func headersToSchema(headers network.Headers) []schemas.NVPair {
	var result []schemas.NVPair
	for k, v := range headers {
		result = append(result, schemas.NVPair{Name: k, Value: fmt.Sprintf("%v", v)})
	}
	return result
}
