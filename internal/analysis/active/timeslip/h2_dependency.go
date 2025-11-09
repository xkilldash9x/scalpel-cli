// internal/analysis/active/timeslip/h2_dependency.go
package timeslip

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ExecuteH2Dependency leverages HTTP/2 Stream Dependencies (PRIORITY frames).
// It manually controls H2 frames to create a dependency chain for tighter synchronization.
// The strategy involves opening a "gate" stream first, having subsequent streams depend on it,
// and finally releasing the gate stream's data (if any) to trigger simultaneous processing.
func ExecuteH2Dependency(ctx context.Context, candidate *RaceCandidate, config *Config, oracle *SuccessOracle, logger *zap.Logger) (*RaceResult, error) {
	startTime := time.Now()

	// H2 requires HTTPS.
	if !strings.HasPrefix(candidate.URL, "https://") {
		return nil, fmt.Errorf("%w: H2 Dependency strategy requires HTTPS", ErrConfigurationError)
	}

	if config.Concurrency < 2 {
		return nil, fmt.Errorf("%w: H2 Dependency requires concurrency >= 2", ErrConfigurationError)
	}

	targetURL, err := url.Parse(candidate.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL: %v", ErrConfigurationError, err)
	}

	// 1. Establish TCP/TLS Connection manually.
	conn, err := dialH2Connection(ctx, targetURL, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Set overall deadline for the connection
	deadline := time.Now().Add(config.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetDeadline(deadline)

	// 2. Initialize H2 Framer and HPACK encoder/decoder.
	framer := http2.NewFramer(conn, conn)
	hbuf := getBuffer() // Use pooled buffer for HPACK encoding
	defer putBuffer(hbuf)
	encoder := hpack.NewEncoder(hbuf)
	decoder := hpack.NewDecoder(4096, nil) // Standard initial table size

	// Send H2 preface and initial SETTINGS.
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("%w: failed to write H2 preface: %v", ErrH2FrameError, err)
	}
	// Disable PUSH (SettingID 2).
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 0}); err != nil {
		return nil, fmt.Errorf("%w: failed to write initial SETTINGS: %v", ErrH2FrameError, err)
	}

	// Wait for server SETTINGS ACK.
	if err := waitForSettingsAck(framer); err != nil {
		return nil, err
	}

	// 3. Prepare requests (N total).
	requests, err := prepareH2Requests(candidate, config.Concurrency)
	if err != nil {
		return nil, err
	}

	// 4. Define Stream IDs.
	// Client-initiated streams must be odd.
	gateStreamID := uint32(1)
	nextStreamID := gateStreamID + 2

	// 5. Separate dependent requests (N-1) and the gate request (1).
	// We take the last request as the gate request for simplicity in slicing.
	dependentRequests := requests[:config.Concurrency-1]
	gateRequest := requests[config.Concurrency-1]
	streamIDs := make([]uint32, 0, config.Concurrency)
	streamIDs = append(streamIDs, gateStreamID) // Track gate stream ID.

	// 6. Send the Gate request HEADERS.
	// This ensures the stream is opened (or half-closed local) before dependent streams reference it,
	// avoiding potential PROTOCOL_ERROR on strict servers (like the Go test server).
	gateHasBody := len(gateRequest.body) > 0

	// Send HEADERS. If no body, set END_STREAM=true.
	if err := sendH2Headers(framer, encoder, hbuf, gateStreamID, candidate.Method, gateRequest, targetURL, !gateHasBody); err != nil {
		return nil, fmt.Errorf("%w: failed to send gate HEADERS %d: %v", ErrH2FrameError, gateStreamID, err)
	}

	// 7. Send N-1 dependent requests.
	for _, reqData := range dependentRequests {
		streamID := nextStreamID
		streamIDs = append(streamIDs, streamID)
		nextStreamID += 2

		// Write PRIORITY frame: This stream depends on the gateStreamID.
		priority := http2.PriorityParam{
			StreamDep: gateStreamID,
			Weight:    15,    // Default weight (16 when serialized)
			Exclusive: false, // Non-exclusive for compatibility with various server implementations.
		}
		if err := framer.WritePriority(streamID, priority); err != nil {
			return nil, fmt.Errorf("%w: failed to write PRIORITY frame for stream %d: %v", ErrH2FrameError, streamID, err)
		}

		// Send the actual request (HEADERS + DATA).
		if err := sendH2Request(framer, encoder, hbuf, streamID, candidate.Method, reqData, targetURL); err != nil {
			return nil, fmt.Errorf("%w: failed to send dependent request %d: %v", ErrH2FrameError, streamID, err)
		}
	}

	// 8. If Gate request had a body, send the DATA frame now (The synchronization point).
	if gateHasBody {
		// Assuming request bodies fit in one frame.
		if err := framer.WriteData(gateStreamID, true, gateRequest.body); err != nil {
			return nil, fmt.Errorf("%w: failed to write gate DATA frame %d: %v", ErrH2FrameError, gateStreamID, err)
		}
	}

	// 9. Read responses.
	// We rely on the connection deadline set earlier to manage read timeouts.
	responses, err := readH2Responses(framer, decoder, streamIDs, logger)
	duration := time.Since(startTime)

	if err != nil {
		// Log the error but continue processing any responses we did receive.
		// We check specifically if the error was a GOAWAY, as that indicates a server rejection of the strategy.
		if strings.Contains(err.Error(), "server sent GOAWAY") {
			// If the server rejected the connection (e.g., due to PROTOCOL_ERROR), treat it as a strategy failure.
			// We might still have partial responses, but the strategy itself likely didn't work as intended.
			logger.Warn("H2 Dependency strategy potentially rejected by server (GOAWAY received)", zap.Error(err))
		} else {
			logger.Warn("Error during response reading (may be partial results)", zap.Error(err))
		}
	}

	if len(responses) == 0 {
		// If we received no responses, classify as unreachable.
		if err != nil {
			return nil, fmt.Errorf("%w: no responses received, last error: %v", ErrTargetUnreachable, err)
		}
		return nil, fmt.Errorf("%w: no responses received", ErrTargetUnreachable)
	}

	// 10. Package results.
	result := &RaceResult{
		Strategy:  H2Dependency,
		Responses: make([]*RaceResponse, 0, len(responses)),
		Duration:  duration,
	}

	excludeMap := config.GetExcludedHeaders()

	for _, resp := range responses {
		parsedResponse := &ParsedResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       resp.BodyBytes,
			Duration:   0, // Individual timing isn't measured in this manual strategy.
			// Raw *http.Response is not available as we manually constructed it.
		}

		// Handle synthetic status codes (like 0 for RST_STREAM without headers)
		if parsedResponse.StatusCode == 0 && len(parsedResponse.Body) == 0 {
			// Create a synthetic error response for analysis
			raceResp := &RaceResponse{
				Error:    fmt.Errorf("stream reset by server before headers received (StreamID %d)", resp.StreamID),
				StreamID: resp.StreamID,
			}
			result.Responses = append(result.Responses, raceResp)
			continue
		}

		fingerprint := GenerateFingerprint(parsedResponse.StatusCode, parsedResponse.Headers, parsedResponse.Body, excludeMap)

		raceResp := &RaceResponse{
			ParsedResponse: parsedResponse,
			Fingerprint:    fingerprint,
			SpecificBody:   parsedResponse.Body,
			StreamID:       resp.StreamID,
		}

		raceResp.IsSuccess = oracle.IsSuccess(raceResp)
		result.Responses = append(result.Responses, raceResp)
	}

	return result, nil
}

// --- Helper structs and functions for manual H2 handling ---

type h2RequestData struct {
	body    []byte
	headers http.Header
}

type h2ResponseData struct {
	StreamID   uint32
	StatusCode int
	Header     http.Header
	BodyBytes  []byte
}

// dialH2Connection establishes a TCP connection and negotiates TLS with ALPN forced to H2.
func dialH2Connection(ctx context.Context, targetURL *url.URL, config *Config) (net.Conn, error) {
	address := targetURL.Host
	// Ensure port is present
	if !strings.Contains(address, ":") {
		address = net.JoinHostPort(address, "443")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		NextProtos:         []string{"h2"}, // Force H2 via ALPN
		ServerName:         targetURL.Hostname(),
	}

	dialer := &net.Dialer{
		Timeout:   config.Timeout,
		KeepAlive: 30 * time.Second,
	}

	// Dial TCP
	baseConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to dial TCP: %v", ErrTargetUnreachable, err)
	}

	// Negotiate TLS
	tlsConn := tls.Client(baseConn, tlsConfig)
	// Use a context for the handshake
	handshakeCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		baseConn.Close()
		return nil, fmt.Errorf("%w: TLS handshake failed: %v", ErrTargetUnreachable, err)
	}

	// Verify H2 negotiation
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return nil, ErrH2Unsupported
	}

	return tlsConn, nil
}

// waitForSettingsAck waits for the server to acknowledge our initial SETTINGS frame.
// Relies on the connection deadline for timeout.
func waitForSettingsAck(framer *http2.Framer) error {
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			// Check if the error is a timeout from the connection deadline.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return fmt.Errorf("%w: timeout waiting for SETTINGS ACK: %v", ErrTargetUnreachable, err)
			}
			if err == io.EOF {
				return fmt.Errorf("%w: connection closed while waiting for SETTINGS ACK", ErrTargetUnreachable)
			}
			// Handle GOAWAY frames received during initialization if they are embedded in the error
			if goAwayErr, ok := err.(http2.GoAwayError); ok {
				return fmt.Errorf("%w: server sent GOAWAY during initialization: %v", ErrH2FrameError, goAwayErr)
			}
			return fmt.Errorf("%w: error reading frame while waiting for SETTINGS ACK: %v", ErrH2FrameError, err)
		}

		if settingsFrame, ok := frame.(*http2.SettingsFrame); ok {
			if settingsFrame.IsAck() {
				return nil // Got ACK
			}
			// Got server settings, we must acknowledge them.
			if err := framer.WriteSettingsAck(); err != nil {
				return fmt.Errorf("%w: failed to write SETTINGS ACK: %v", ErrH2FrameError, err)
			}
		}
		// Ignore other frames (like WINDOW_UPDATE) during initialization.
	}
}

// prepareH2Requests generates the mutated requests.
func prepareH2Requests(candidate *RaceCandidate, count int) ([]h2RequestData, error) {
	var requests []h2RequestData
	for i := 0; i < count; i++ {
		// Create a copy of the candidate for mutation to avoid side effects between iterations.
		candidateCopy := *candidate
		// Ensure Headers map is initialized before cloning if it's nil.
		if candidateCopy.Headers == nil {
			candidateCopy.Headers = make(http.Header)
		}
		candidateCopy.Headers = candidate.Headers.Clone()

		mutatedBody, mutatedHeaders, _, err := MutateRequest(&candidateCopy)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to mutate request %d: %v", ErrPayloadMutationFail, i, err)
		}
		requests = append(requests, h2RequestData{body: mutatedBody, headers: mutatedHeaders})
	}
	return requests, nil
}

// sendH2Headers encodes headers and writes only the HEADERS frame.
func sendH2Headers(framer *http2.Framer, encoder *hpack.Encoder, hbuf *bytes.Buffer, streamID uint32, method string, reqData h2RequestData, targetURL *url.URL, endStream bool) error {
	// Encode headers.
	headerBlock, err := encodeHeaders(encoder, hbuf, method, reqData.body, reqData.headers, targetURL)
	if err != nil {
		return fmt.Errorf("failed to encode headers: %w", err)
	}

	// Write HEADERS frame.
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndStream:     endStream,
		EndHeaders:    true, // Assuming headers fit in one frame.
	}); err != nil {
		return fmt.Errorf("failed to write HEADERS frame: %w", err)
	}
	return nil
}

// sendH2Request encodes headers and writes the HEADERS and DATA frames for a request.
// This is used for the dependent requests which are sent entirely at once.
func sendH2Request(framer *http2.Framer, encoder *hpack.Encoder, hbuf *bytes.Buffer, streamID uint32, method string, reqData h2RequestData, targetURL *url.URL) error {
	// Determine if stream ends after headers.
	endStream := len(reqData.body) == 0

	// Send HEADERS.
	if err := sendH2Headers(framer, encoder, hbuf, streamID, method, reqData, targetURL, endStream); err != nil {
		return err
	}

	// Write DATA frame if body exists.
	if !endStream {
		// Assuming request bodies fit in one frame for this strategy.
		if err := framer.WriteData(streamID, true, reqData.body); err != nil {
			return fmt.Errorf("failed to write DATA frame: %w", err)
		}
	}
	return nil
}

// encodeHeaders serializes HTTP headers into HPACK format, including pseudo-headers.
func encodeHeaders(encoder *hpack.Encoder, hbuf *bytes.Buffer, method string, body []byte, headers http.Header, targetURL *url.URL) ([]byte, error) {
	hbuf.Reset()

	// Pseudo-headers (must be first and in specific order)
	// :method
	encoder.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	// :scheme
	encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: targetURL.Scheme})
	// :authority (Host header)
	authority := headers.Get("Host")
	if authority == "" {
		authority = targetURL.Host
	}
	encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	// :path
	path := targetURL.RequestURI()
	if path == "" {
		path = "/"
	}
	encoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})

	// Content-Length (important for requests with bodies)
	if len(body) > 0 {
		encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))})
	}

	// Regular headers
	for k, vv := range headers {
		canonicalKey := http.CanonicalHeaderKey(k)
		// Skip Host as it's covered by :authority
		if canonicalKey == "Host" {
			continue
		}
		// Skip Content-Length as we handled it explicitly above
		if canonicalKey == "Content-Length" {
			continue
		}

		// H2 requires lower-case header names.
		name := strings.ToLower(k)
		for _, v := range vv {
			encoder.WriteField(hpack.HeaderField{Name: name, Value: v})
		}
	}

	// Return a copy of the buffer's bytes as the buffer will be reused.
	result := make([]byte, hbuf.Len())
	copy(result, hbuf.Bytes())
	return result, nil
}

// readH2Responses handles the asynchronous reading and parsing of H2 frames into responses.
// It relies on the connection deadline for timeouts.
func readH2Responses(framer *http2.Framer, decoder *hpack.Decoder, streamIDs []uint32, logger *zap.Logger) ([]h2ResponseData, error) {
	responses := make(map[uint32]*h2ResponseData)
	expectedStreams := make(map[uint32]bool)
	for _, id := range streamIDs {
		expectedStreams[id] = true
	}

	var lastErr error

	// Process incoming frames until all expected streams are closed.
	for len(expectedStreams) > 0 {
		frame, err := framer.ReadFrame()
		if err != nil {
			// Check if the error is due to the connection deadline expiring
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				lastErr = fmt.Errorf("timeout reading frame (received %d/%d): %w", len(responses), len(streamIDs), err)
			} else if err == io.EOF {
				lastErr = fmt.Errorf("connection closed unexpectedly (received %d/%d)", len(responses), len(streamIDs))
			} else {
				// Handle GOAWAY frames if they occur during ReadFrame (e.g., due to protocol errors)
				if goAwayErr, ok := err.(http2.GoAwayError); ok {
					lastErr = fmt.Errorf("server sent GOAWAY: %v", goAwayErr)
				} else if h2Err, ok := err.(http2.StreamError); ok {
					lastErr = fmt.Errorf("H2 stream error reading frame: Code %v, Err: %w", h2Err.Code, h2Err.Cause)
				} else {
					lastErr = fmt.Errorf("error reading frame: %w", err)
				}
			}
			break // Exit loop on read error
		}

		streamID := frame.Header().StreamID

		// Handle connection-level frames (Stream 0)
		if streamID == 0 {
			switch f := frame.(type) {
			case *http2.GoAwayFrame:
				// This handles GOAWAY frames explicitly received as a frame type.
				lastErr = fmt.Errorf("server sent GOAWAY: %v (Error Code: %d, LastStreamID: %d)", f.ErrCode.String(), f.ErrCode, f.LastStreamID)
				// Stop processing immediately.
				break

			case *http2.PingFrame:
				if !f.IsAck() {
					// Acknowledge PINGs to keep the connection alive.
					if err := framer.WritePing(true, f.Data); err != nil {
						logger.Warn("Failed to write PING ACK", zap.Error(err))
						// Continue processing existing frames even if PING ACK fails
					}
				}
			case *http2.WindowUpdateFrame, *http2.SettingsFrame:
				// Flow control/Settings frames, ignored in this simple implementation.
				logger.Debug("Received control frame", zap.String("type", frame.Header().Type.String()))
			}
			// If GOAWAY was received, break the main loop.
			if lastErr != nil {
				break
			}
			continue
		}

		// Ignore frames for streams we didn't initiate, unless we are already tracking them.
		if !expectedStreams[streamID] && responses[streamID] == nil {
			// This can happen if the server pushes resources, which we disabled in SETTINGS, but we ignore them anyway.
			logger.Debug("Ignoring unexpected stream ID", zap.Uint32("streamID", streamID))
			continue
		}

		// Handle stream-level frames
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if _, exists := responses[streamID]; exists {
				// Potential Trailers, which we ignore for simplicity in this analysis.
				if f.StreamEnded() {
					delete(expectedStreams, streamID)
				}
				logger.Debug("Received HEADERS (likely trailers) for existing stream", zap.Uint32("streamID", streamID))
				continue
			}

			// Decode headers
			headerFields, err := decoder.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				logger.Error("HPACK decoding error", zap.Error(err), zap.Uint32("streamID", streamID))
				delete(expectedStreams, streamID)
				// Consider sending RST_STREAM for decoding errors.
				framer.WriteRSTStream(streamID, http2.ErrCodeCompression)
				continue
			}

			respData := &h2ResponseData{
				StreamID: streamID,
				Header:   make(http.Header),
			}

			// Parse headers
			for _, hf := range headerFields {
				if hf.Name == ":status" {
					status, err := strconv.Atoi(hf.Value)
					if err != nil {
						logger.Error("Invalid :status header", zap.String("value", hf.Value), zap.Uint32("streamID", streamID))
						delete(expectedStreams, streamID)
						break // Stop parsing headers for this frame
					}
					respData.StatusCode = status
				} else {
					// Convert back to canonical format for http.Header map
					respData.Header.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
				}
			}

			if respData.StatusCode != 0 {
				responses[streamID] = respData
			} else {
				// If status code wasn't found, it's an invalid response.
				logger.Error("Missing :status header in response", zap.Uint32("streamID", streamID))
				delete(expectedStreams, streamID)
			}

			if f.StreamEnded() {
				delete(expectedStreams, streamID)
			}

		case *http2.DataFrame:
			respData, exists := responses[streamID]
			if !exists {
				// DATA before HEADERS? Protocol error.
				logger.Error("Received DATA before HEADERS", zap.Uint32("streamID", streamID))
				// Send RST_STREAM (best effort)
				framer.WriteRSTStream(streamID, http2.ErrCodeProtocol)
				delete(expectedStreams, streamID)
				continue
			}
			respData.BodyBytes = append(respData.BodyBytes, f.Data()...)

			// Enforce body size limit
			if len(respData.BodyBytes) > maxResponseBodyBytes {
				logger.Warn("Response body exceeded limit, truncating and resetting stream.", zap.Uint32("streamID", streamID))
				respData.BodyBytes = respData.BodyBytes[:maxResponseBodyBytes]
				// Send RST_STREAM (best effort)
				framer.WriteRSTStream(streamID, http2.ErrCodeFrameSize)
				delete(expectedStreams, streamID)
				continue
			}

			if f.StreamEnded() {
				delete(expectedStreams, streamID)
			}

		case *http2.RSTStreamFrame:
			logger.Info("Stream reset by server", zap.Uint32("streamID", streamID), zap.String("errorCode", f.ErrCode.String()))
			// If we haven't received a response yet, create an error placeholder.
			if _, exists := responses[streamID]; !exists {
				responses[streamID] = &h2ResponseData{
					StreamID: streamID,
					// Use a synthetic status code 0 to indicate stream reset before headers.
					StatusCode: 0,
				}
			}
			delete(expectedStreams, streamID)

		case *http2.WindowUpdateFrame:
			// Flow control frame, ignored here.
			logger.Debug("Received WINDOW_UPDATE for stream", zap.Uint32("streamID", streamID))
		}
	}

	// Convert map to slice for the result.
	var result []h2ResponseData
	for _, resp := range responses {
		result = append(result, *resp)
	}

	// Return the last error encountered if any streams remain expected or if a connection error occurred (like GOAWAY).
	if lastErr != nil {
		return result, lastErr
	}
	return result, nil
}
