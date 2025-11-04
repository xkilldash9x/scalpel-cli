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

// ExecuteH2Dependency leverages HTTP/2 Stream Dependencies.
// It manually controls H2 frames to create a dependency chain for tighter synchronization.
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

	// Send H2 preface.
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("%w: failed to write H2 preface: %v", ErrH2FrameError, err)
	}
	// Send initial SETTINGS frame. Disable PUSH.
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

	// 4. Define Stream IDs (Client-initiated streams must be odd).
	gateStreamID := uint32(1)
	nextStreamID := gateStreamID + 2

	// 5. Separate dependent requests (N-1) and the gate request (1).
	dependentRequests := requests[:config.Concurrency-1]
	gateRequest := requests[config.Concurrency-1]
	streamIDs := make([]uint32, 0, config.Concurrency)

	// 6. Send N-1 dependent requests.
	for _, reqData := range dependentRequests {
		streamID := nextStreamID
		streamIDs = append(streamIDs, streamID)
		nextStreamID += 2

		// Define PRIORITY parameters: This stream depends on the gateStreamID.
		priority := http2.PriorityParam{
			StreamDep: gateStreamID,
			Weight:    16, // Default weight (16 when serialized)
			// Using non-exclusive dependency is generally more compatible.
			Exclusive: true,
		}

		// Send the actual request (HEADERS including Priority + DATA).
		// FIX: Include the priority in the HEADERS frame instead of sending a separate PRIORITY frame.
		// This resolves potential PROTOCOL_ERROR issues seen in the logs.
		if err := sendH2Request(framer, encoder, hbuf, streamID, candidate.Method, reqData, targetURL, &priority); err != nil {
			return nil, fmt.Errorf("%w: failed to send dependent request %d: %v", ErrH2FrameError, streamID, err)
		}
	}

	// 7. Send the Gate request. This should trigger the server to process the dependent streams.
	streamIDs = append(streamIDs, gateStreamID)
	// The gate request doesn't need special priority settings.
	if err := sendH2Request(framer, encoder, hbuf, gateStreamID, candidate.Method, gateRequest, targetURL, nil); err != nil {
		return nil, fmt.Errorf("%w: failed to send gate request %d: %v", ErrH2FrameError, gateStreamID, err)
	}

	// 8. Read responses (relies on the connection deadline).
	responses, err := readH2Responses(framer, decoder, streamIDs, logger)
	duration := time.Since(startTime)

	if err != nil {
		// Log the error but continue processing any responses we did receive.
		logger.Warn("Error during response reading (may be partial results)", zap.Error(err))
	}

	if len(responses) == 0 {
		// If we received no responses, classify as unreachable.
		if err != nil {
			// This includes the GOAWAY error handling from the logs.
			return nil, fmt.Errorf("%w: no responses received, last error: %v", ErrTargetUnreachable, err)
		}
		return nil, fmt.Errorf("%w: no responses received", ErrTargetUnreachable)
	}

	// 9. Package results.
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
func waitForSettingsAck(framer *http2.Framer) error {
	for {
		// Relies on the connection deadline for timeout.
		frame, err := framer.ReadFrame()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return fmt.Errorf("%w: timeout waiting for SETTINGS ACK: %v", ErrTargetUnreachable, err)
			}
			if err == io.EOF {
				return fmt.Errorf("%w: connection closed while waiting for SETTINGS ACK", ErrTargetUnreachable)
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
		// Create a copy of the candidate for mutation.
		candidateCopy := *candidate
		if candidate.Headers != nil {
			candidateCopy.Headers = candidate.Headers.Clone()
		}

		mutatedBody, mutatedHeaders, _, err := MutateRequest(&candidateCopy)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to mutate request %d: %v", ErrPayloadMutationFail, i, err)
		}
		requests = append(requests, h2RequestData{body: mutatedBody, headers: mutatedHeaders})
	}
	return requests, nil
}

// sendH2Request encodes headers and writes the HEADERS and DATA frames for a request.
// It optionally includes priority information in the HEADERS frame.
func sendH2Request(framer *http2.Framer, encoder *hpack.Encoder, hbuf *bytes.Buffer, streamID uint32, method string, reqData h2RequestData, targetURL *url.URL, priority *http2.PriorityParam) error {
	// Encode headers.
	headerBlock, err := encodeHeaders(encoder, hbuf, method, reqData.body, reqData.headers, targetURL)
	if err != nil {
		return fmt.Errorf("failed to encode headers: %w", err)
	}

	// Write HEADERS frame.
	endStream := len(reqData.body) == 0
	params := http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndStream:     endStream,
		EndHeaders:    true,
	}

	// Include priority information if provided (FIX for PROTOCOL_ERROR).
	if priority != nil {
		params.Priority = *priority
	}

	if err := framer.WriteHeaders(params); err != nil {
		return fmt.Errorf("failed to write HEADERS frame: %w", err)
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
		// Skip Host (covered by :authority) and Content-Length (handled explicitly).
		if canonicalKey == "Host" || canonicalKey == "Content-Length" {
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
				lastErr = fmt.Errorf("error reading frame: %w", err)
			}
			break // Exit loop on read error
		}

		streamID := frame.Header().StreamID

		// Handle connection-level frames (Stream 0)
		if streamID == 0 {
			switch f := frame.(type) {
			case *http2.GoAwayFrame:
				// Capture GOAWAY errors, which caused the failure in the logs.
				lastErr = fmt.Errorf("server sent GOAWAY: %v (LastStreamID: %d)", f.ErrCode, f.LastStreamID)
				// Stop processing further streams.
				expectedStreams = make(map[uint32]bool)
				break

			case *http2.PingFrame:
				if !f.IsAck() {
					// Acknowledge PINGs (best effort).
					if err := framer.WritePing(true, f.Data); err != nil {
						lastErr = fmt.Errorf("failed to write PING ACK: %w", err)
					}
				}
			case *http2.WindowUpdateFrame, *http2.SettingsFrame:
				logger.Debug("Received control frame", zap.String("type", frame.Header().Type.String()))
			}
			continue
		}

		// Ignore frames for unexpected streams.
		if !expectedStreams[streamID] && responses[streamID] == nil {
			logger.Debug("Ignoring unexpected stream ID", zap.Uint32("streamID", streamID))
			continue
		}

		// Handle stream-level frames
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if _, exists := responses[streamID]; exists {
				// Potential Trailers, ignored here.
				if f.StreamEnded() {
					delete(expectedStreams, streamID)
				}
				continue
			}

			// Decode headers
			headerFields, err := decoder.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				logger.Error("HPACK decoding error", zap.Error(err), zap.Uint32("streamID", streamID))
				delete(expectedStreams, streamID)
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
						break
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
				delete(expectedStreams, streamID)
			}

			if f.StreamEnded() {
				delete(expectedStreams, streamID)
			}

		case *http2.DataFrame:
			respData, exists := responses[streamID]
			if !exists {
				// DATA before HEADERS (Protocol error).
				logger.Error("Received DATA before HEADERS", zap.Uint32("streamID", streamID))
				framer.WriteRSTStream(streamID, http2.ErrCodeProtocol)
				delete(expectedStreams, streamID)
				continue
			}
			respData.BodyBytes = append(respData.BodyBytes, f.Data()...)

			// Enforce body size limit
			if len(respData.BodyBytes) > maxResponseBodyBytes {
				logger.Warn("Response body exceeded limit, truncating and resetting stream.", zap.Uint32("streamID", streamID))
				respData.BodyBytes = respData.BodyBytes[:maxResponseBodyBytes]
				framer.WriteRSTStream(streamID, http2.ErrCodeFrameSize)
				delete(expectedStreams, streamID)
				continue
			}

			if f.StreamEnded() {
				delete(expectedStreams, streamID)
			}

		case *http2.RSTStreamFrame:
			logger.Info("Stream reset by server", zap.Uint32("streamID", streamID), zap.Uint32("errorCode", uint32(f.ErrCode)))
			delete(expectedStreams, streamID)
		}
	}

	// Convert map to slice for the result.
	var result []h2ResponseData
	for _, resp := range responses {
		result = append(result, *resp)
	}
	return result, lastErr
}
