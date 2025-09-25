// internal/network/http_parser.go
package network

import (
    "bufio"
    "compress/gzip"
    "compress/zlib"
    "fmt"
    "io"
    "net/http"
    "strings"

    "go.uber.org/zap"
)

// closeWrapper is a custom ReadCloser that ensures both the decompression reader
// and the underlying original body are closed correctly.
type closeWrapper struct {
    io.ReadCloser
    originalBody io.ReadCloser
}

// Close closes both the decompression reader and the original body.
func (w *closeWrapper) Close() error {
    // Ensure both are closed, and prioritize returning the error from the decompression reader if both fail.
    err1 := w.ReadCloser.Close()
    err2 := w.originalBody.Close()
    if err1 != nil {
        return err1
    }
    return err2
}

// HTTPParser handles the parsing of raw HTTP messages.
type HTTPParser struct {
    logger *zap.Logger
}

// NewHTTPParser creates a new HTTPParser instance.
func NewHTTPParser(logger *zap.Logger) *HTTPParser {
    return &HTTPParser{
        logger: logger.Named("http_parser"),
    }
}

// decompressBody returns an io.ReadCloser that transparently decompresses the
// original response body based on the Content-Encoding header.
func (p *HTTPParser) decompressBody(resp *http.Response) (io.ReadCloser, error) {
    // Robustness: Handle nil response or nil body gracefully.
    if resp == nil || resp.Body == nil {
        return nil, nil
    }

    switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
    case "gzip":
        reader, err := gzip.NewReader(resp.Body)
        if err != nil {
            p.logger.Error("Failed to create gzip reader", zap.Error(err))
            return nil, err
        }
        return &closeWrapper{ReadCloser: reader, originalBody: resp.Body}, nil
    case "deflate":
        reader, err := zlib.NewReader(resp.Body)
        if err != nil {
            p.logger.Error("Failed to create zlib reader", zap.Error(err))
            return nil, err
        }
        return &closeWrapper{ReadCloser: reader, originalBody: resp.Body}, nil
    default:
        // No compression, return the original body reader as is.
        return resp.Body, nil
    }
}

// ParsePipelinedResponses reads from a buffered reader and attempts to parse a specified
// number of HTTP responses. This is crucial for handling HTTP pipelining, where
// multiple responses are sent over the same connection in sequence.
// Note: This function consumes the bodies of the responses to advance the reader.
func (p *HTTPParser) ParsePipelinedResponses(conn io.Reader, expectedTotal int) ([]*http.Response, error) {
    if expectedTotal <= 0 {
        return nil, nil
    }

    var responses []*http.Response
    bufReader := bufio.NewReader(conn)

    for i := 0; i < expectedTotal; i++ {
        resp, err := http.ReadResponse(bufReader, nil)
        if err != nil {
            p.logger.Error("Failed to parse pipelined response",
                zap.Int("response_index", i),
                zap.Int("expected_total", expectedTotal),
                zap.Error(err),
            )
            // Return what we have parsed so far along with the error.
            return responses, err
        }

        decompressedBody, err := p.decompressBody(resp)
        if err != nil {
            p.logger.Warn("Failed to decompress body, proceeding with original body",
                zap.Int("status", resp.StatusCode),
                zap.String("content_encoding", resp.Header.Get("Content-Encoding")),
                zap.Error(err),
            )
            // If decompression failed, resp.Body is still the original body (handled by decompressBody).
        } else if decompressedBody != nil {
            // Replace the response body with the new, decompressed reader.
            resp.Body = decompressedBody
            resp.Header.Del("Content-Encoding")
            // Content length is now unknown for the decompressed stream.
            resp.ContentLength = -1
            resp.Header.Del("Content-Length")
        }

        responses = append(responses, resp)

        // Consume and close the body to advance the reader (bufReader) to the start of the next response.
        if resp.Body != nil {
            // We must read the body entirely. If we fail, the stream is likely corrupted or misaligned for the next ReadResponse call.
            _, copyErr := io.Copy(io.Discard, resp.Body)
            closeErr := resp.Body.Close()

            if copyErr != nil {
                p.logger.Error("Failed to consume pipelined response body", zap.Error(copyErr), zap.Int("response_index", i))
                return responses, fmt.Errorf("failed to consume body for response %d: %w", i, copyErr)
            }
            if closeErr != nil {
                // Error during close is less critical but should be logged.
                p.logger.Warn("Error closing pipelined response body", zap.Error(closeErr))
            }
        }

        // Check if the server signaled connection closure.
        if strings.EqualFold(resp.Header.Get("Connection"), "close") {
            if i < expectedTotal-1 {
                p.logger.Warn("Connection closed prematurely by server",
                    zap.Int("received", len(responses)),
                    zap.Int("expected", expectedTotal),
                )
            }
            break // Stop parsing as the connection is closing.
        }
    }

    return responses, nil
}