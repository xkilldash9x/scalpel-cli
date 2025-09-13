// internal/network/http_parser.go
package network

import (
    "bufio"
    "compress/gzip"
    "compress/zlib"
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

func (w *closeWrapper) Close() error {
    w.ReadCloser.Close()
    return w.originalBody.Close()
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
            return responses, err
        }

        decompressedBody, err := p.decompressBody(resp)
        if err != nil {
            p.logger.Warn("Failed to decompress body, returning original body",
                zap.Int("status", resp.StatusCode),
                zap.String("content_encoding", resp.Header.Get("Content-Encoding")),
                zap.Error(err),
            )
        } else {
            // Replace the response body with the new, decompressed reader.
            resp.Body = decompressedBody
            resp.Header.Del("Content-Encoding")
            resp.ContentLength = -1
            resp.Header.Del("Content-Length")
        }

        responses = append(responses, resp)
        io.Copy(io.Discard, resp.Body)
        resp.Body.Close()

        if strings.EqualFold(resp.Header.Get("Connection"), "close") {
            if i < expectedTotal-1 {
                p.logger.Warn("Connection closed prematurely by server",
                    zap.Int("received", len(responses)),
                    zap.Int("expected", expectedTotal),
                )
            }
            break
        }
    }

    return responses, nil
}