// browser/network/compression.go
package network

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli" // Import Brotli library
)

// Pools for decompression readers to reduce allocation overhead.
var (
	gzipReaderPool = sync.Pool{
		New: func() interface{} {
			// Initialize with a dummy reader; relies on Reset() before use.
			r, _ := gzip.NewReader(strings.NewReader(""))
			return r
		},
	}
)

// getGzipReader retrieves a gzip reader from the pool and resets it with the new source.
func getGzipReader(r io.Reader) (*gzip.Reader, error) {
	zr := gzipReaderPool.Get().(*gzip.Reader)
	if err := zr.Reset(r); err != nil {
		// If reset fails (e.g., invalid header in the new stream), the reader might be unusable.
		// Discard it (by not putting it back) and create a fresh one if NewReader also fails.
		return gzip.NewReader(r)
	}
	return zr, nil
}

// putGzipReader returns a gzip reader to the pool.
func putGzipReader(zr *gzip.Reader) {
	// Resetting helps release references to the previous reader/data sooner.
	zr.Reset(strings.NewReader(""))
	gzipReaderPool.Put(zr)
}

// CompressionMiddleware wraps an http.RoundTripper to handle response decompression transparently.
type CompressionMiddleware struct {
	Transport http.RoundTripper
}

// NewCompressionMiddleware creates the middleware wrapper.
func NewCompressionMiddleware(transport http.RoundTripper) *CompressionMiddleware {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &CompressionMiddleware{
		Transport: transport,
	}
}

// RoundTrip executes a single HTTP transaction, handling compression negotiation.
func (cm *CompressionMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	// Advertise support for modern compression algorithms if the caller hasn't already.
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, identity")
	}

	resp, err := cm.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Decompress the response body based on the Content-Encoding header.
	if err := DecompressResponse(resp); err != nil {
		// Ensure the body (including any partially initialized layers) is closed if decompression fails
		_ = resp.Body.Close()
		return nil, fmt.Errorf("failed to initialize response decompression: %w", err)
	}

	return resp, nil
}

// closeWrapper ensures the decompression reader and the underlying original body are closed.
// It also handles returning pooled readers back to the pool via a callback.
type closeWrapper struct {
	io.ReadCloser
	originalBody io.ReadCloser
	// poolCallback is executed when Close() is called.
	poolCallback func()
}

func (w *closeWrapper) Close() error {
	// Return the reader to the pool if applicable.
	if w.poolCallback != nil {
		w.poolCallback()
	}

	// Close the decompression reader itself.
	err1 := w.ReadCloser.Close()
	// Close the original underlying body.
	err2 := w.originalBody.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// DecompressResponse checks the Content-Encoding header and wraps the response body.
// It handles multi-layer encoding, uses pooling, and supports robust deflate detection.
func DecompressResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}

	// Get all encoding values. They are listed in the order they were applied.
	// We must process them in reverse order to decode.
	encodings := resp.Header.Values("Content-Encoding")
	if len(encodings) == 0 {
		return nil
	}

	// Iterate in reverse order.
	for i := len(encodings) - 1; i >= 0; i-- {
		encoding := strings.ToLower(strings.TrimSpace(encodings[i]))

		var reader io.ReadCloser
		var err error
		var poolCallback func()

		switch encoding {
		case "gzip":
			// Use pooled gzip reader.
			gzipReader, err := getGzipReader(resp.Body)
			if err != nil {
				return fmt.Errorf("gzip initialization error: %w", err)
			}
			reader = gzipReader
			// Define the callback to return this specific reader instance to the pool when closed.
			poolCallback = func() {
				putGzipReader(gzipReader)
			}

		case "deflate":
			// Use robust deflate handling (Zlib or Raw).
			reader, err = tryDeflate(resp.Body)
			if err != nil {
				return fmt.Errorf("deflate initialization error: %w", err)
			}

		case "br":
			// Brotli reader does not implement io.ReadCloser.
			brReader := brotli.NewReader(resp.Body)
			reader = io.NopCloser(brReader)

		case "identity", "":
			// No compression or explicitly identity. Skip this layer.
			continue

		default:
			return fmt.Errorf("unsupported Content-Encoding layer: %s", encoding)
		}

		// Wrap the current body with the new decompression reader.
		// This becomes the input for the next iteration (if any).
		resp.Body = &closeWrapper{
			ReadCloser:   reader,
			originalBody: resp.Body,
			poolCallback: poolCallback,
		}
	}

	// Update headers to reflect the final decompressed state.
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1 // Length is now unknown
	resp.Header.Del("Content-Length")
	resp.Uncompressed = true

	return nil
}

// --- Robust Deflate Handling ---

// resettableReader allows buffering the start of a stream to attempt reading with one
// decompressor and resetting if it fails.
type resettableReader struct {
	r      io.Reader // The current reader (tee or multi)
	buf    *bytes.Buffer
	source io.Reader
}

func newResettableReader(r io.Reader) *resettableReader {
	buf := new(bytes.Buffer)
	// Tee the reads into the buffer while reading from the source.
	tee := io.TeeReader(r, buf)
	return &resettableReader{
		r:      tee,
		buf:    buf,
		source: r,
	}
}

func (rr *resettableReader) Read(p []byte) (int, error) {
	return rr.r.Read(p)
}

// Reset prepares the reader to be read again from the beginning.
func (rr *resettableReader) Reset() {
	// Create a new reader combining the buffered data and the remaining source data.
	rr.r = io.MultiReader(bytes.NewReader(rr.buf.Bytes()), rr.source)
}

// tryDeflate attempts to decode as Zlib, falling back to raw deflate.
func tryDeflate(r io.Reader) (io.ReadCloser, error) {
	rr := newResettableReader(r)

	// 1. Attempt to read as Zlib (RFC 1950).
	zlibReader, err := zlib.NewReader(rr)
	if err == nil {
		return zlibReader, nil
	}

	// 2. If Zlib failed (likely due to missing header), reset the reader and try raw deflate (RFC 1951).
	rr.Reset()
	flateReader := flate.NewReader(rr)
	// flate.NewReader does not return an error on initialization.
	return flateReader, nil
}
