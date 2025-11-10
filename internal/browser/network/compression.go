// browser/network/compression.go
package network

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
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
			// Initialize by allocating the struct. We rely on Reset() before use.
			// We must return a non-nil struct.
			return new(gzip.Reader)
		},
	}

	// Optimization: Add Brotli reader pool.
	brotliReaderPool = sync.Pool{
		New: func() interface{} {
			// brotli.NewReader(nil) is the idiomatic way to create a reusable reader ready for Reset().
			return brotli.NewReader(nil)
		},
	}
)

// Shared empty reader used for safely resetting pooled readers.
// Using a shared instance avoids allocations on every put operation.
var emptyReader = strings.NewReader("")

// getGzipReader retrieves a gzip reader from the pool and resets it with the new source.
func getGzipReader(r io.Reader) (*gzip.Reader, error) {
	zr := gzipReaderPool.Get().(*gzip.Reader)
	if err := zr.Reset(r); err != nil {
		// If Reset fails (e.g., invalid header), r may be partially consumed.
		// However, the allocation (zr) is still valid for reuse because Reset re-initializes the state.
		// Put it back in the pool and return the error. Do not attempt NewReader(r).
		// We rely on the next call to Reset() in getGzipReader to clean it up fully.
		gzipReaderPool.Put(zr)
		return nil, err
	}
	return zr, nil
}

// putGzipReader returns a gzip reader to the pool.
func putGzipReader(zr *gzip.Reader) {
	if zr == nil {
		return
	}
	// Resetting helps release references to the previous reader/data sooner.
	// FIX: We use an empty reader instead of nil. In some Go versions (e.g., < 1.16),
	// gzip.Reset(nil) could panic because it unconditionally tries to read a header.
	// Resetting with an empty reader causes Reset() to return io.EOF, which we safely ignore here.
	_ = zr.Reset(emptyReader)
	gzipReaderPool.Put(zr)
}

// getBrotliReader retrieves a Brotli reader from the pool and resets it.
func getBrotliReader(r io.Reader) (*brotli.Reader, error) {
	br := brotliReaderPool.Get().(*brotli.Reader)
	if err := br.Reset(r); err != nil {
		// If Reset fails, put it back in the pool and return the error.
		brotliReaderPool.Put(br)
		return nil, err
	}
	return br, nil
}

// putBrotliReader returns a Brotli reader to the pool.
func putBrotliReader(br *brotli.Reader) {
	if br == nil {
		return
	}
	// While brotli.Reader handles Reset(nil) safely, we use an empty reader
	// for consistency with gzip handling and maximum robustness.
	_ = br.Reset(emptyReader)
	brotliReaderPool.Put(br)
}

// CompressionMiddleware is an http.RoundTripper that transparently handles
// HTTP response decompression. It automatically adds an `Accept-Encoding` header
// to outgoing requests to negotiate compression with the server and then decompresses
// the response body based on the `Content-Encoding` header received.
//
// This middleware supports gzip, deflate (both zlib and raw), and brotli encoding,
// utilizing sync.Pool for readers to optimize performance and reduce garbage collection.
type CompressionMiddleware struct {
	// Transport is the underlying http.RoundTripper to which requests will be
	// sent after the Accept-Encoding header is added. If nil, http.DefaultTransport
	// is used.
	Transport http.RoundTripper
}

// NewCompressionMiddleware creates a new CompressionMiddleware that wraps the
// provided http.RoundTripper. If the provided transport is nil, it defaults to
// http.DefaultTransport.
func NewCompressionMiddleware(transport http.RoundTripper) *CompressionMiddleware {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &CompressionMiddleware{
		Transport: transport,
	}
}

// RoundTrip implements the http.RoundTripper interface. It modifies the request
// to advertise support for compression, sends the request to the underlying
// transport, and then decompresses the response body if necessary.
func (cm *CompressionMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	// Advertise support for modern compression algorithms if the caller hasn't already.
	if req.Header.Get("Accept-Encoding") == "" {
		// Prioritize Brotli (br) as it generally offers better compression.
		req.Header.Set("Accept-Encoding", "br, gzip, deflate, identity")
	}

	resp, err := cm.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Decompress the response body based on the Content-Encoding header.
	if err := DecompressResponse(resp); err != nil {
		// If decompression initialization fails, the body stream (resp.Body) might be partially consumed.
		// We must close the body and discard the response to prevent corruption.
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
		w.poolCallback = nil // Prevent double-callback
	}

	// Close the decompression reader itself.
	// Note: For readers that don't implement Close (like Brotli wrapped in NopCloser), this is a no-op.
	// For others (like Gzip, Deflate), this closes the decompressor stream.
	err1 := w.ReadCloser.Close()
	// Close the original underlying body (e.g., the TCP connection managed by http.Transport).
	err2 := w.originalBody.Close()

	// Use errors.Join (Go 1.20+) to robustly report errors if multiple close operations fail.
	return errors.Join(err1, err2)
}

// DecompressResponse inspects the `Content-Encoding` header of an http.Response
// and wraps its Body with the appropriate decompression reader(s). It is the core
// decompression logic used by the CompressionMiddleware.
//
// This function handles multiple, layered encodings (e.g., gzip applied over deflate)
// by applying decoders in the reverse order. It supports gzip, brotli, and both
// zlib-wrapped and raw deflate streams. For performance, it uses pooled readers
// for gzip and brotli.
//
// After successfully wrapping the body, it removes the `Content-Encoding` and
// `Content-Length` headers from the response and sets `resp.Uncompressed` to true.
//
// NOTE: If this function returns an error (e.g., due to an invalid header or
// unsupported encoding), the `resp.Body` may have been partially read and should be
// considered corrupted. The caller is responsible for closing the body and
// discarding the response in such cases.
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
				// If initialization fails, we must abort the chain.
				return fmt.Errorf("gzip initialization error: %w", err)
			}
			reader = gzipReader
			// Define the callback to return this specific reader instance to the pool when closed.
			poolCallback = func() {
				putGzipReader(gzipReader)
			}

		case "deflate":
			// Use robust deflate handling (Zlib or Raw).
			// tryDeflate is safe regarding stream consumption on failure due to resettableReader.
			reader, err = tryDeflate(resp.Body)
			if err != nil {
				return fmt.Errorf("deflate initialization error: %w", err)
			}

		case "br":
			// Use pooled Brotli reader.
			brReader, err := getBrotliReader(resp.Body)
			if err != nil {
				return fmt.Errorf("brotli initialization error: %w", err)
			}
			// Brotli reader does not implement io.Closer.
			reader = io.NopCloser(brReader)
			poolCallback = func() {
				putBrotliReader(brReader)
			}

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
	// Use a small buffer, enough for headers (e.g., 2 bytes for Zlib).
	buf := bytes.NewBuffer(make([]byte, 0, 128))
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
