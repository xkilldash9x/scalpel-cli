// internal/browser/network/customhttp/fuzz_test.go
//go:build go1.18
// +build go1.18

package customhttp

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"go.uber.org/zap/zaptest"
)

func FuzzSerializeRequest(f *testing.F) {
	f.Add("GET", "http://example.com", "key", "value", "body")
	f.Fuzz(func(t *testing.T, method, urlStr, headerKey, headerValue, body string) {
		if len(method) == 0 || len(urlStr) == 0 || strings.Contains(urlStr, "\x00") {
			return
		}

		req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
		if err != nil {
			return
		}

		// Add a header, ensuring the key is valid.
		if len(headerKey) > 0 && !strings.ContainsAny(headerKey, " \t\r\n\x00") {
			req.Header.Set(headerKey, headerValue)
		}

		// The function under test.
		_, _ = SerializeRequest(req)
	})
}

func FuzzH1ResponseParsing(f *testing.F) {
	// Seed with a valid HTTP response.
	f.Add("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	f.Fuzz(func(t *testing.T, response string) {
		logger := zaptest.NewLogger(t)
		parser := network.NewHTTPParser(logger)
		reader := bufio.NewReader(strings.NewReader(response))

		// The function under test.
		_, _ = parser.ParsePipelinedResponses(reader, 1)
	})
}
