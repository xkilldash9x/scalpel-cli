// internal/browser/network/customhttp/performance_test.go
package customhttp

import (
	"context"
	"net/http"
	"testing"

	"go.uber.org/zap/zaptest"
)

func BenchmarkH1_SimpleGET(b *testing.B) {
	handler := &MockServerHandler{
		StatusCode: http.StatusOK,
		Body:       []byte("benchmark"),
	}
	server := NewMockServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(b)
	config := NewBrowserClientConfig()
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, _ := http.NewRequest("GET", server.URL, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Do(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func BenchmarkH2_SimpleGET(b *testing.B) {
	handler := &MockServerHandler{
		StatusCode: http.StatusOK,
		Body:       []byte("benchmark"),
	}
	server := NewMockTLSServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(b)
	config := NewBrowserClientConfig()
	config.InsecureSkipVerify = true
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, _ := http.NewRequest("GET", server.URL, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Do(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func BenchmarkH2_ConcurrentGET(b *testing.B) {
	handler := &MockServerHandler{
		StatusCode: http.StatusOK,
		Body:       []byte("benchmark"),
	}
	server := NewMockTLSServer(handler)
	defer server.Close()

	logger := zaptest.NewLogger(b)
	config := NewBrowserClientConfig()
	config.InsecureSkipVerify = true
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, _ := http.NewRequest("GET", server.URL, nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Do(context.Background(), req)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
		}
	})
}

func BenchmarkRedirects(b *testing.B) {
	finalHandler := &MockServerHandler{StatusCode: http.StatusOK, Body: []byte("final")}
	finalServer := NewMockServer(finalHandler)
	defer finalServer.Close()

	redirectHandler := &MockServerHandler{StatusCode: http.StatusFound, RedirectURL: finalServer.URL}
	redirectServer := NewMockServer(redirectHandler)
	defer redirectServer.Close()

	logger := zaptest.NewLogger(b)
	client := NewCustomClient(NewBrowserClientConfig(), logger)
	defer client.CloseAll()

	req, _ := http.NewRequest("GET", redirectServer.URL, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Do(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}
