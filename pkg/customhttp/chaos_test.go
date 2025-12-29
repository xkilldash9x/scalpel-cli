// internal/browser/network/customhttp/chaos_test.go
package customhttp

import (
	"context"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// chaosProxy sits between the client and server to inject faults.
type chaosProxy struct {
	target      string
	listener    net.Listener
	delayRange  [2]time.Duration
	corruptRate float64
	closeRate   float64
	wg          sync.WaitGroup
	t           *testing.T
}

func newChaosProxy(t *testing.T, target string) *chaosProxy {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &chaosProxy{
		target:   target,
		listener: listener,
		t:        t,
	}
	p.wg.Add(1)
	go p.run()
	return p
}

func (p *chaosProxy) Addr() string {
	return p.listener.Addr().String()
}

func (p *chaosProxy) Close() {
	p.listener.Close()
	p.wg.Wait()
}

func (p *chaosProxy) run() {
	defer p.wg.Done()
	for {
		clientConn, err := p.listener.Accept()
		if err != nil {
			return // Listener closed
		}
		p.wg.Add(1)
		go p.handleConn(clientConn)
	}
}

func (p *chaosProxy) handleConn(clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	serverConn, err := net.Dial("tcp", p.target)
	if err != nil {
		p.t.Logf("Chaos proxy failed to connect to target: %v", err)
		return
	}
	defer serverConn.Close()

	go p.proxyData(clientConn, serverConn)
	p.proxyData(serverConn, clientConn)
}

func (p *chaosProxy) proxyData(dst, src net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		data := buf[:n]

		// Inject chaos
		if p.delayRange[1] > 0 {
			delay := p.delayRange[0] + time.Duration(rand.Int63n(int64(p.delayRange[1]-p.delayRange[0])))
			time.Sleep(delay)
		}
		if rand.Float64() < p.corruptRate {
			rand.Read(data) // Corrupt the data
		}
		if rand.Float64() < p.closeRate {
			src.Close()
			dst.Close()
			return
		}

		_, err = dst.Write(data)
		if err != nil {
			return
		}
	}
}

func TestChaos_RandomDelays(t *testing.T) {
	handler := &MockServerHandler{StatusCode: http.StatusOK}
	server := NewMockServer(handler)
	defer server.Close()

	proxy := newChaosProxy(t, server.Listener.Addr().String())
	proxy.delayRange = [2]time.Duration{50 * time.Millisecond, 150 * time.Millisecond}
	defer proxy.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.RequestTimeout = 100 * time.Millisecond
	config.RetryPolicy.MaxRetries = 3
	config.RetryPolicy.InitialBackoff = 10 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	// The request may or may not succeed depending on the random delays.
	// A successful test run simply means the client doesn't panic or get stuck.
	req, _ := http.NewRequest("GET", "http://"+proxy.Addr(), nil)
	_, _ = client.Do(context.Background(), req)
}

func TestChaos_ConnectionDrops(t *testing.T) {
	handler := &MockServerHandler{StatusCode: http.StatusOK, Body: []byte("ok")}
	server := NewMockServer(handler)
	defer server.Close()

	proxy := newChaosProxy(t, server.Listener.Addr().String())
	proxy.closeRate = 0.1 // 10% chance of dropping the connection
	defer proxy.Close()

	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	config.RetryPolicy.MaxRetries = 5
	config.RetryPolicy.InitialBackoff = 10 * time.Millisecond
	client := NewCustomClient(config, logger)
	defer client.CloseAll()

	req, _ := http.NewRequest("GET", "http://"+proxy.Addr(), nil)
	resp, err := client.Do(context.Background(), req)

	// We expect the request to eventually succeed due to retries.
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
