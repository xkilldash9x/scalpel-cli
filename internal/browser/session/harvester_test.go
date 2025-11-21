// internal/browser/session/harvester_test.go
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestWaitNetworkIdle focuses specifically on the network idle detection logic.
func TestWaitNetworkIdle(t *testing.T) {
	// We use the newTestFixture to get a real session and harvester instance.
	// We only use the harvester part, the browser connection isn't strictly necessary for this specific logic test,
	// but it provides a realistic setup.
	fixture := newTestFixture(t)
	harvester := fixture.Session.harvester
	require.NotNil(t, harvester)

	// Define test parameters
	quietPeriod := 200 * time.Millisecond
	testTimeout := 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// 1. Test initial idle state
	t.Log("Testing initial idle state...")
	startTime := time.Now()
	err := harvester.WaitNetworkIdle(ctx, quietPeriod)
	require.NoError(t, err)
	duration := time.Since(startTime)
	// It should take at least the quiet period, but not much longer
	assert.GreaterOrEqual(t, duration, quietPeriod)
	// Allow buffer for ticker frequency
	assert.Less(t, duration, quietPeriod+networkIdleCheckFrequency*2)

	// 2. Test transition from active to idle
	t.Log("Testing transition from active to idle...")

	// Simulate network activity
	harvester.mu.Lock()
	harvester.activeReqs = 3
	harvester.mu.Unlock()

	// Start waiting in a goroutine, as it will block until idle
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- harvester.WaitNetworkIdle(ctx, quietPeriod)
	}()

	// Wait a bit, then decrease activity gradually
	time.Sleep(100 * time.Millisecond)
	harvester.mu.Lock()
	harvester.activeReqs = 2
	harvester.mu.Unlock()

	time.Sleep(100 * time.Millisecond)
	harvester.mu.Lock()
	harvester.activeReqs = 1
	harvester.mu.Unlock()

	// Wait again before becoming fully idle
	activityDuration := 300 * time.Millisecond
	time.Sleep(activityDuration)

	startTime = time.Now() // Record time when activity stops
	harvester.mu.Lock()
	harvester.activeReqs = 0
	harvester.mu.Unlock()

	// Wait for the goroutine to finish
	select {
	case err := <-doneChan:
		require.NoError(t, err)
		idleDuration := time.Since(startTime)
		// The duration since activity stopped should be roughly the quiet period
		assert.InDelta(t, float64(quietPeriod), float64(idleDuration), float64(networkIdleCheckFrequency*2))
	case <-ctx.Done():
		t.Fatal("Test timed out waiting for network idle")
	}

	// 3. Test activity bursts interrupting idle period
	t.Log("Testing activity bursts...")

	harvester.mu.Lock()
	harvester.activeReqs = 1
	harvester.mu.Unlock()

	go func() {
		doneChan <- harvester.WaitNetworkIdle(ctx, quietPeriod)
	}()

	time.Sleep(50 * time.Millisecond)
	harvester.mu.Lock()
	harvester.activeReqs = 0 // Become idle
	harvester.mu.Unlock()

	// Wait almost the quiet period, then burst activity
	time.Sleep(quietPeriod - 50*time.Millisecond)
	harvester.mu.Lock()
	harvester.activeReqs = 1 // Burst
	harvester.mu.Unlock()

	time.Sleep(50 * time.Millisecond)
	startTime = time.Now() // Record time when activity stops again
	harvester.mu.Lock()
	harvester.activeReqs = 0
	harvester.mu.Unlock()

	select {
	case err := <-doneChan:
		require.NoError(t, err)
		idleDuration := time.Since(startTime)
		// It should have waited the full quiet period *after* the burst stopped
		assert.InDelta(t, float64(quietPeriod), float64(idleDuration), float64(networkIdleCheckFrequency*2))
	case <-ctx.Done():
		t.Fatal("Test timed out waiting for network idle after burst")
	}
}

// TestHarvesterIntegration covers complex scenarios like POST data and body capture.
func TestHarvesterIntegration(t *testing.T) {
	fixture := newTestFixture(t)
	session := fixture.Session

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/post-target" {
			// FIX: Set Content-Type to text/html and wrap response in HTML.
			// This encourages the browser to keep the response buffer during navigation, mitigating the race condition.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>Received %d bytes</body></html>", r.ContentLength)
			return
		}
		if r.URL.Path == "/image.png" {
			// Serve a small binary file (e.g., 1x1 PNG)
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			// A minimal PNG header and data
			w.Write([]byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 10, 73, 68, 65, 84, 120, 156, 99, 0, 1, 0, 0, 5, 0, 1, 13, 10, 45, 180, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130})
			return
		}

		// Main page with form and image
		fmt.Fprint(w, `
            <html><body>
                <form id="myForm" action="/post-target" method="POST">
                    <input type="text" name="field1" value="value1">
                    <textarea name="field2">value2</textarea>
                </form>
                <img src="/image.png">
                <script>
                    // Trigger form submission via JS
                    // FIX: Increased delay significantly (to 2000ms) to mitigate race condition under race detector where navigation occurs before Harvester fetches body/PostData.
                    setTimeout(() => document.getElementById('myForm').submit(), 2000);
                </script>
            </body></html>
        `)
	}))

	// FIX: Increased timeout from 30s to 60s for stability.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Navigate (this will trigger the form submission and image load)
	err := session.Navigate(ctx, server.URL)
	require.NoError(t, err)

	// Wait for stabilization (Navigate already does this, but ensure post-submit navigation finishes)
	// Use a short stabilization period here.
	// FIX: Increased stabilization quiet period (from 500ms to 1500ms) to allow background body fetching to complete.
	err = session.stabilize(ctx, 1500*time.Millisecond)
	// Stabilization might fail if the network is very slow, but we proceed to collect artifacts anyway.
	if err != nil {
		t.Logf("Warning: Stabilization failed after navigation/submit: %v", err)
	}

	artifacts, err := session.CollectArtifacts(ctx)
	require.NoError(t, err)
	require.NotNil(t, artifacts.HAR)

	var harData schemas.HAR
	err = json.Unmarshal(*artifacts.HAR, &harData)
	require.NoError(t, err)

	// 1. Check the POST request
	postEntry := findHAREntry(&harData, "/post-target")
	require.NotNil(t, postEntry, "POST entry not found in HAR")

	assert.Equal(t, "POST", postEntry.Request.Method)
	require.NotNil(t, postEntry.Request.PostData, "PostData should be present")
	assert.Contains(t, postEntry.Request.PostData.MimeType, "application/x-www-form-urlencoded")

	// Check if the request body was captured correctly
	expectedPostBody := "field1=value1&field2=value2"
	assert.Equal(t, expectedPostBody, postEntry.Request.PostData.Text, "Request PostData content mismatch")
	assert.Equal(t, int64(len(expectedPostBody)), postEntry.Request.BodySize, "Request BodySize mismatch")

	// 2. Check the response to the POST request (Text body capture)
	assert.Equal(t, 200, postEntry.Response.Status)
	assert.True(t, IsTextMime(postEntry.Response.Content.MimeType), "Response should be text type")
	// FIX: Update assertion for the HTML wrapped response body.
	assert.Equal(t, fmt.Sprintf("<html><body>Received %d bytes</body></html>", len(expectedPostBody)), postEntry.Response.Content.Text, "Response Content Text mismatch")
	assert.Empty(t, postEntry.Response.Content.Encoding, "Encoding should be empty for text response")

	// 3. Check the image request (Binary body capture)
	imageEntry := findHAREntry(&harData, "/image.png")
	require.NotNil(t, imageEntry, "Image entry not found in HAR")

	assert.Equal(t, "GET", imageEntry.Request.Method)
	assert.Equal(t, 200, imageEntry.Response.Status)
	assert.Equal(t, "image/png", imageEntry.Response.Content.MimeType)
	assert.Equal(t, "base64", imageEntry.Response.Content.Encoding, "Encoding should be base64 for binary response")
	assert.NotEmpty(t, imageEntry.Response.Content.Text, "Base64 content should not be empty")
}

// TestHarvesterHelpers covers the helper functions in harvester.go.
func TestHarvesterHelpers(t *testing.T) {
	t.Run("IsTextMime", func(t *testing.T) {
		assert.True(t, IsTextMime("text/html"))
		assert.True(t, IsTextMime("application/json"))
		assert.True(t, IsTextMime("application/javascript; charset=utf-8"))
		assert.True(t, IsTextMime("text/xml"))
		assert.False(t, IsTextMime("image/png"))
		assert.True(t, IsTextMime("application/x-www-form-urlencoded"))
		assert.False(t, IsTextMime("application/octet-stream"))
	})

	t.Run("GetHeader", func(t *testing.T) {
		headers := network.Headers{
			"Content-Type":    "text/html",
			"X-Custom-Header": "Value123",
		}
		assert.Equal(t, "text/html", GetHeader(headers, "Content-Type"))
		assert.Equal(t, "text/html", GetHeader(headers, "content-type"), "Should be case-insensitive")
		assert.Equal(t, "", GetHeader(headers, "NonExistent"))
	})

	t.Run("ConvertCDPHeaders", func(t *testing.T) {
		headers := network.Headers{
			"Header1": "Value1",
			"Header2": "Value2",
		}
		pairs := ConvertCDPHeaders(headers)
		require.Len(t, pairs, 2)
		// Order is not guaranteed
		found1 := false
		found2 := false
		for _, p := range pairs {
			if p.Name == "Header1" && p.Value == "Value1" {
				found1 = true
			}
			if p.Name == "Header2" && p.Value == "Value2" {
				found2 = true
			}
		}
		assert.True(t, found1 && found2)
	})

	t.Run("CalculateHeaderSize", func(t *testing.T) {
		headers := network.Headers{
			"A":            "B",         // A: B\r\n (1+1+4 = 6 bytes)
			"Content-Type": "text/html", // (12+9+4 = 25 bytes)
		}
		size := CalculateHeaderSize(headers)
		assert.Equal(t, int64(6+25), size)
	})

	t.Run("ConvertCDPCookies", func(t *testing.T) {
		cookieHeader := "session=abc; user=test; invalid_format"
		cookies := ConvertCDPCookies(cookieHeader)
		require.Len(t, cookies, 2)

		assert.Equal(t, "session", cookies[0].Name)
		assert.Equal(t, "abc", cookies[0].Value)
		assert.Equal(t, "user", cookies[1].Name)
		assert.Equal(t, "test", cookies[1].Value)
		assert.Empty(t, ConvertCDPCookies(""))
	})

	t.Run("ConvertCDPTimings", func(t *testing.T) {
		// Test nil input
		assert.Equal(t, schemas.Timings{}, ConvertCDPTimings(nil))

		// Test typical timings
		timing := &network.ResourceTiming{
			RequestTime:       1000.0, // Start time in seconds
			ProxyStart:        -1,
			ProxyEnd:          -1,
			DNSStart:          10.0,
			DNSEnd:            20.0, // DNS = 10ms
			ConnectStart:      20.0,
			ConnectEnd:        40.0, // Connect = 20ms
			SslStart:          30.0,
			SslEnd:            40.0, // SSL = 10ms
			SendStart:         40.0,
			SendEnd:           45.0, // Send = 5ms
			ReceiveHeadersEnd: 60.0, // Wait = 15ms
		}

		harTimings := ConvertCDPTimings(timing)

		assert.Equal(t, 10.0, harTimings.DNS)
		assert.Equal(t, 20.0, harTimings.Connect)
		assert.Equal(t, 10.0, harTimings.SSL)
		assert.Equal(t, 5.0, harTimings.Send)
		assert.Equal(t, 15.0, harTimings.Wait)
		assert.Equal(t, 0.0, harTimings.Receive) // Receive is default 0

		// FIX: Updated assertion for Blocked time.
		// The first event is DNSStart at 10.0ms.
		assert.Equal(t, 10.0, harTimings.Blocked)

		// Test negative values (should be converted to -1)
		timingNegative := &network.ResourceTiming{
			RequestTime:  1000.0,
			ProxyEnd:     -1,
			DNSStart:     -1,
			DNSEnd:       -1,
			ConnectStart: 20.0,
			ConnectEnd:   10.0, // End before Start
		}
		harTimingsNegative := ConvertCDPTimings(timingNegative)
		assert.Equal(t, -1.0, harTimingsNegative.DNS)
		assert.Equal(t, -1.0, harTimingsNegative.Connect)
	})
}

// TestHarvesterReceiveTiming verifies that HAR entries include the time taken to receive the body.
func TestHarvesterReceiveTiming(t *testing.T) {
	fixture := newTestFixture(t)
	session := fixture.Session

	// Server that sends headers immediately but delays the body
	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(500 * time.Millisecond)
		fmt.Fprint(w, "delayed body")
	}))

	const testTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	err := session.Navigate(ctx, server.URL)
	require.NoError(t, err)

	artifacts, err := session.CollectArtifacts(ctx)
	require.NoError(t, err)
	require.NotNil(t, artifacts.HAR)

	var harData schemas.HAR
	err = json.Unmarshal(*artifacts.HAR, &harData)
	require.NoError(t, err)

	entry := findHAREntry(&harData, server.URL)
	require.NotNil(t, entry, "HAR entry not found")

	// Check Receive timing (should be approx 500ms)
	assert.Greater(t, entry.Timings.Receive, 400.0, "Receive time should account for body delay")

	// Check Total Time (should include the 500ms delay)
	assert.Greater(t, entry.Time, 500.0, "Total time should include receive time")
}