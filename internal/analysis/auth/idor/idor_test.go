package idor_test

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/auth/idor"
)

// MockSession is a test implementation of the idor.Session interface.
type MockSession struct {
	AuthCookie *http.Cookie
	IsAuthed   bool
}

func (s *MockSession) IsAuthenticated() bool {
	return s.IsAuthed
}

func (s *MockSession) ApplyToRequest(req *http.Request) {
	if s.IsAuthed && s.AuthCookie != nil {
		req.AddCookie(s.AuthCookie)
	}
}

func TestIDORAnalyzer(t *testing.T) {
	// 1. Setup a mock server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		cookie, err := r.Cookie("session_id")

		if err != nil || cookie == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if userID == "123" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"user": "alice", "data": "secret_data_for_alice"}`)
		} else {
			http.NotFound(w, r)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	// 2. Create two authenticated sessions
	sessionAlice := &MockSession{
		IsAuthed:   true,
		AuthCookie: &http.Cookie{Name: "session_id", Value: "session_for_alice"},
	}
	sessionBob := &MockSession{
		IsAuthed:   true,
		AuthCookie: &http.Cookie{Name: "session_id", Value: "session_for_bob"},
	}

	// 3. Create a request/response pair
	reqURL, _ := url.Parse(server.URL + "/api/user?user_id=123")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}
	sessionAlice.ApplyToRequest(req)

	resBody := `{"user": "alice", "data": "secret_data_for_alice"}`
	res := &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewBufferString(resBody)),
		ContentLength: int64(len(resBody)),
	}

	traffic := []idor.RequestResponsePair{
		{Request: req, Response: res},
	}

	// 4. Setup the analyzer
	analyzer := idor.NewIDORAnalyzer(log.New(io.Discard, "", 0))
	config := idor.Config{
		ParametersToTest: []string{"user_id"},
		Session:          sessionAlice,
		SecondSession:    sessionBob,
	}

	// 5. Run the analysis
	findings, err := analyzer.AnalyzeTraffic(traffic, config)

	// 6. Assert the results
	assert.NoError(t, err, "Analysis should not produce an error")
	assert.Len(t, findings, 1, "Should have found exactly one IDOR vulnerability")
	if len(findings) > 0 {
		finding := findings[0]
		assert.Equal(t, req.URL.String(), finding.URL)
		assert.Equal(t, "user_id", finding.Parameter)
	}
}