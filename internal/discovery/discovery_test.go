package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// -- Mocks and Test Helpers --

// mockHTTPClient allows us to simulate HTTP responses for testing the PassiveRunner.
// No need to hit the actual network, which makes tests fast and reliable.
type mockHTTPClient struct {
	// A map of URL to a function that returns the desired response.
	// This provides a lot of flexibility for different test cases.
	responses map[string]func() (body []byte, statusCode int, err error)
}

// Get fulfills the HTTPClient interface.
func (m *mockHTTPClient) Get(ctx context.Context, url string) ([]byte, int, error) {
	if respFunc, ok := m.responses[url]; ok {
		return respFunc()
	}
	// Default response for any URL not explicitly mocked.
	return nil, http.StatusNotFound, fmt.Errorf("mockHTTPClient: no response for %s", url)
}

// mockBrowserInteractor simulates the behavior of a web browser for the Engine tests.
type mockBrowserInteractor struct {
	// A map of URL to the links that should be "found" on that page.
	pages map[string][]string
}

func (m *mockBrowserInteractor) NavigateAndExtract(ctx context.Context, url string) ([]string, error) {
	if links, ok := m.pages[url]; ok {
		return links, nil
	}
	return nil, fmt.Errorf("mockBrowserInteractor: no page data for %s", url)
}

// -- Test Cases --

// TestBasicScopeManager verifies that our scope logic correctly identifies
// in scope and out of scope URLs. This is critical to prevent scope creep.
func TestBasicScopeManager(t *testing.T) {
	// Table driven tests are a clean way to test multiple scenarios.
	testCases := []struct {
		name              string
		initialURL        string
		includeSubdomains bool
		urlToCheck        string
		expectedInScope   bool
		expectError       bool
	}{
		{
			name:              "Root domain is in scope",
			initialURL:        "https://example.com",
			includeSubdomains: true,
			urlToCheck:        "https://example.com/path",
			expectedInScope:   true,
		},
		{
			name:              "Subdomain is in scope when enabled",
			initialURL:        "https://example.com",
			includeSubdomains: true,
			urlToCheck:        "https://sub.example.com",
			expectedInScope:   true,
		},
		{
			name:              "Subdomain is not in scope when disabled",
			initialURL:        "https://example.com",
			includeSubdomains: false,
			urlToCheck:        "https://sub.example.com",
			expectedInScope:   false,
		},
		{
			name:              "Different domain is out of scope",
			initialURL:        "https://example.com",
			includeSubdomains: true,
			urlToCheck:        "https://another-domain.com",
			expectedInScope:   false,
		},
		{
			name:              "Handles complex TLDs correctly",
			initialURL:        "https://www.example.co.uk/test",
			includeSubdomains: true,
			urlToCheck:        "https://api.example.co.uk",
			expectedInScope:   true,
		},
		{
			name:              "Prevents partial domain matching",
			initialURL:        "https://example.com",
			includeSubdomains: true,
			urlToCheck:        "https://not-example.com",
			expectedInScope:   false,
		},
		{
			name:        "Invalid initial URL",
			initialURL:  "://invalid",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := NewBasicScopeManager(tc.initialURL, tc.includeSubdomains)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			u, err := url.Parse(tc.urlToCheck)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedInScope, scope.IsInScope(u))
		})
	}
}

// TestPassiveRunner covers the passive discovery techniques like crt.sh and sitemap parsing.
func TestPassiveRunner(t *testing.T) {
	logger := zap.NewNop()
	scope, err := NewBasicScopeManager("https://example.com", true)
	require.NoError(t, err)

	t.Run("checkCrtSh finds subdomains", func(t *testing.T) {
		// Simulate a successful response from crt.sh
		crtShURL := "https://crt.sh/?q=%.example.com&output=json"
		mockResp := `[{"name_value": "example.com"}, {"name_value": "sub.example.com"}, {"name_value": "*.wildcard.example.com\nwww.example.com"}]`
		client := &mockHTTPClient{
			responses: map[string]func() ([]byte, int, error){
				crtShURL: func() ([]byte, int, error) {
					return []byte(mockResp), http.StatusOK, nil
				},
			},
		}

		// Setup a temporary cache directory for this test.
		cacheDir, err := os.MkdirTemp("", "passive_cache_*")
		require.NoError(t, err)
		defer os.RemoveAll(cacheDir)

		mockConfig := &mocks.MockConfig{}
		discoveryConfig := config.DiscoveryConfig{
			CacheDir:       cacheDir,
			CrtShRateLimit: 10, // Set a non-zero rate limit to prevent test hanging
		}
		mockConfig.On("Discovery").Return(discoveryConfig)

		runner := NewPassiveRunner(mockConfig, client, scope, logger)
		resultsChan := make(chan string, 100)
		go func() {
			defer close(resultsChan)
			// Call the specific function under test to keep the test focused.
			rootDomain := scope.GetRootDomain()
			runner.checkCrtSh(context.Background(), rootDomain, resultsChan)
		}()

		// Collect results from the channel
		var found []string
		for res := range resultsChan {
			found = append(found, res)
		}

		// Check the results. We expect URLs to be fully formed.
		assert.Contains(t, found, "https://example.com")
		assert.Contains(t, found, "https://sub.example.com")
		assert.Contains(t, found, "https://wildcard.example.com")
		assert.Contains(t, found, "https://www.example.com")

		// Verify that a cache file was created.
		cacheFile := filepath.Join(cacheDir, "crt_cache_example_com.json")
		_, err = os.Stat(cacheFile)
		assert.NoError(t, err, "Cache file should have been created")
	})

	t.Run("checkRobotsAndSitemaps", func(t *testing.T) {
		var server *httptest.Server
		// Use httptest to create a real local server for testing robots.txt and sitemaps.
		// We declare the server variable before the handler so we can refer to it inside the handler.
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/robots.txt":
				fmt.Fprintln(w, "User-agent: *")
				fmt.Fprintln(w, "Disallow: /private/")
				// The handler closure can now safely access the server.URL.
				fmt.Fprintln(w, "Sitemap: "+server.URL+"/sitemap.xml")
			case "/sitemap.xml":
				fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?>`)
				fmt.Fprintln(w, `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
				fmt.Fprintln(w, `<url><loc>`+server.URL+`/page1</loc></url>`)
				fmt.Fprintln(w, `</urlset>`)
			default:
				http.NotFound(w, r)
			}
		})
		server = httptest.NewServer(handler)
		defer server.Close()

		// The httpClientAdapter lets us use the test server with our interface.
		client := &httpClientAdapter{client: server.Client()}
		mockConfig := &mocks.MockConfig{}
		discoveryConfig := config.DiscoveryConfig{}
		mockConfig.On("Discovery").Return(discoveryConfig)
		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		// A more specific scope for this test case.
		testScope, err := NewBasicScopeManager(server.URL, true)
		require.NoError(t, err)

		runner := NewPassiveRunner(mockConfig, client, testScope, logger)
		resultsChan := make(chan string, 100)
		// We call checkRobotsAndSitemaps directly to isolate the test and avoid
		// the network call that runner.Run() would otherwise trigger.
		// This makes the test faster and more reliable.
		go func() {
			defer close(resultsChan)
			runner.checkRobotsAndSitemaps(context.Background(), serverURL, resultsChan)
		}()

		var found []string
		for res := range resultsChan {
			found = append(found, res)
		}

		assert.Contains(t, found, server.URL+"/private/")
		assert.Contains(t, found, server.URL+"/page1")
	})
}

// TestEngine_normalizeAndValidate is a critical test for the URL processing logic.
// Incorrect normalization can lead to missed pages or crawling out of scope.
func TestEngine_normalizeAndValidate(t *testing.T) {
	scope, err := NewBasicScopeManager("https://example.com", true)
	require.NoError(t, err)
	engine := &Engine{scope: scope}

	testCases := []struct {
		name        string
		rawURL      string
		baseURL     string
		expectedURL string
		expectError bool
	}{
		{"Absolute URL in scope", "https://example.com/path", "https://example.com", "https://example.com/path", false},
		{"Relative URL", "/about", "https://example.com/home", "https://example.com/about", false},
		{"Out of scope", "https://other.com", "https://example.com", "", true},
		{"Unsupported scheme", "ftp://example.com", "https://example.com", "", true},
		{"Removes fragment", "https://example.com/page#section", "https://example.com", "https://example.com/page", false},
		{"Normalizes empty path", "https://example.com", "https://example.com", "https://example.com/", false},
		{"Ignored extension", "https://example.com/style.css", "https://example.com", "", true},
		{"Relative URL without base", "/path", "", "", true},
		{"Subdomain in scope", "https://sub.example.com", "https://example.com", "https://sub.example.com/", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := engine.normalizeAndValidate(tc.rawURL, tc.baseURL)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedURL, u.String())
			}
		})
	}
}

// TestEngine_Start is an integration test for the core crawling logic.
// It brings together the engine, scope, and mocks for its dependencies.
func TestEngine_Start(t *testing.T) {
	t.Run("Crawls to max depth and respects scope", func(t *testing.T) {
		// -- Setup Mocks and Engine --
		scope, err := NewBasicScopeManager("https://example.com", true)
		require.NoError(t, err)

		kgClient := new(mocks.MockKGClient)
		kgClient.On("AddNode", mock.Anything, mock.Anything).Return(nil)
		kgClient.On("AddEdge", mock.Anything, mock.Anything).Return(nil)

		// This defines the "shape" of the website we're crawling.
		browser := &mockBrowserInteractor{
			pages: map[string][]string{
				"https://example.com/":           {"/page1", "/page2", "https://sub.example.com/"},
				"https://example.com/page1":      {"/page1_sub1"},
				"https://example.com/page2":      {"https://external.com/"}, // Out of scope link
				"https://sub.example.com/":       {},
				"https://example.com/page1_sub1": {"/final"}, // This will be at depth 2
			},
		}

		// For this test, we'll disable passive discovery to focus on the active crawler.
		passiveDisabled := false
		mockConfig := &mocks.MockConfig{}
		discoveryConfig := config.DiscoveryConfig{
			MaxDepth:       2, // We expect it to stop after page1_sub1
			Concurrency:    2,
			Timeout:        5 * time.Second,
			PassiveEnabled: &passiveDisabled,
		}
		scannersConfig := config.ScannersConfig{
			Active: config.ActiveScannersConfig{
				Taint: config.TaintConfig{Enabled: true},
			},
		}
		mockConfig.On("Discovery").Return(discoveryConfig)
		mockConfig.On("Scanners").Return(scannersConfig)

		// We don't need a real passive runner here.
		engine := NewEngine(mockConfig, scope, kgClient, browser, nil, zap.NewNop())

		// -- Execute --
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		taskChan, err := engine.Start(ctx, []string{"https://example.com"})
		require.NoError(t, err)

		// -- Verify --
		var tasks []schemas.Task
		for task := range taskChan {
			tasks = append(tasks, task)
		}

		// Create a map of URLs from the tasks for easier checking.
		taskUrls := make(map[string]bool)
		for _, task := range tasks {
			taskUrls[task.TargetURL] = true
		}

		assert.Len(t, tasks, 5, "Should have discovered 5 unique, in-scope URLs")
		assert.Contains(t, taskUrls, "https://example.com/")
		assert.Contains(t, taskUrls, "https://example.com/page1")
		assert.Contains(t, taskUrls, "https://example.com/page2")
		assert.Contains(t, taskUrls, "https://sub.example.com/")
		assert.Contains(t, taskUrls, "https://example.com/page1_sub1")

		// The crawler should not have processed the depth 2 link or the out of scope link
		assert.NotContains(t, taskUrls, "https://example.com/final")
		assert.NotContains(t, taskUrls, "https://external.com/")

		// Verify the mock's expectations were met.
		kgClient.AssertExpectations(t)
	})
}
