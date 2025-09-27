// File: internal/discovery/adapter.go
package discovery

import (
	"context"
	"io"
	"net/http"

	// This is your application's main, feature-rich HTTP client.
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
)

// HTTPClient interface (defined elsewhere in discovery package, e.g., passive.go):
/*
type HTTPClient interface {
	Get(ctx context.Context, url string) (body []byte, statusCode int, err error)
}
*/

// networkClientAdapter implements the local discovery.HTTPClient interface
// by wrapping the main application's network.Client.
type networkClientAdapter struct {
	client *network.Client
}

// NewHTTPClientAdapter is the public constructor that solves the "undefined" error.
func NewHTTPClientAdapter(client *network.Client) HTTPClient {
	return &networkClientAdapter{client: client}
}

// Get is the method that fulfills the interface contract.
// FIX: network.Client embeds http.Client, which does not have a Get method matching this signature.
// We must adapt the standard http.Client behavior (using Do) to the required interface.
func (a *networkClientAdapter) Get(ctx context.Context, url string) ([]byte, int, error) {
	// 1. Create the request with the provided context.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}

	// 2. Execute the request using the underlying network.Client (which has the Do method).
	resp, err := a.client.Do(req)
	if err != nil {
		// Network error or timeout.
		return nil, 0, err
	}
	defer resp.Body.Close()

	// 3. Read the response body.
	// Using io.ReadAll (available since Go 1.16, replacing ioutil.ReadAll).
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Error reading body, but we still have the status code.
		return nil, resp.StatusCode, err
	}

	// 4. Return the results in the required format.
	return body, resp.StatusCode, nil
}