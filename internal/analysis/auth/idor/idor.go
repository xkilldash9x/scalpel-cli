package idor

import (
	"fmt"
	"log"
	"net/http"
)

// ErrUnauthenticated is returned when one or both sessions in the config are not authenticated.
type ErrUnauthenticated struct{}

func (e *ErrUnauthenticated) Error() string {
	return "IDOR analysis requires two distinct authenticated sessions"
}

// Detect performs the primary IDOR analysis by replaying requests with a secondary user session.
func Detect(traffic []RequestResponsePair, config Config, logger *log.Logger) ([]Finding, error) {
	var findings []Finding
	client := &http.Client{}

	// Identify parameters that look like IDs (e.g., "id", "user_id", "accountId").
	potentialIDParams := identifyPotentialIDParameters(traffic, config.ParametersToTest)

	// For each request made by the primary user...
	for _, pair := range traffic {
		// For each parameter we identified as a potential ID...
		for paramName, originalValue := range potentialIDParams {
			// Check if this specific request contains the parameter.
			if !requestContainsParam(pair.Request, paramName) {
				continue
			}

			logger.Printf("Testing endpoint '%s' with parameter '%s'", pair.Request.URL.Path, paramName)

			// Create a new request based on the original, but for the second user.
			replayReq, err := http.NewRequest(pair.Request.Method, pair.Request.URL.String(), pair.Request.Body)
			if err != nil {
				continue
			}

			// Copy headers and apply the second user's session tokens/cookies.
			replayReq.Header = pair.Request.Header
			config.SecondSession.ApplyToRequest(replayReq)

			// Execute the request as the second user.
			resp, err := client.Do(replayReq)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for vulnerability
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// Naive check: A more robust check would compare response bodies.
				if resp.ContentLength == pair.Response.ContentLength {
					findings = append(findings, Finding{
						URL:           pair.Request.URL.String(),
						Parameter:     paramName,
						OriginalValue: originalValue,
						TestedValue:   originalValue,
						Method:        pair.Request.Method,
						Evidence:      fmt.Sprintf("Accessed resource with status %d and identical content length.", resp.StatusCode),
					})
				}
			}
		}
	}

	return findings, nil
}

// identifyPotentialIDParameters scans traffic and returns a map of parameter names and example values.
func identifyPotentialIDParameters(traffic []RequestResponsePair, explicitParams []string) map[string]string {
	params := make(map[string]string)
	commonIDNames := []string{"id", "uuid", "user_id", "account_id", "profile_id"}

	for _, p := range explicitParams {
		params[p] = ""
	}

	for _, pair := range traffic {
		for key, values := range pair.Request.URL.Query() {
			for _, common := range commonIDNames {
				if key == common && len(values) > 0 {
					params[key] = values[0]
				}
			}
		}
	}
	return params
}

// requestContainsParam checks if a request's query parameters contain the given key.
func requestContainsParam(req *http.Request, paramName string) bool {
	return req.URL.Query().Get(paramName) != ""
}