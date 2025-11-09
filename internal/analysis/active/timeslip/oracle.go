// internal/analysis/active/timeslip/oracle.go
package timeslip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// SuccessOracle determines if a response indicates a successful operation based on configuration.
type SuccessOracle struct {
	config    *Config
	isGraphQL bool
	// FIX: Store compiled regexes here instead of the shared Config struct.
	// This resolves the data race (CWE-362) detected during concurrent Analyzer initialization.
	bodyRx   *regexp.Regexp
	headerRx *regexp.Regexp
}

// NewSuccessOracle initializes the oracle with the validated configuration.
func NewSuccessOracle(config *Config, isGraphQL bool) (*SuccessOracle, error) {
	// Initialize the oracle instance.
	oracle := &SuccessOracle{
		config:    config,
		isGraphQL: isGraphQL,
	}

	// Compile regexes during initialization for performance.
	if config != nil && config.Success.BodyRegex != "" {
		rx, err := regexp.Compile(config.Success.BodyRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid BodyRegex: %w", err)
		}
		// FIX: Store in the oracle instance.
		oracle.bodyRx = rx
	}

	if config != nil && config.Success.HeaderRegex != "" {
		rx, err := regexp.Compile(config.Success.HeaderRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid HeaderRegex: %w", err)
		}
		// FIX: Store in the oracle instance.
		oracle.headerRx = rx
	}

	return oracle, nil
}

// IsSuccess evaluates the RaceResponse against the configured success conditions.
func (o *SuccessOracle) IsSuccess(resp *RaceResponse) bool {
	if resp.Error != nil ||
		resp.ParsedResponse == nil {
		return false
	}

	// 1. Check HTTP Status Code.
	if !o.checkStatusCode(resp.StatusCode) {
		return false
	}

	// 2. Check Body Regex.
	// FIX: Use the regex compiled in the oracle instance.
	if o.bodyRx != nil {
		if !o.bodyRx.Match(resp.SpecificBody) {
			return false
		}
	}

	// 3. Check Header Regex.
	// FIX: Use the regex compiled in the oracle instance.
	if o.headerRx != nil {
		if !o.checkHeaderRegex(resp.Headers) {
			return false
		}
	}

	// 4. If GraphQL, check application-layer success (even if HTTP status is 200 OK).
	if o.isGraphQL {
		if !isGraphQLSpecSuccess(resp.SpecificBody) {
			return false
		}
	}

	// If all configured checks pass, it's a success.
	return true
}

func (o *SuccessOracle) checkStatusCode(statusCode int) bool {
	// Handle case where config might be nil (though NewAnalyzer prevents this, defensive coding is good).
	if o.config == nil {
		return (statusCode >= 200 && statusCode < 400)
	}

	configuredCodes := o.config.Success.StatusCodes
	if len(configuredCodes) > 0 {
		for _, code := range configuredCodes {
			if statusCode == code {
				return true
			}
		}
		return false
	}

	// Default behavior if no codes are configured (2xx and 3xx).
	// Note: For GraphQL, 200 OK is standard transport, but we rely on isGraphQLSpecSuccess for operation success.
	return (statusCode >= 200 && statusCode < 400)
}

func (o *SuccessOracle) checkHeaderRegex(headers http.Header) bool {
	// FIX: Use the regex compiled in the oracle instance.
	rx := o.headerRx
	if rx == nil {
		return true
	}

	// Use a pooled buffer to avoid allocations.
	buf := getBuffer()
	defer putBuffer(buf)

	// Must match at least one header line (Key: Value).
	for key, values := range headers {
		for _, value := range values {
			buf.Reset() // Reset buffer for the next iteration
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)

			// Use rx.Match which accepts []byte, avoiding string allocation.
			if rx.Match(buf.Bytes()) {
				return true
			}
		}
	}
	return false
}

// isGraphQLSpecSuccess analyzes a GraphQL response body according to the spec (absence of "errors" key).
func isGraphQLSpecSuccess(responseBody []byte) bool {
	// Ensure it's a JSON object before attempting to parse.
	trimmedBody := bytes.TrimSpace(responseBody)
	if len(trimmedBody) == 0 ||
		trimmedBody[0] != '{' {
		// If it's not a JSON object, it might not be a standard GraphQL response, rely on other indicators.
		// However, if we expect GraphQL, a non-JSON object is usually a failure.
		return false
	}

	// We only need to parse the top-level structure to check for the "errors" key.
	var gqlResp struct {
		// Use RawMessage to avoid parsing the potentially complex structure.
		Errors json.RawMessage `json:"errors"`
	}

	if err := json.Unmarshal(responseBody, &gqlResp); err != nil {
		// If we can't parse it as a GraphQL response object, assume failure.
		return false
	}

	// Success criteria: The "errors" key must be absent or explicitly null.
	hasErrors := len(gqlResp.Errors) > 0 && string(gqlResp.Errors) != "null"

	return !hasErrors
}
