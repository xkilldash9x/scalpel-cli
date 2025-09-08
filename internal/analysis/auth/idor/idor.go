// internal/analysis/auth/idor/idor.go
package idor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.comcom/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// NOTE: The type and struct definitions (IdentifierType, IdentifierLocation, ObservedIdentifier)
// have been moved to types.go to act as the single source of truth for the idor package
// and resolve redeclaration errors.

// -- Identifier Classification --
// This section contains the logic for identifying and classifying potential IDs.

// These regexes are the core of the classification logic.
var (
	regexUUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	// regexNumeric: Allow 1 to 19 digits (to fit within int64).
	regexNumeric = regexp.MustCompile(`^\d{1,19}$`)
	// regexBase64 includes URL-safe characters (-_) and handles potential lack of padding.
	regexBase64 = regexp.MustCompile(`^([A-Za-z0-9+/=_-]{4})*([A-Za-z0-9+/=_-]{2,4})?$`)
	// MongoDB ObjectID format
	regexObjectID = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
	// Heuristic regexes to reduce false positives
	regexOnlyLetters = regexp.MustCompile(`^[a-zA-Z]+$`)
	regexOnlyNumbers = regexp.MustCompile(`^[0-9]+$`)
)

// ClassifyIdentifier determines the type of an identifier based on regex and heuristics.
func ClassifyIdentifier(value string) core.IdentifierType {
	if len(value) == 0 {
		return core.TypeUnknown
	}
	// Order matters: Check specific formats first.
	if regexUUID.MatchString(value) {
		return core.TypeUUID
	}
	if regexObjectID.MatchString(value) {
		return core.TypeObjectID
	}
	if regexNumeric.MatchString(value) {
		// Heuristic: Filter out common numeric values that are unlikely to be IDs (like years or common ports)
		if len(value) <= 4 {
			if num, err := strconv.Atoi(value); err == nil {
				// Filter years 1980-2100
				if num >= 1980 && num <= 2100 {
					return core.TypeUnknown
				}
				// Filter common ports
				if num == 80 || num == 443 || num == 8080 || num == 8443 {
					return core.TypeUnknown
				}
			}
		}
		return core.TypeNumericID
	}
	// Check Base64 heuristic (length >= 8 and matches regex).
	if len(value) >= 8 && regexBase64.MatchString(value) {
		if isLikelyBase64(value) {
			return core.TypeBase64
		}
	}
	return core.TypeUnknown
}

// isLikelyBase64 is a helper function to attempt decoding using various Base64 schemes.
func isLikelyBase64(value string) bool {
	// Heuristic: If it's just letters or just numbers, it's unlikely to be a Base64 ID.
	// This helps avoid classifying common words like "username" or long numeric strings as Base64.
	// While a valid Base64 string could be all letters/numbers, it's less common for IDs.
	if regexOnlyLetters.MatchString(value) || regexOnlyNumbers.MatchString(value) {
		return false
	}

	encodings := []base64.Encoding{
		*base64.StdEncoding,
		*base64.URLEncoding,
		*base64.RawStdEncoding,
		*base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if _, err := enc.DecodeString(value); err == nil {
			return true
		}
	}
	return false
}

// -- Identifier Extraction --
// This section contains the logic for finding identifiers within HTTP requests.

// ExtractIdentifiers searches all parts of an HTTP request for classifiable identifiers.
func ExtractIdentifiers(req *http.Request, body []byte) []core.ObservedIdentifier {
	var identifiers []core.ObservedIdentifier
	// 1. URL Path
	segments := strings.Split(req.URL.Path, "/")
	for i, segment := range segments { // Iterate with index i
		if idType := ClassifyIdentifier(segment); idType != core.TypeUnknown {
			identifiers = append(identifiers, core.ObservedIdentifier{
				Value:     segment,
				Type:      idType,
				Location:  core.LocationURLPath,
				PathIndex: i, // Store the index
			})
		}
	}
	// 2. Query Parameters
	for key, values := range req.URL.Query() {
		for _, value := range values {
			if idType := ClassifyIdentifier(value); idType != core.TypeUnknown {
				identifiers = append(identifiers, core.ObservedIdentifier{
					Value:    value,
					Type:     idType,
					Location: core.LocationQueryParam,
					Key:      key,
				})
			}
		}
	}
	// 3. JSON Body
	if strings.Contains(req.Header.Get("Content-Type"), "application/json") && len(body) > 0 {
		var data interface{}
		// Use json.Decoder with UseNumber() for accurate numeric handling.
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&data); err == nil {
			extractFromJSON(data, "", &identifiers)
		}
	}
	// 4. Headers (excluding standard auth/cookie headers managed by session management)
	for key, values := range req.Header {
		lowerKey := strings.ToLower(key)
		if lowerKey == "authorization" || lowerKey == "cookie" {
			continue
		}

		// Heuristic: Check headers that often contain custom IDs.
		if strings.Contains(lowerKey, "id") || strings.Contains(lowerKey, "user") || strings.Contains(lowerKey, "account") || strings.HasPrefix(lowerKey, "x-") {
			for _, value := range values {
				if idType := ClassifyIdentifier(value); idType != core.TypeUnknown {
					identifiers = append(identifiers, core.ObservedIdentifier{
						Value:    value,
						Type:     idType,
						Location: core.LocationHeader,
						Key:      key,
					})
				}
			}
		}
	}
	return identifiers
}

// extractFromJSON recursively searches a decoded JSON structure for identifiers.
// It generates dot-separated paths like "user.id" or "items.0.id".
func extractFromJSON(data interface{}, prefix string, identifiers *[]core.ObservedIdentifier) {
	switch typedData := data.(type) {
	case map[string]interface{}:
		for key, value := range typedData {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			extractValue(value, fullKey, identifiers)
		}
	case []interface{}:
		for i, value := range typedData {
			fullKey := fmt.Sprintf("%s.%d", prefix, i)
			// Handle root arrays correctly
			if prefix == "" {
				fullKey = fmt.Sprintf("%d", i)
			}
			extractValue(value, fullKey, identifiers)
		}
	}
}

// extractValue is a helper for extractFromJSON that handles the actual value classification.
func extractValue(value interface{}, fullKey string, identifiers *[]core.ObservedIdentifier) {
	switch v := value.(type) {
	case string:
		if idType := ClassifyIdentifier(v); idType != core.TypeUnknown {
			*identifiers = append(*identifiers, core.ObservedIdentifier{
				Value:    v,
				Type:     idType,
				Location: core.LocationJSONBody,
				Key:      fullKey,
			})
		}
	case json.Number:
		// Handle numbers extracted using UseNumber().
		strVal := v.String()
		if idType := ClassifyIdentifier(strVal); idType == core.TypeNumericID {
			*identifiers = append(*identifiers, core.ObservedIdentifier{
				Value:    strVal,
				Type:     idType,
				Location: core.LocationJSONBody,
				Key:      fullKey,
			})
		}
	case map[string]interface{}, []interface{}:
		extractFromJSON(v, fullKey, identifiers)
	}
}

// -- Identifier Modification --
// This section contains logic for generating and applying test values for predictive analysis.

// GenerateTestValue creates a plausible alternative identifier value for testing.
func GenerateTestValue(identifier core.ObservedIdentifier) (string, error) {
	switch identifier.Type {
	case core.TypeNumericID:
		num, err := strconv.ParseInt(identifier.Value, 10, 64)
		if err != nil {
			return "", err
		}
		// Simple increment for prediction.
		return strconv.FormatInt(num+1, 10), nil

	case core.TypeBase64:
		// Decode, flip a bit, and re-encode.
		var decoded []byte
		var usedEncoding *base64.Encoding
		encodings := []base64.Encoding{
			*base64.StdEncoding, *base64.URLEncoding, *base64.RawStdEncoding, *base64.RawURLEncoding,
		}

		for _, enc := range encodings {
			var err error
			decoded, err = enc.DecodeString(identifier.Value)
			if err == nil {
				usedEncoding = &enc
				break
			}
		}

		if usedEncoding == nil {
			return "", fmt.Errorf("failed to decode Base64 value %s", identifier.Value)
		}

		if len(decoded) > 0 {
			// Flip the last bit of the last byte.
			decoded[len(decoded)-1] ^= 0x01
		} else {
			return "", fmt.Errorf("decoded Base64 value is empty")
		}
		return usedEncoding.EncodeToString(decoded), nil

	case core.TypeUUID:
		// UUIDs are not predictable. We return an error to signal that predictive testing should be skipped for this type.
		return "", fmt.Errorf("UUIDs are not suitable for predictive IDOR testing")

	case core.TypeObjectID:
		// Slightly modify the ObjectID predictably.
		if len(identifier.Value) != 24 {
			return "", fmt.Errorf("invalid ObjectID length")
		}
		// Simple modification: change the last character predictably.
		chars := []rune(identifier.Value)
		lastChar := chars[len(chars)-1]
		// Cycle through hex characters 0-9, a-f.
		if lastChar >= '0' && lastChar < '9' {
			chars[len(chars)-1]++
		} else if lastChar == '9' {
			chars[len(chars)-1] = 'a'
		} else if (lastChar >= 'a' && lastChar < 'f') || (lastChar >= 'A' && lastChar < 'F') {
			chars[len(chars)-1]++
		} else {
			// If 'f' or 'F', wrap around to '0'.
			chars[len(chars)-1] = '0'
		}
		return string(chars), nil
	}
	return "", fmt.Errorf("cannot generate predictable test value for type %s", identifier.Type)
}

// ApplyTestValue modifies a cloned request with a generated test ID.
func ApplyTestValue(req *http.Request, body []byte, identifier core.ObservedIdentifier, testValue string) (*http.Request, []byte, error) {
	clonedReq := req.Clone(req.Context())
	newBody := body

	switch identifier.Location {
	case core.LocationURLPath:
		segments := strings.Split(clonedReq.URL.Path, "/")
		// Use the specific index for replacement
		idx := identifier.PathIndex
		if idx >= 0 && idx < len(segments) {
			// Verify that the value at the index still matches the original observed value
			if segments[idx] == identifier.Value {
				segments[idx] = testValue
				clonedReq.URL.Path = strings.Join(segments, "/")
			}
		}

	case core.LocationQueryParam:
		q := clonedReq.URL.Query()
		q.Set(identifier.Key, testValue)
		clonedReq.URL.RawQuery = q.Encode()

	case core.LocationHeader:
		clonedReq.Header.Set(identifier.Key, testValue)

	case core.LocationJSONBody:
		// Use the robust structured modification method.
		var err error
		newBody, err = modifyJSONPayload(body, identifier, testValue)
		if err != nil {
			return nil, body, fmt.Errorf("failed to modify JSON body for key '%s': %w", identifier.Key, err)
		}
		clonedReq.ContentLength = int64(len(newBody))
	}

	return clonedReq, newBody, nil
}

// modifyJSONPayload modifies the JSON structure securely instead of using string replacement.
func modifyJSONPayload(body []byte, identifier core.ObservedIdentifier, testValue string) ([]byte, error) {
	var data interface{}
	// Use Decoder with UseNumber for consistency and precision.
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode JSON payload: %w", err)
	}

	path := identifier.Key

	// Determine the appropriate type for the replacement value.
	var typedValue interface{}
	if identifier.Type == core.TypeNumericID {
		// Keep it as json.Number if the original was numeric.
		typedValue = json.Number(testValue)
	} else {
		typedValue = testValue
	}

	// Navigate the structure and set the value.
	if err := setJSONValueByPath(data, strings.Split(path, "."), typedValue); err != nil {
		return nil, fmt.Errorf("failed to set JSON value by path '%s': %w", path, err)
	}

	return json.Marshal(data)
}

// setJSONValueByPath recursively navigates the JSON structure (maps and slices) to set a value.
func setJSONValueByPath(data interface{}, path []string, value interface{}) error {
	if len(path) == 0 {
		return fmt.Errorf("path cannot be empty")
	}

	currentKey := path[0]
	remainingPath := path[1:]

	// Case 1: Map (JSON Object)
	if m, ok := data.(map[string]interface{}); ok {
		if _, exists := m[currentKey]; !exists {
			return fmt.Errorf("key '%s' not found in JSON object", currentKey)
		}

		if len(remainingPath) == 0 {
			// End of the path. Set the value.
			m[currentKey] = value
			return nil
		}
		// Recurse into the next level.
		return setJSONValueByPath(m[currentKey], remainingPath, value)
	}

	// Case 2: Slice (JSON Array)
	if s, ok := data.([]interface{}); ok {
		index, err := strconv.Atoi(currentKey)
		if err != nil {
			return fmt.Errorf("invalid array index '%s' in path (expected integer)", currentKey)
		}
		if index < 0 || index >= len(s) {
			return fmt.Errorf("array index %d out of bounds (length %d)", index, len(s))
		}

		if len(remainingPath) == 0 {
			// End of the path. Set the value.
			s[index] = value
			return nil
		}
		// Recurse into the next level.
		return setJSONValueByPath(s[index], remainingPath, value)
	}

	return fmt.Errorf("unsupported JSON data structure type or path mismatch at segment '%s'. Expected map or slice, got %T", currentKey, data)
}
