// helpers.go
package idor

import (
	"bytes"
	"context" // Added import
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var (
	// Improved UUID regex to adhere closely to RFC 4122 (version and variant bits) for accuracy
	uuidRegex = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	// Numeric regex allowing for potentially large integers (up to 19 digits for 64-bit int)
	numericRegex = regexp.MustCompile(`\b\d{1,19}\b`)
)

// ExtractIdentifiers scans all parts of an HTTP request—including the URL path,
// query parameters, headers, and JSON body—to find potential resource
// identifiers like UUIDs and numeric IDs. It returns a slice of
// `ObservedIdentifier`, each detailing the found value and its location.
func ExtractIdentifiers(req *http.Request, body []byte) []ObservedIdentifier {
	var identifiers []ObservedIdentifier

	// 1. Check URL Path
	parts := strings.Split(req.URL.Path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if matchIdentifier(part, TypeUUID, uuidRegex) {
			identifiers = append(identifiers, ObservedIdentifier{Value: part, Type: TypeUUID, Location: LocationURLPath, PathIndex: i})
		} else if matchIdentifier(part, TypeNumericID, numericRegex) {
			identifiers = append(identifiers, ObservedIdentifier{Value: part, Type: TypeNumericID, Location: LocationURLPath, PathIndex: i})
		}
	}

	// 2. Check Query Parameters
	for key, values := range req.URL.Query() {
		for _, value := range values {
			if matchIdentifier(value, TypeUUID, uuidRegex) {
				identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeUUID, Location: LocationQueryParam, Key: key})
			} else if matchIdentifier(value, TypeNumericID, numericRegex) {
				identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeNumericID, Location: LocationQueryParam, Key: key})
			}
		}
	}

	// 3. Check Headers (excluding noisy ones)
	for key, values := range req.Header {
		// Skip headers commonly containing IDs that aren't resource identifiers (e.g., session cookies, auth tokens)
		if strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "User-Agent") {
			continue
		}
		for _, value := range values {
			if matchIdentifier(value, TypeUUID, uuidRegex) {
				identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeUUID, Location: LocationHeader, Key: key})
			}
		}
	}

	// 4. Check JSON Body
	if len(body) > 0 && strings.Contains(req.Header.Get("Content-Type"), "application/json") {
		var data interface{}
		// Use json.Unmarshal for analyzing the structure.
		if err := json.Unmarshal(body, &data); err == nil {
			extractFromJSON(data, "", &identifiers)
		}
	}

	return identifiers
}

// matchIdentifier validates the match, including strict UUID parsing.
func matchIdentifier(value string, idType IdentifierType, regex *regexp.Regexp) bool {
	if !regex.MatchString(value) {
		return false
	}
	// Additional validation for UUIDs using strict parsing
	if idType == TypeUUID {
		if _, err := uuid.Parse(value); err != nil {
			return false
		}
	}
	return true
}

// extractFromJSON recursively traverses a JSON structure to find identifiers.
func extractFromJSON(data interface{}, prefix string, identifiers *[]ObservedIdentifier) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			newPrefix := key
			if prefix != "" {
				newPrefix = prefix + "." + key
			}
			extractFromJSON(val, newPrefix, identifiers)
		}
	case []interface{}:
		for i, val := range v {
			// Use a distinct notation for array indices in the key path (e.g., items[0].id)
			newPrefix := fmt.Sprintf("%s[%d]", prefix, i)
			// Handle root array access (e.g., [0].id)
			if prefix == "" {
				newPrefix = fmt.Sprintf("[%d]", i)
			}
			extractFromJSON(val, newPrefix, identifiers)
		}
	case string:
		if matchIdentifier(v, TypeUUID, uuidRegex) {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: v, Type: TypeUUID, Location: LocationJSONBody, Key: prefix})
		} else if matchIdentifier(v, TypeNumericID, numericRegex) {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: v, Type: TypeNumericID, Location: LocationJSONBody, Key: prefix})
		}
	case float64:
		// Handle numbers in JSON (which unmarshal as float64) if they look like integers
		if v == float64(int64(v)) { // Check if it's an integer representation
			strVal := strconv.FormatFloat(v, 'f', -1, 64)
			if matchIdentifier(strVal, TypeNumericID, numericRegex) {
				*identifiers = append(*identifiers, ObservedIdentifier{Value: strVal, Type: TypeNumericID, Location: LocationJSONBody, Key: prefix})
			}
		}
	}
}

// GenerateTestValue creates a new, predictable value based on an observed
// identifier, to be used in testing for unauthorized access. For numeric IDs, it
// increments the value. For UUIDs, it generates a new random UUID.
func GenerateTestValue(ident ObservedIdentifier) (string, error) {
	switch ident.Type {
	case TypeNumericID:
		// Increment the ID. This assumes IDs are somewhat sequential.
		val, err := strconv.ParseInt(ident.Value, 10, 64)
		if err != nil {
			return "", fmt.Errorf("could not parse numeric ID '%s': %w", ident.Value, err)
		}
		return strconv.FormatInt(val+1, 10), nil
	case TypeUUID:
		// Generate a completely new, random UUID.
		return uuid.NewString(), nil
	default:
		return "", fmt.Errorf("unsupported identifier type for test value generation: %s", ident.Type)
	}
}

// ApplyTestValue takes an original HTTP request, an observed identifier, and a
// new test value, and returns a new `http.Request` with the identifier's value
// replaced. It correctly handles replacement in all supported locations,
// including URL paths, query parameters, headers, and nested JSON bodies.
func ApplyTestValue(ctx context.Context, req *http.Request, body []byte, ident ObservedIdentifier, testValue string) (*http.Request, []byte, error) {
	// Clone the request using the provided context (ctx) to ensure cancellation is respected.
	newReq := req.Clone(ctx)
	newBody := body

	switch ident.Location {
	case LocationURLPath:
		newURL := *req.URL
		parts := strings.Split(newURL.Path, "/")
		if ident.PathIndex < len(parts) {
			parts[ident.PathIndex] = testValue
		}
		newURL.Path = strings.Join(parts, "/")
		newReq.URL = &newURL

	case LocationQueryParam:
		newURL := *req.URL
		q := newURL.Query()
		q.Set(ident.Key, testValue)
		newURL.RawQuery = q.Encode()
		newReq.URL = &newURL

	case LocationHeader:
		newReq.Header.Set(ident.Key, testValue)

	case LocationJSONBody:
		var data interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal JSON body for modification: %w", err)
		}

		// Use a dedicated function to handle nested JSON path modification (e.g., user.profile[0].id)
		if err := modifyJSONByPath(data, ident.Key, testValue); err != nil {
			return nil, nil, fmt.Errorf("failed to modify JSON at path '%s': %w", ident.Key, err)
		}

		newBodyBytes, err := json.Marshal(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal modified JSON body: %w", err)
		}
		newBody = newBodyBytes
		newReq.Body = io.NopCloser(bytes.NewReader(newBody))
		newReq.ContentLength = int64(len(newBody))

	default:
		return nil, nil, fmt.Errorf("unsupported location to apply test value: %s", ident.Location)
	}
	return newReq, newBody, nil
}

// modifyJSONByPath navigates the JSON structure based on the path (dot notation with array indices) and sets the value.
func modifyJSONByPath(data interface{}, path string, newValue string) error {
	// Split path into segments, handling array indices.
	segments := parseJSONPath(path)
	if len(segments) == 0 {
		return fmt.Errorf("invalid or empty path for modification: %s", path)
	}

	current := data
	for i, segment := range segments {
		isLast := i == len(segments)-1

		// Check if current data is nil before proceeding
		if current == nil {
			return fmt.Errorf("encountered nil value while traversing path at segment %d (%v)", i, segment)
		}

		switch s := segment.(type) {
		case string: // Object key
			m, ok := current.(map[string]interface{})
			if !ok {
				return fmt.Errorf("expected object at segment '%s', got %T", s, current)
			}
			if isLast {
				// Attempt to preserve numeric type if applicable, otherwise assign as string.
				if _, err := strconv.ParseInt(newValue, 10, 64); err == nil {
					m[s] = json.Number(newValue)
				} else {
					m[s] = newValue
				}
				return nil
			}
			current = m[s]

		case int: // Array index
			a, ok := current.([]interface{})
			if !ok {
				return fmt.Errorf("expected array at index '%d', got %T", s, current)
			}
			if s < 0 || s >= len(a) {
				return fmt.Errorf("array index %d out of bounds", s)
			}
			if isLast {
				if _, err := strconv.ParseInt(newValue, 10, 64); err == nil {
					a[s] = json.Number(newValue)
				} else {
					a[s] = newValue
				}
				return nil
			}
			current = a[s]
		}
	}
	return nil
}

// parseJSONPath breaks down a dot-notation path with array indices into segments (string keys or int indices).
// e.g., "user.items[0].id" -> ["user", "items", 0, "id"]
// e.g., "[0].id" -> [0, "id"]
func parseJSONPath(path string) []interface{} {
	var segments []interface{}

	// Normalize root array accessors: "[0].id" -> ".[0].id" for consistent splitting by "."
	normalizedPath := path
	if strings.HasPrefix(path, "[") {
		normalizedPath = "." + path
	}

	parts := strings.Split(normalizedPath, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		// Regex to handle keys with array accessors (e.g., "items[0][1]") or just accessors ("[0]")
		// It matches a potential key part (.*?) followed by one or more index parts (\[(\d+)\])+
		re := regexp.MustCompile(`^(.*?)(\[(\d+)\])+$`)
		matches := re.FindStringSubmatch(part)

		if matches != nil {
			keyPart := matches[1]
			indicesPart := part[len(keyPart):]

			// If there's a key part (e.g., "items" in "items[0]"), add it.
			if keyPart != "" {
				segments = append(segments, keyPart)
			}

			// Extract indices from the indices part (e.g., "[0][1]")
			indexRe := regexp.MustCompile(`\[(\d+)\]`)
			indexMatches := indexRe.FindAllStringSubmatch(indicesPart, -1)

			for _, match := range indexMatches {
				index, err := strconv.Atoi(match[1])
				if err == nil {
					segments = append(segments, index)
				}
			}
		} else {
			// Standard object key (no array indices)
			segments = append(segments, part)
		}
	}
	return segments
}
