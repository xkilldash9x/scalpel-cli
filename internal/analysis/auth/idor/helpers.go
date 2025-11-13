// helpers.go
package idor

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/beevik/etree" // Added for XML parsing
	"github.com/google/uuid"
)

var (
	// Improved UUID regex to adhere closely to RFC 4122 (version and variant bits) for accuracy
	uuidRegex = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	// Numeric regex. Minimum length 3 to filter noise, max 19 for 64-bit int.
	numericRegex = regexp.MustCompile(`\b\d{3,19}\b`)
	// Hash regex covering MD5 (32), SHA1 (40), and SHA256 (64) hex characters.
	hashRegex = regexp.MustCompile(`(?i)\b[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}\b`)
)

// ExtractIdentifiers scans all parts of an HTTP request (URL, headers, cookies, JSON/XML/Form body)
// to find potential resource identifiers. It returns a deduplicated slice.
func ExtractIdentifiers(req *http.Request, body []byte) []ObservedIdentifier {
	var identifiers []ObservedIdentifier
	contentType := req.Header.Get("Content-Type")

	// Helper function to check and add identifiers, handling overlaps (e.g., Numeric vs Hash)
	checkAndAdd := func(value string, location IdentifierLocation, key string, pathIndex int) {
		if matchIdentifier(value, TypeUUID, uuidRegex) {
			identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeUUID, Location: location, Key: key, PathIndex: pathIndex})
			return
		}

		isHash := matchIdentifier(value, TypeHash, hashRegex)
		isNumeric := matchIdentifier(value, TypeNumericID, numericRegex)

		if isNumeric && !isHash {
			identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeNumericID, Location: location, Key: key, PathIndex: pathIndex})
		} else if isHash {
			// Prioritize Hash if it matches both (e.g., a long hex string that happens to be all digits)
			identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeHash, Location: location, Key: key, PathIndex: pathIndex})
		}
	}

	// 1. Check URL Path
	parts := strings.Split(req.URL.Path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		checkAndAdd(part, LocationURLPath, "", i)
	}

	// 2. Check Query Parameters
	for key, values := range req.URL.Query() {
		for _, value := range values {
			checkAndAdd(value, LocationQueryParam, key, 0)
		}
	}

	// 3. Check Headers (excluding noisy ones)
	for key, values := range req.Header {
		// Skip headers commonly containing IDs that aren't resource identifiers
		if strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "User-Agent") || strings.EqualFold(key, "Referer") {
			continue
		}
		for _, value := range values {
			// Headers often contain UUIDs or Hashes.
			if matchIdentifier(value, TypeUUID, uuidRegex) {
				identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeUUID, Location: LocationHeader, Key: key})
			} else if matchIdentifier(value, TypeHash, hashRegex) {
				identifiers = append(identifiers, ObservedIdentifier{Value: value, Type: TypeHash, Location: LocationHeader, Key: key})
			}
		}
	}

	// 4. Check Cookies
	for _, cookie := range req.Cookies() {
		// Skip common session cookie names
		if strings.EqualFold(cookie.Name, "session") || strings.EqualFold(cookie.Name, "JSESSIONID") || strings.Contains(strings.ToLower(cookie.Name), "auth") {
			continue
		}
		checkAndAdd(cookie.Value, LocationCookie, cookie.Name, 0)
	}

	// 5. Check Body
	if len(body) > 0 {
		if strings.Contains(contentType, "application/json") {
			var data interface{}
			// Use Decoder with UseNumber() for accurate extraction.
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			if err := decoder.Decode(&data); err == nil {
				extractFromJSON(data, "", &identifiers)
			}
		} else if strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml") {
			doc := etree.NewDocument()
			if err := doc.ReadFromBytes(body); err == nil {
				extractFromXML(doc.Root(), &identifiers)
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			formValues, err := url.ParseQuery(string(body))
			if err == nil {
				for key, values := range formValues {
					for _, value := range values {
						checkAndAdd(value, LocationFormBody, key, 0)
					}
				}
			}
		} else if strings.Contains(contentType, "multipart/form-data") {
			mediaType, params, err := mime.ParseMediaType(contentType)
			if err == nil && strings.HasPrefix(mediaType, "multipart/") {
				boundary := params["boundary"]
				mr := multipart.NewReader(bytes.NewReader(body), boundary)
				for {
					p, err := mr.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil || p.FileName() != "" { // Skip errors and file uploads
						continue
					}
					partData, err := io.ReadAll(p)
					if err == nil {
						checkAndAdd(string(partData), LocationFormBody, p.FormName(), 0)
					}
				}
			}
		}
	}

	return deduplicateIdentifiers(identifiers)
}

// deduplicateIdentifiers removes duplicates based on Type and Value.
func deduplicateIdentifiers(identifiers []ObservedIdentifier) []ObservedIdentifier {
	seen := make(map[string]bool)
	var unique []ObservedIdentifier
	for _, ident := range identifiers {
		// Key combines Type and Value (e.g., "NumericID:12345")
		key := fmt.Sprintf("%s:%s", ident.Type, ident.Value)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ident)
		}
	}
	return unique
}

// matchIdentifier validates the match, including strict parsing and heuristics.
func matchIdentifier(value string, idType IdentifierType, regex *regexp.Regexp) bool {
	if value == "" {
		return false
	}
	if !regex.MatchString(value) {
		return false
	}
	// Additional validation
	switch idType {
	case TypeUUID:
		if _, err := uuid.Parse(value); err != nil {
			return false
		}
	case TypeNumericID:
		// Filter out common years (simple heuristic to reduce noise)
		if val, err := strconv.Atoi(value); err == nil {
			// Check against a reasonable range for years relevant to modern applications
			if val >= 1990 && val <= 2035 && len(value) == 4 {
				return false
			}
		}
	}
	return true
}

// extractFromXML traverses the XML document (etree) and extracts identifiers.
func extractFromXML(element *etree.Element, identifiers *[]ObservedIdentifier) {
	if element == nil {
		return
	}

	// GetPath provides an XPath to the element.
	path := element.GetPath()

	// Helper to check and add, handling overlaps
	checkAndAdd := func(value string, key string) {
		if matchIdentifier(value, TypeUUID, uuidRegex) {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: value, Type: TypeUUID, Location: LocationXMLBody, Key: key})
			return
		}
		isHash := matchIdentifier(value, TypeHash, hashRegex)
		isNumeric := matchIdentifier(value, TypeNumericID, numericRegex)

		if isNumeric && !isHash {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: value, Type: TypeNumericID, Location: LocationXMLBody, Key: key})
		} else if isHash {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: value, Type: TypeHash, Location: LocationXMLBody, Key: key})
		}
	}

	// Check element text content
	text := strings.TrimSpace(element.Text())
	if text != "" {
		checkAndAdd(text, path)
	}

	// Check attributes
	for _, attr := range element.Attr {
		// Key format for attributes: XPath/@attributeName
		attrKey := fmt.Sprintf("%s/@%s", path, attr.Key)
		checkAndAdd(attr.Value, attrKey)
	}

	// Recurse into children
	for _, child := range element.ChildElements() {
		extractFromXML(child, identifiers)
	}
}

// extractFromJSON recursively traverses a JSON structure to find identifiers.
func extractFromJSON(data interface{}, prefix string, identifiers *[]ObservedIdentifier) {
	// Limit recursion depth
	const maxDepth = 15
	if strings.Count(prefix, ".") > maxDepth {
		return
	}

	// Helper to check and add, handling overlaps
	checkAndAdd := func(value string) {
		if matchIdentifier(value, TypeUUID, uuidRegex) {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: value, Type: TypeUUID, Location: LocationJSONBody, Key: prefix})
			return
		}
		isHash := matchIdentifier(value, TypeHash, hashRegex)
		isNumeric := matchIdentifier(value, TypeNumericID, numericRegex)

		if isNumeric && !isHash {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: value, Type: TypeNumericID, Location: LocationJSONBody, Key: prefix})
		} else if isHash {
			*identifiers = append(*identifiers, ObservedIdentifier{Value: value, Type: TypeHash, Location: LocationJSONBody, Key: prefix})
		}
	}

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
			// Use a distinct notation for array indices (e.g., items[0].id)
			newPrefix := fmt.Sprintf("%s[%d]", prefix, i)
			// Handle root array access (e.g., [0].id)
			if prefix == "" {
				newPrefix = fmt.Sprintf("[%d]", i)
			}
			extractFromJSON(val, newPrefix, identifiers)
		}
	case string:
		checkAndAdd(v)
	case json.Number:
		// Handle numbers (when UseNumber() is used)
		checkAndAdd(v.String())
		// float64 case is removed as we now enforce UseNumber() during decoding.
	}
}

// GenerateTestValues creates a list of new, predictable values based on an observed identifier.
func GenerateTestValues(ident ObservedIdentifier) ([]string, error) {
	switch ident.Type {
	case TypeNumericID:
		val, err := strconv.ParseInt(ident.Value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse numeric ID '%s' as int64: %w", ident.Value, err)
		}
		// Strategies: Increment, Decrement (if > 0), and a larger number.
		testValues := []string{strconv.FormatInt(val+1, 10)}
		if val > 0 {
			testValues = append(testValues, strconv.FormatInt(val-1, 10))
		}
		// Add a larger number, avoiding overflow issues and ensuring it's distinct.
		if val < (1<<63-1000) && val+100 > val+1 {
			testValues = append(testValues, strconv.FormatInt(val+100, 10))
		}
		return uniqueStrings(testValues), nil

	case TypeUUID:
		// Generate a new, random UUID. One is sufficient.
		return []string{uuid.NewString()}, nil
	case TypeHash:
		// Generate a new hash based on the format (length) of the original hash.
		return []string{generateHash(ident.Value, "test_idor_value")}, nil
	default:
		return nil, fmt.Errorf("unsupported identifier type for test value generation: %s", ident.Type)
	}
}

// uniqueStrings removes duplicates from a slice.
func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	j := 0
	for _, v := range input {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		input[j] = v
		j++
	}
	return input[:j]
}

// generateHash creates a hash of the input string matching the format (length) of the example hash.
func generateHash(originalHash, input string) string {
	var hashBytes []byte
	inputBytes := []byte(input)

	switch len(originalHash) {
	case 32: // MD5
		h := md5.Sum(inputBytes)
		hashBytes = h[:]
	case 40: // SHA1
		h := sha1.Sum(inputBytes)
		hashBytes = h[:]
	case 64: // SHA256
		h := sha256.Sum256(inputBytes)
		hashBytes = h[:]
	default:
		// Default to SHA256 if length is unexpected
		h := sha256.Sum256(inputBytes)
		hashBytes = h[:]
	}
	return hex.EncodeToString(hashBytes)
}

// ApplyTestValue takes an original HTTP request and returns a new `http.Request`
// with the identifier's value replaced.
func ApplyTestValue(ctx context.Context, req *http.Request, body []byte, ident ObservedIdentifier, testValue string) (*http.Request, []byte, error) {
	// Clone the request.
	newReq := req.Clone(ctx)
	newBody := body

	// Ensure cookies are copied (net/http's Clone might miss the internal slice).
	if len(req.Cookies()) > 0 && len(newReq.Header.Get("Cookie")) == 0 {
		for _, cookie := range req.Cookies() {
			newReq.AddCookie(cookie)
		}
	}

	switch ident.Location {
	case LocationURLPath:
		newURL := *req.URL
		parts := strings.Split(newURL.Path, "/")
		// Validate index and value before replacement.
		if ident.PathIndex >= 0 && ident.PathIndex < len(parts) {
			if parts[ident.PathIndex] == ident.Value {
				parts[ident.PathIndex] = testValue
			} else {
				return nil, nil, fmt.Errorf("mismatch in URL path extraction: expected '%s' at index %d, found '%s'", ident.Value, ident.PathIndex, parts[ident.PathIndex])
			}
		} else {
			return nil, nil, fmt.Errorf("invalid URL path index %d", ident.PathIndex)
		}
		newURL.Path = strings.Join(parts, "/")
		newReq.URL = &newURL

	case LocationQueryParam:
		newURL := *req.URL
		q := newURL.Query()
		if q.Get(ident.Key) != "" {
			q.Set(ident.Key, testValue)
		} else {
			return nil, nil, fmt.Errorf("query parameter key '%s' not found", ident.Key)
		}
		newURL.RawQuery = q.Encode()
		newReq.URL = &newURL

	case LocationHeader:
		if newReq.Header.Get(ident.Key) != "" {
			newReq.Header.Set(ident.Key, testValue)
		} else {
			return nil, nil, fmt.Errorf("header key '%s' not found", ident.Key)
		}

	case LocationCookie:
		// Rebuild cookies, replacing the target one.
		newReq.Header.Del("Cookie")
		found := false
		for _, cookie := range req.Cookies() {
			if cookie.Name == ident.Key {
				newReq.AddCookie(&http.Cookie{Name: ident.Key, Value: testValue})
				found = true
			} else {
				newReq.AddCookie(cookie)
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("cookie '%s' not found for replacement", ident.Key)
		}

	case LocationFormBody:
		contentType := req.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			formValues, err := url.ParseQuery(string(body))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse form-urlencoded body: %w", err)
			}
			if formValues.Get(ident.Key) != "" {
				formValues.Set(ident.Key, testValue)
			} else {
				return nil, nil, fmt.Errorf("form key '%s' not found", ident.Key)
			}
			newBody = []byte(formValues.Encode())

		} else if strings.Contains(contentType, "multipart/form-data") {
			newBodyBytes, newContentType, err := modifyMultipartFormData(body, contentType, ident.Key, testValue)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to modify multipart form data: %w", err)
			}
			newBody = newBodyBytes
			// Update Content-Type as the boundary changes.
			newReq.Header.Set("Content-Type", newContentType)
		} else {
			return nil, nil, fmt.Errorf("unsupported content type for LocationFormBody: %s", contentType)
		}
		newReq.Body = io.NopCloser(bytes.NewReader(newBody))
		newReq.ContentLength = int64(len(newBody))

	case LocationJSONBody:
		var data interface{}
		// Use Decoder with UseNumber() to preserve numeric types accurately during modification.
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&data); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal JSON body: %w", err)
		}

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

	case LocationXMLBody:
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(body); err != nil {
			return nil, nil, fmt.Errorf("failed to parse XML body: %w", err)
		}

		if err := modifyXMLByPath(doc, ident.Key, testValue); err != nil {
			return nil, nil, fmt.Errorf("failed to modify XML at path '%s': %w", ident.Key, err)
		}

		newBodyBytes, err := doc.WriteToBytes()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize modified XML body: %w", err)
		}
		newBody = newBodyBytes
		newReq.Body = io.NopCloser(bytes.NewReader(newBody))
		newReq.ContentLength = int64(len(newBody))

	default:
		return nil, nil, fmt.Errorf("unsupported location to apply test value: %s", ident.Location)
	}
	return newReq, newBody, nil
}

// modifyMultipartFormData reads the original multipart body, replaces the specified field value,
// and writes out a new multipart body with a new boundary.
func modifyMultipartFormData(body []byte, contentType string, fieldName, newValue string) ([]byte, string, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return nil, "", fmt.Errorf("invalid multipart content type")
	}
	boundary := params["boundary"]
	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf) // Creates a new writer with a new random boundary

	// Iterate over parts and copy them to the new writer, modifying the target field.
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("error reading next part: %w", err)
		}

		partHeaders := p.Header
		formName := p.FormName()

		if formName == fieldName {
			// This is the field to modify. Create a new part with the new value.
			if err := createFormPart(mw, partHeaders, newValue); err != nil {
				return nil, "", err
			}
			// Consume the old part data
			io.Copy(io.Discard, p)
		} else {
			// This is a different field or file, copy it verbatim.
			pw, err := mw.CreatePart(partHeaders)
			if err != nil {
				return nil, "", fmt.Errorf("error creating part for copy: %w", err)
			}
			if _, err := io.Copy(pw, p); err != nil {
				return nil, "", fmt.Errorf("error copying part data: %w", err)
			}
		}
	}

	if err := mw.Close(); err != nil {
		return nil, "", fmt.Errorf("error closing multipart writer: %w", err)
	}

	// Return the new body and the new Content-Type (which includes the new boundary).
	return buf.Bytes(), mw.FormDataContentType(), nil
}

// createFormPart helps create a multipart form field while preserving original headers (except Content-Length).
func createFormPart(w *multipart.Writer, originalHeaders textproto.MIMEHeader, value string) error {
	h := make(textproto.MIMEHeader)
	for k, v := range originalHeaders {
		if !strings.EqualFold(k, "Content-Length") {
			h[k] = v
		}
	}

	pw, err := w.CreatePart(h)
	if err != nil {
		return fmt.Errorf("error creating modified part: %w", err)
	}
	_, err = pw.Write([]byte(value))
	return err
}

// modifyXMLByPath uses the XPath to find and modify the XML element or attribute.
func modifyXMLByPath(doc *etree.Document, path string, newValue string) error {
	// Check if the path refers to an attribute (contains /@)
	if strings.Contains(path, "/@") {
		// This handles XPaths where the attribute is at the end.
		parts := strings.Split(path, "/@")
		if len(parts) < 2 {
			return fmt.Errorf("invalid attribute XPath format: %s", path)
		}
		// Handle complex XPaths where attributes might appear earlier
		elementPath := strings.Join(parts[:len(parts)-1], "/@")
		attrName := parts[len(parts)-1]

		element := doc.FindElement(elementPath)
		if element == nil {
			return fmt.Errorf("XML element not found at XPath: %s", elementPath)
		}

		attr := element.SelectAttr(attrName)
		if attr == nil {
			return fmt.Errorf("XML attribute '%s' not found on element at XPath: %s", attrName, elementPath)
		}
		attr.Value = newValue
		return nil
	}

	// Handle element modification
	element := doc.FindElement(path)
	if element == nil {
		return fmt.Errorf("XML element not found at XPath: %s", path)
	}
	element.SetText(newValue)
	return nil
}

// modifyJSONByPath navigates the JSON structure based on the path (dot notation with array indices) and sets the value.
// It attempts to preserve the data type of the new value (using json.Number for numerics).
func modifyJSONByPath(data interface{}, path string, newValue string) error {
	// Split path into segments.
	segments := parseJSONPath(path)
	if len(segments) == 0 {
		return fmt.Errorf("invalid or empty path for modification: %s", path)
	}

	// Determine the type for the new value. Use json.Number if it parses as numeric.
	var replacementValue interface{}
	if _, err := strconv.ParseFloat(newValue, 64); err == nil {
		replacementValue = json.Number(newValue)
	} else {
		replacementValue = newValue
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
				m[s] = replacementValue
				return nil
			}
			if _, exists := m[s]; !exists {
				return fmt.Errorf("key '%s' not found in object", s)
			}
			current = m[s]

		case int: // Array index
			a, ok := current.([]interface{})
			if !ok {
				return fmt.Errorf("expected array at index '%d', got %T", s, current)
			}
			if s < 0 || s >= len(a) {
				return fmt.Errorf("array index %d out of bounds (length %d)", s, len(a))
			}
			if isLast {
				a[s] = replacementValue
				return nil
			}
			current = a[s]
		}
	}
	return fmt.Errorf("failed to apply modification for path: %s", path)
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

		// Regex to handle keys with array accessors (e.g., "items[0][1]")
		// It matches a potential key part ([^\[]*) followed by one or more index parts ((?:\[\d+\])+).
		re := regexp.MustCompile(`^([^\[]*)((?:\[\d+\])+)$`)
		matches := re.FindStringSubmatch(part)

		if matches != nil {
			keyPart := matches[1]
			indicesPart := matches[2]

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
