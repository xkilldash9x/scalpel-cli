package schemas

import (
	"time"
)

// -- HAR (HTTP Archive) Schemas --

// HAR is the root object of the HTTP Archive format, which represents a log of
// HTTP requests and responses. See http://www.softwareishard.com/blog/har-1-2-spec/
// for the full specification.
type HAR struct {
	Log HARLog `json:"log"`
}

// HARLog is the main container within a HAR file, holding metadata about the
// creator, pages, and a list of all network entries.
type HARLog struct {
	Version string  `json:"version"` // The version of the HAR format.
	Creator Creator `json:"creator"` // Information about the tool that created the HAR.
	Pages   []Page  `json:"pages"`   // A list of pages loaded during the session.
	Entries []Entry `json:"entries"` // A list of all recorded HTTP requests and responses.
}

// Creator provides information about the application that generated the HAR file.
type Creator struct {
	Name    string `json:"name"`    // The name of the creator application.
	Version string `json:"version"` // The version of the creator application.
}

// Page represents a single page that was loaded in the browser. A HAR file can
// contain multiple pages if the user navigated during the recording session.
type Page struct {
	StartedDateTime time.Time   `json:"startedDateTime"` // The timestamp when the page load started.
	ID              string      `json:"id"`              // A unique identifier for the page.
	Title           string      `json:"title"`           // The title of the page.
	PageTimings     PageTimings `json:"pageTimings"`     // Timings for page load events.
}

// PageTimings contains timing information for key page load events, such as
// DOMContentLoaded and the window's load event.
type PageTimings struct {
	OnContentLoad float64 `json:"onContentLoad"` // Time until the DOMContentLoaded event, in milliseconds.
	OnLoad        float64 `json:"onLoad"`        // Time until the page's load event, in milliseconds.
}

// Entry represents a single HTTP request-response pair recorded in the HAR.
type Entry struct {
	Pageref         string    `json:"pageref"`         // A reference to the page this entry belongs to.
	StartedDateTime time.Time `json:"startedDateTime"` // The timestamp when the request started.
	Time            float64   `json:"time"`            // The total time for the request-response cycle.
	Request         Request   `json:"request"`         // Detailed information about the HTTP request.
	Response        Response  `json:"response"`        // Detailed information about the HTTP response.
	Cache           struct{}  `json:"cache"`           // Information about the browser cache state.
	Timings         Timings   `json:"timings"`         // Detailed breakdown of the request timing phases.
}

// Request contains detailed information about a single HTTP request, including
// the method, URL, headers, and any posted data.
type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []HARCookie `json:"cookies"`
	Headers     []NVPair    `json:"headers"`
	QueryString []NVPair    `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int64       `json:"headersSize"` // The size of the request headers in bytes.
	BodySize    int64       `json:"bodySize"`    // The size of the request body in bytes.
}

// Response contains detailed information about an HTTP response, including the
// status code, headers, and content. It also includes custom fields for storing
// additional network data from the Chrome DevTools Protocol.
type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []HARCookie `json:"cookies"`
	Headers     []NVPair    `json:"headers"`
	Content     Content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int64       `json:"headersSize"` // The size of the response headers in bytes.
	BodySize    int64       `json:"bodySize"`    // The size of the response body in bytes.
	// --- ADDED FIELDS ---
	// Custom fields for storing CDP network data for later analysis.
	// The underscore prefix indicates they are non-standard HAR fields.
	RemoteIPSpace   string `json:"_remoteIPAddressSpace,omitempty"` // The IP address space of the remote server.
	RemoteIPAddress string `json:"_remoteIPAddress,omitempty"`    // The IP address of the remote server.
}

// Timings provides a detailed breakdown of the time spent in various phases of
// a single network request, from being blocked to receiving the final response.
type Timings struct {
	Blocked float64 `json:"blocked"` // Time spent blocked before the request could be sent.
	DNS     float64 `json:"dns"`     // DNS lookup time.
	Connect float64 `json:"connect"` // TCP connection time.
	SSL     float64 `json:"ssl"`     // SSL/TLS handshake time.
	Send    float64 `json:"send"`    // Time spent sending the HTTP request.
	Wait    float64 `json:"wait"`    // Time spent waiting for the first byte of the response (TTFB).
	Receive float64 `json:"receive"` // Time spent receiving the response data.
}

// NVPair represents a simple name-value pair, used for headers, query strings,
// and form parameters.
type NVPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARCookie represents an HTTP cookie as defined in the HAR specification.
// It uses a string for the 'Expires' field to maintain strict conformance.
type HARCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"` // The expiration date in a string format.
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// PostData contains information about the data sent in an HTTP POST request.
type PostData struct {
	MimeType string   `json:"mimeType"` // The MIME type of the posted data.
	Text     string   `json:"text"`     // The raw text of the posted data.
	Params   []NVPair `json:"params"`   // A list of parameters for form-encoded data.
}

// Content describes the content of an HTTP response body.
type Content struct {
	Size     int64  `json:"size"`      // The size of the content in bytes.
	MimeType string `json:"mimeType"`  // The MIME type of the content.
	Text     string `json:"text,omitempty"`      // The content text, if it's not binary.
	Encoding string `json:"encoding,omitempty"`  // The encoding of the content (e.g., "base64").
}

// NewHAR is a factory function that creates and initializes a new HAR object
// with default values for the log version and creator information.
func NewHAR() *HAR {
	return &HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: Creator{
				Name:    "Scalpel-CLI",
				Version: "2.0",
			},
			Entries: make([]Entry, 0),
		},
	}
}
