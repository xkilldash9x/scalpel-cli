// schemas/browser.go
package schemas

import (
	"encoding/json"
	"time"
)

// -- Browser Persona Schemas --

// UserAgentBrandVersion provides a structured representation of a brand in the
// User-Agent string, such as "Google Chrome" or "Not;A=Brand".
type UserAgentBrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// ClientHints encapsulates the User-Agent Client Hints data, which provides
// more detailed information about the browser and operating system than the
// traditional User-Agent string.
type ClientHints struct {
	Platform        string                   `json:"platform"`
	PlatformVersion string                   `json:"platformVersion"`
	Architecture    string                   `json:"architecture"`
	Bitness         string                   `json:"bitness"`
	Mobile          bool                     `json:"mobile"`
	Brands          []*UserAgentBrandVersion `json:"brands"`
}

// Persona defines a complete and consistent browser fingerprint for emulation.
// It includes everything from the User-Agent string and screen dimensions to
// WebGL details and locale settings, ensuring that the automated browser appears
// like a real user's environment.
type Persona struct {
	UserAgent       string       `json:"userAgent"`
	Platform        string       `json:"platform"`
	Languages       []string     `json:"languages"`
	Width           int64        `json:"width"`
	Height          int64        `json:"height"`
	AvailWidth      int64        `json:"availWidth"`
	AvailHeight     int64        `json:"availHeight"`
	ColorDepth      int64        `json:"colorDepth"`
	PixelDepth      int64        `json:"pixelDepth"`
	Mobile          bool         `json:"mobile"`
	Timezone        string       `json:"timezoneId"`
	Locale          string       `json:"locale"`
	ClientHintsData *ClientHints `json:"clientHintsData,omitempty"`
	// WebGLVendor and WebGLRenderer are used to spoof canvas fingerprinting attempts.
	WebGLVendor   string `json:"webGLVendor,omitempty"`
	WebGLRenderer string `json:"webGLRenderer,omitempty"`
	NoiseSeed     int64  `json:"noiseSeed"`
}

// DefaultPersona provides a fallback persona if none is specified.
var DefaultPersona = Persona{

	UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/536.36",
	Platform:    "Win32",
	Languages:   []string{"en-US", "en"},
	Width:       1920,
	Height:      1080,
	AvailWidth:  1920,
	AvailHeight: 1040,
	ColorDepth:  24,
	PixelDepth:  24,
	Mobile:      false,
	Timezone:    "America/Los_Angeles",
	Locale:      "en-US",
}

// -- Browser Interaction Schemas --

// InteractionAction represents a specific type of action that can be performed
// within a web browser, such as navigating to a URL, clicking an element, or typing text.
type InteractionAction string

// Constants defining the set of supported browser interaction actions.
const (
	ActionNavigate InteractionAction = "navigate" // Navigates to a new URL.
	ActionClick    InteractionAction = "click"    // Clicks on a DOM element.
	ActionType     InteractionAction = "type"     // Types text into an input field.
	ActionSelect   InteractionAction = "select"   // Selects an option in a dropdown.
	ActionSubmit   InteractionAction = "submit"   // Submits a form.
	ActionWait     InteractionAction = "wait"     // Pauses for a specified duration.
	ActionScroll   InteractionAction = "scroll"   // Scrolls the page.
)

// InteractionStep represents a single, discrete action to be performed by the
// browser automation service. A sequence of these steps defines a user journey.
type InteractionStep struct {
	Action       InteractionAction `json:"action"`                 // The type of action to perform.
	Selector     string            `json:"selector,omitempty"`     // CSS selector for targeting a DOM element.
	Value        string            `json:"value,omitempty"`        // The value to use (e.g., text to type, option to select).
	Milliseconds int               `json:"milliseconds,omitempty"` // Duration for wait actions.
	Direction    string            `json:"direction,omitempty"`    // Direction for scroll actions (e.g., "down", "up").
}

// InteractionConfig provides a comprehensive configuration for controlling
// automated browser interactions, including crawl depth, delays, and custom
// interaction sequences.
type InteractionConfig struct {
	MaxDepth                int               `json:"max_depth"`                  // Maximum depth for crawling links.
	MaxInteractionsPerDepth int               `json:"max_interactions_per_depth"` // Max actions on a single page.
	InteractionDelayMs      int               `json:"interaction_delay_ms"`       // Delay between actions.
	PostInteractionWaitMs   int               `json:"post_interaction_wait_ms"`   // Wait time after an action for page load.
	CustomInputData         map[string]string `json:"custom_input_data,omitempty"`  // Pre-filled data for forms.
	Steps                   []InteractionStep `json:"steps,omitempty"`            // A specific sequence of actions to perform.
}

// -- Browser Artifact Schemas --

// ConsoleLog captures a single message from the browser's JavaScript console,
// such as logs, errors, or warnings.
type ConsoleLog struct {
	Type      string    `json:"type"`      // The type of console message (e.g., "log", "error").
	Timestamp time.Time `json:"timestamp"` // The time the message was logged.
	Text      string    `json:"text"`      // The content of the console message.
	Source    string    `json:"source,omitempty"`
	URL       string    `json:"url,omitempty"` // The URL of the script that generated the message.
	Line      int64     `json:"line,omitempty"`  // The line number in the script.
}

// CookieSameSite specifies the SameSite attribute for an HTTP cookie, controlling
// whether it's sent with cross-site requests.
type CookieSameSite string

// Constants for the CookieSameSite attribute.
const (
	CookieSameSiteStrict CookieSameSite = "Strict" // The cookie is only sent for same-site requests.
	CookieSameSiteLax    CookieSameSite = "Lax"    // The cookie is sent for same-site requests and top-level navigations.
	CookieSameSiteNone   CookieSameSite = "None"   // The cookie is sent for all requests, but requires the Secure attribute.
)

// Cookie represents a single HTTP cookie, containing its name, value, and
// associated metadata like domain, path, and security attributes.
type Cookie struct {
	Name     string         `json:"name"`
	Value    string         `json:"value"`
	Domain   string         `json:"domain"`
	Path     string         `json:"path"`
	Expires  float64        `json:"expires"`
	Size     int64          `json:"size"`
	HTTPOnly bool           `json:"httpOnly"`
	Secure   bool           `json:"secure"`
	Session  bool           `json:"session"`
	SameSite CookieSameSite `json:"sameSite,omitempty"`
}

// StorageState provides a snapshot of the browser's storage for a given origin,
// including cookies, local storage, and session storage.
type StorageState struct {
	Cookies        []*Cookie         `json:"cookies"`
	LocalStorage   map[string]string `json:"local_storage"`
	SessionStorage map[string]string `json:"session_storage"`
}

// Artifacts is a comprehensive collection of all data gathered from a browser
// session or interaction, including network requests (HAR), the DOM tree,
// console logs, and storage state.
type Artifacts struct {
	HAR         *json.RawMessage `json:"har"`          // The HTTP Archive (HAR) data for network requests.
	DOM         string           `json:"dom"`          // The full HTML source of the page.
	ConsoleLogs []ConsoleLog     `json:"console_logs"` // A log of all console messages.
	Storage     StorageState     `json:"storage"`      // A snapshot of the browser's storage.
}

// HistoryState represents a single entry in the browser's navigation history,
// capturing the state, title, and URL at a specific point in time.
type HistoryState struct {
	State interface{} `json:"state"` // The serialized state object associated with the history entry.
	Title string      `json:"title"` // The title of the page at this history entry.
	URL   string      `json:"url"`   // The URL of the history entry.
}

// FetchRequest encapsulates the details of an HTTP request made using the
// Fetch API from within the browser, including the URL, method, headers, and body.
type FetchRequest struct {
	URL         string   `json:"url"`         // The URL of the request.
	Method      string   `json:"method"`      // The HTTP method (e.g., "GET", "POST").
	Headers     []NVPair `json:"headers"`     // The request headers.
	Body        []byte   `json:"body"`        // The request body.
	Credentials string   `json:"credentials"` // The credentials policy (e.g., "include", "omit").
}

// FetchResponse encapsulates the details of an HTTP response received from a
// Fetch API call, including the status code, headers, and response body.
type FetchResponse struct {
	URL        string   `json:"url"`        // The final URL after any redirects.
	Status     int      `json:"status"`     // The HTTP status code (e.g., 200, 404).
	StatusText string   `json:"statusText"` // The status text (e.g., "OK", "Not Found").
	Headers    []NVPair `json:"headers"`    // The response headers.
	Body       []byte   `json:"body"`       // The response body.
}

// -- Humanoid Low-Level Interaction Schemas --

// ElementGeometry describes the physical properties of a DOM element on the page,
// including its dimensions, vertices, and tag information. This is used for
// precise, human-like interactions.
type ElementGeometry struct {
	Vertices []float64 `json:"vertices"` // The coordinates of the element's corners.
	Width    int64     `json:"width"`    // The width of the element in pixels.
	Height   int64     `json:"height"`   // The height of the element in pixels.
	// TagName provides the HTML tag of the element (e.g., "INPUT", "BUTTON"),
	// which can be used to influence interaction behavior.
	TagName string `json:"tagName"`
	// Type attribute of the element (e.g., "text", "password", "checkbox"),
	// further specializing interaction logic.
	Type string `json:"type,omitempty"`
}

// MouseEventType defines the specific type of a mouse event, such as movement,
// pressing a button, or releasing it.
type MouseEventType string

// Constants for different types of mouse events.
const (
	MouseMove    MouseEventType = "mouseMoved"    // The mouse was moved.
	MousePress   MouseEventType = "mousePressed"  // A mouse button was pressed.
	MouseRelease MouseEventType = "mouseReleased" // A mouse button was released.
	MouseWheel   MouseEventType = "mouseWheel"   // The mouse wheel was scrolled.
)

// MouseButton identifies a specific mouse button.
type MouseButton string

// Constants for different mouse buttons.
const (
	ButtonNone   MouseButton = "none"   // No button.
	ButtonLeft   MouseButton = "left"   // The left mouse button.
	ButtonRight  MouseButton = "right"  // The right mouse button.
	ButtonMiddle MouseButton = "middle" // The middle mouse button.
)

// MouseEventData encapsulates all the information related to a single mouse
// event, including its type, position, and button state.
type MouseEventData struct {
	Type       MouseEventType `json:"type"`       // The type of the mouse event.
	X          float64        `json:"x"`          // The x-coordinate of the event.
	Y          float64        `json:"y"`          // The y-coordinate of the event.
	Button     MouseButton    `json:"button"`     // The primary button associated with the event.
	Buttons    int64          `json:"buttons"`    // A bitmask of all buttons currently pressed.
	ClickCount int            `json:"clickCount"` // The number of consecutive clicks.
	DeltaX     float64        `json:"deltaX"`     // The horizontal scroll amount for wheel events.
	DeltaY     float64        `json:"deltaY"`     // The vertical scroll amount for wheel events.
}
