package schemas

import (
	"encoding/json"
	"time"
)

// -- Browser Persona Schemas --

// UserAgentBrandVersion is a local replacement for emulation.UserAgentBrandVersion.
type UserAgentBrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// ClientHints defines the User-Agent Client Hints data.
type ClientHints struct {
	Platform        string                   `json:"platform"`
	PlatformVersion string                   `json:"platformVersion"`
	Architecture    string                   `json:"architecture"`
	Bitness         string                   `json:"bitness"`
	Mobile          bool                     `json:"mobile"`
	Brands          []*UserAgentBrandVersion `json:"brands"`
}

// Persona encapsulates all properties for a consistent browser fingerprint.
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
	NoiseSeed       int64        `json:"noiseSeed"`
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

// InteractionAction defines the type of action to perform in an interaction step.
type InteractionAction string

const (
	ActionNavigate InteractionAction = "navigate"
	ActionClick    InteractionAction = "click"
	ActionType     InteractionAction = "type"
	ActionSelect   InteractionAction = "select"
	ActionSubmit   InteractionAction = "submit"
	ActionWait     InteractionAction = "wait"
	ActionScroll   InteractionAction = "scroll"
)

// InteractionStep defines a single action to be performed in a sequence.
type InteractionStep struct {
	Action       InteractionAction `json:"action"`
	Selector     string            `json:"selector,omitempty"`
	Value        string            `json:"value,omitempty"`
	Milliseconds int               `json:"milliseconds,omitempty"`
	Direction    string            `json:"direction,omitempty"`
}

// InteractionConfig defines parameters for browser interaction.
type InteractionConfig struct {
	MaxDepth                int               `json:"max_depth"`
	MaxInteractionsPerDepth int               `json:"max_interactions_per_depth"`
	InteractionDelayMs      int               `json:"interaction_delay_ms"`
	PostInteractionWaitMs   int               `json:"post_interaction_wait_ms"`
	CustomInputData         map[string]string `json:"custom_input_data,omitempty"`
	Steps                   []InteractionStep `json:"steps,omitempty"`
}

// -- Browser Artifact Schemas --

// ConsoleLog represents a single entry from the browser's console.
type ConsoleLog struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Text      string    `json:"text"`
	Source    string    `json:"source,omitempty"`
	URL       string    `json:"url,omitempty"`
	Line      int64     `json:"line,omitempty"`
}

// CookieSameSite defines the SameSite attribute for cookies.
type CookieSameSite string

const (
	CookieSameSiteStrict CookieSameSite = "Strict"
	CookieSameSiteLax    CookieSameSite = "Lax"
	CookieSameSiteNone   CookieSameSite = "None"
)

// Cookie represents a browser cookie.
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

// StorageState captures the state of browser storage at a point in time.
type StorageState struct {
	Cookies        []*Cookie         `json:"cookies"`
	LocalStorage   map[string]string `json:"local_storage"`
	SessionStorage map[string]string `json:"session_storage"`
}

// Artifacts is a collection of all data gathered during a browser interaction.
type Artifacts struct {
	HAR         *json.RawMessage `json:"har"`
	DOM         string           `json:"dom"`
	ConsoleLogs []ConsoleLog     `json:"console_logs"`
	Storage     StorageState     `json:"storage"`
}

// HistoryState represents an entry in the browser's session history.
type HistoryState struct {
	State interface{} `json:"state"`
	Title string      `json:"title"`
	URL   string      `json:"url"`
}

// FetchRequest represents the data for a fetch request initiated from JS.
type FetchRequest struct {
	URL         string   `json:"url"`
	Method      string   `json:"method"`
	Headers     []NVPair `json:"headers"`
	Body        []byte   `json:"body"`
	Credentials string   `json:"credentials"`
}

// FetchResponse represents the data from a fetch response.
type FetchResponse struct {
	URL        string   `json:"url"`
	Status     int      `json:"status"`
	StatusText string   `json:"statusText"`
	Headers    []NVPair `json:"headers"`
	Body       []byte   `json:"body"`
}

// -- Humanoid Low-Level Interaction Schemas --

// ElementGeometry defines the bounding box, vertices, and metadata of a DOM element.
type ElementGeometry struct {
	Vertices []float64 `json:"vertices"`
	Width    int64     `json:"width"`
	Height   int64     `json:"height"`
	// TagName (e.g., "INPUT", "BUTTON") used for behavioral biasing.
	TagName string `json:"tagName"`
	// Type (e.g., 'text', 'password', 'checkbox') used for behavioral biasing.
	Type string `json:"type,omitempty"`
}

// MouseEventType defines the type of a mouse event.
type MouseEventType string

const (
	MouseMove    MouseEventType = "mouseMoved"
	MousePress   MouseEventType = "mousePressed"
	MouseRelease MouseEventType = "mouseReleased"
	MouseWheel   MouseEventType = "mouseWheel"
)

// MouseButton defines the mouse button being pressed.
type MouseButton string

const (
	ButtonNone   MouseButton = "none"
	ButtonLeft   MouseButton = "left"
	ButtonRight  MouseButton = "right"
	ButtonMiddle MouseButton = "middle"
)

// MouseEventData encapsulates all data for a mouse event.
type MouseEventData struct {
	Type       MouseEventType `json:"type"`
	X          float64        `json:"x"`
	Y          float64        `json:"y"`
	Button     MouseButton    `json:"button"`
	Buttons    int64          `json:"buttons"`
	ClickCount int            `json:"clickCount"`
	DeltaX     float64        `json:"deltaX"`
	DeltaY     float64        `json:"deltaY"`
}
