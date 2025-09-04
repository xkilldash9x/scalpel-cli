package schemas

import (
	"github.com/chromedp/cdproto/har"
	"github.com/chromedp/cdproto/network"
)

// Artifacts represents the data collected from a browser session.
type Artifacts struct {
	HAR         *har.HAR
	DOM         string
	ConsoleLogs []ConsoleLog
	Storage     StorageState
}

// ConsoleLog represents a single entry from the browser console.
type ConsoleLog struct {
	Type string
	Text string
}

// StorageState captures the state of cookies, localStorage, and sessionStorage.
type StorageState struct {
	Cookies        []*network.Cookie
	LocalStorage   map[string]string `json:"localStorage"`
	SessionStorage map[string]string `json:"sessionStorage"`
}

// InteractionConfig holds parameters for automated interaction/crawling.
type InteractionConfig struct {
	MaxDepth                int
	MaxInteractionsPerDepth int
	InteractionDelayMs      int
	PostInteractionWaitMs   int
}