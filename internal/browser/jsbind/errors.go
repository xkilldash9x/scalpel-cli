// internal/browser/jsbind/errors.go
package jsbind

import "fmt"

// This file introduces custom, typed errors for the browser session. Using typed errors
// allows consumers like the Agent's Executor to reliably classify failures using type
// assertions (e.g., errors.As) instead of brittle string matching.

// ElementNotFoundError is a specific, typed error for when a selector does not match any element.
type ElementNotFoundError struct {
	Selector string
}

// Error implements the error interface by formatting the message on the fly.
func (e *ElementNotFoundError) Error() string {
	return fmt.Sprintf("element not found matching selector '%s'", e.Selector)
}

// NewElementNotFoundError creates a new ElementNotFoundError.
func NewElementNotFoundError(selector string) *ElementNotFoundError {
	return &ElementNotFoundError{
		Selector: selector,
	}
}

// NavigationError represents a failure during a page navigation attempt.
type NavigationError struct {
	URL     string
	Message string
	Err     error // Underlying network or protocol error
}

// Error implements the error interface.
func (e *NavigationError) Error() string {
	return e.Message
}

// Unwrap provides the underlying error for use with errors.Is/As.
func (e *NavigationError) Unwrap() error {
	return e.Err
}