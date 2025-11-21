package agent

import (
	"sync"
	"time"
)

// waitTimeout is a helper that waits for a WaitGroup to finish but with a specified timeout.
// It's a handy way to prevent tests from hanging indefinitely.
// Returns true if the wait group finishes in time, false otherwise.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	// Channel to signal completion.
	completionChannel := make(chan struct{})

	// Fire off a goroutine to wait on the WaitGroup.
	go func() {
		defer close(completionChannel)
		wg.Wait()
	}()

	// Wait for either the completion signal or the timeout.
	select {
	case <-completionChannel:
		return true // Nailed it, completed in time.
	case <-time.After(timeout):
		return false // Whoops, timed out.
	}
}
