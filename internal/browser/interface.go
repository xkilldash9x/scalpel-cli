package browser

// SessionLifecycleObserver defines the contract for an entity that manages
// the lifecycle of browser sessions. It allows a session to signal back when
// it has been closed, so that the owner can free up associated resources.
type SessionLifecycleObserver interface {
	unregisterSession(*AnalysisContext)
}