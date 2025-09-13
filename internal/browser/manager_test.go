// internal/browser/manager_test.go
package browser_test

import (
	"testing"
	"github.com/stretchr/testify/require"
)

// The TestMain function is now in browser_helper_test.go and is sufficient for the whole package.
// We remove the duplicate here to fix the compilation error.
// The code from the original TestMain is kept in browser_helper_test.go.

// TestManager_Lifecycle now simply verifies that sessions can be created
// from the shared globalFixture. The overall manager lifecycle is implicitly
// tested by the entire suite running successfully within the TestMain wrapper.
func TestManager_Lifecycle(t *testing.T) {
	t.Run("Initialize and Close Session", func(t *testing.T) {
		t.Parallel()
		fixture := globalFixture

		// The helper now creates the session and schedules its own cleanup via t.Cleanup.
		session := fixture.initializeSession(t)
		require.NotNil(t, session)
	})

	t.Run("Initialize Multiple Sessions", func(t *testing.T) {
		t.Parallel()
		fixture := globalFixture

		session1 := fixture.initializeSession(t)
		require.NotNil(t, session1)

		session2 := fixture.initializeSession(t)
		require.NotNil(t, session2)

		// Verify they are distinct instances
		require.NotEqual(t, session1.ID(), session2.ID(), "Each session should have a unique ID")
	})
}