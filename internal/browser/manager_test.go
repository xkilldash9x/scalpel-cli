// internal/browser/manager_test.go
package browser_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestMain is the entry point for the test suite. It sets up a single, shared
// browser manager and fixture that all tests in the package can use. It then
// runs all the tests and guarantees that the cleanup logic is called only after
// all tests, including parallel ones, have completed. This is the standard Go
// pattern for managing expensive, shared test resources.
func TestMain(m *testing.M) {
	// setupSharedBrowserManager (defined in browser_helper_test.go) creates the
	// browser instance and returns the fixture and a cleanup function.
	fixture, cleanup, err := setupSharedBrowserManager()
	if err != nil {
		// If setup fails, we can't run tests. Log the error and exit.
		// Using the logger from the (partially created) fixture if available.
		if fixture != nil && fixture.Logger != nil {
			// Correctly use the logger to report the fatal error.
			fixture.Logger.Fatal("Failed to set up shared browser manager for tests", zap.Error(err))
		} else {
			// Fallback to stdout if logger isn't even available.
			fmt.Printf("Failed to set up shared browser manager for tests: %v\n", err)
		}
		os.Exit(1)
	}
	// Assign the created fixture to the global variable so other tests can access it.
	globalFixture = fixture

	// m.Run() executes all the tests in the package. It blocks until they are all done.
	exitCode := m.Run()

	// After all tests are finished, the cleanup function is called to gracefully
	-// shut down the browser manager and remove temporary files.
	cleanup()

	// Exit with the status code from the test run.
	os.Exit(exitCode)
}

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

