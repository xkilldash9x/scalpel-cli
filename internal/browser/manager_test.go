// manager_test.go
package browser_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManager_InitializeAndCloseSession(t *testing.T) {
	t.Parallel()
	fixture, cleanup := newTestFixture(t)
	defer cleanup()

	require.NotNil(t, fixture.Session)
	require.NotEmpty(t, fixture.Session.ID(), "Session ID should not be empty")
}

func TestManager_InitializeMultipleSessions(t *testing.T) {
	t.Parallel()

	fixture1, cleanup1 := newTestFixture(t)
	defer cleanup1()
	require.NotNil(t, fixture1.Session)

	fixture2, cleanup2 := newTestFixture(t)
	defer cleanup2()
	require.NotNil(t, fixture2.Session)

	require.NotEqual(t, fixture1.Session.ID(), fixture2.Session.ID(), "Each session should have a unique ID")
}