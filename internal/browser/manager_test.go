package browser_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManager_InitializeAndCloseSession(t *testing.T) {
	fixture, cleanup := newTestFixture(t)
	t.Parallel()
	defer cleanup()

	require.NotNil(t, fixture.Session)
	require.NotEmpty(t, fixture.Session.ID(), "Session ID should not be empty")
}

func TestManager_InitializeMultipleSessions(t *testing.T) {
	fixture1, cleanup1 := newTestFixture(t)
	t.Parallel() // This test function will run in parallel with others.
	defer cleanup1()
	require.NotNil(t, fixture1.Session)

	// This second fixture is created sequentially within this test function.
	fixture2, cleanup2 := newTestFixture(t)
	defer cleanup2()
	require.NotNil(t, fixture2.Session)

	require.NotEqual(t, fixture1.Session.ID(), fixture2.Session.ID(), "Each session should have a unique ID")
}
