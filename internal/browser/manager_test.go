package browser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManager(t *testing.T) {
	t.Run("InitializeAndCloseSession", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)

		require.NotNil(t, fixture.Session)
		require.NotEmpty(t, fixture.Session.ID(), "Session ID should not be empty")
	})

	t.Run("InitializeMultipleSessions", func(t *testing.T) {
		t.Parallel()
		fixture1 := newTestFixture(t)
		require.NotNil(t, fixture1.Session)

		fixture2 := newTestFixture(t)
		require.NotNil(t, fixture2.Session)

		require.NotEqual(t, fixture1.Session.ID(), fixture2.Session.ID(), "Each session should have a unique ID")
	})
}
