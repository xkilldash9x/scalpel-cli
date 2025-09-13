package schemas_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// -- Test Helpers --

// getTestTime provides a fixed, reproducible timestamp for consistent test results.
func getTestTime(t *testing.T) time.Time {
	// Using RFC3339Nano ensures maximum precision, and UTC avoids timezone issues.
	ts, err := time.Parse(time.RFC3339Nano, "2025-10-26T10:00:00.123456789Z")
	require.NoError(t, err, "Test setup failed: unable to parse fixed timestamp")
	return ts
}
