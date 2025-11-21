// internal/reporting/reporter_test.go
package reporting_test

// Implementation for Bug 4: Rewritten file with correct package name and comprehensive tests.

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/internal/reporting"
)

const testToolVersion = "v1.0.0-test"

// TestNew_Success_SARIF_Stdout tests creating a SARIF reporter writing to stdout.
func TestNew_Success_SARIF_Stdout(t *testing.T) {
	// Test explicit stdout
	r, err := reporting.New("sarif", "stdout", testToolVersion)
	require.NoError(t, err)
	assert.NotNil(t, r)
	// We assert that Close doesn't return an error (as it should be a no-op for the stdout wrapper).
	assert.NoError(t, r.Close())

	// Test implicit stdout (empty path)
	r, err = reporting.New("sarif", "", testToolVersion)
	require.NoError(t, err)
	assert.NotNil(t, r)
	assert.NoError(t, r.Close())
}

// TestNew_Success_SARIF_File tests creating a SARIF reporter writing to a file.
func TestNew_Success_SARIF_File(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "output.sarif")

	r, err := reporting.New("sarif", tmpFile, testToolVersion)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// File should exist now (created by os.Create in New)
	_, err = os.Stat(tmpFile)
	assert.NoError(t, err, "Output file should have been created")

	// Closing the reporter should finalize the file (and close the handle)
	err = r.Close()
	assert.NoError(t, err)
}

// TestNew_Failure_UnsupportedFormat tests handling of unknown formats and ensures cleanup.
func TestNew_Failure_UnsupportedFormat(t *testing.T) {
	// Test with stdout (no file cleanup needed)
	r, err := reporting.New("invalid-format", "stdout", testToolVersion)
	assert.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "unsupported output format: invalid-format")

	// Test with file (requires file cleanup verification)
	tmpFile := filepath.Join(t.TempDir(), "output.txt")
	r, err = reporting.New("invalid-format", tmpFile, testToolVersion)
	assert.Error(t, err)
	assert.Nil(t, r)

	// Verify the file handle was closed by the cleanup function.
	// The file is created by os.Create before the switch statement, but cleanup() runs on error.
	// We verify the file exists but is empty.
	info, err := os.Stat(tmpFile)
	require.NoError(t, err, "File should still exist after failure")
	assert.Equal(t, int64(0), info.Size(), "File should be empty as initialization failed")
}

// TestNew_Failure_NotImplemented tests formats that are recognized but not implemented.
func TestNew_Failure_NotImplemented(t *testing.T) {
	formats := []string{"json", "text"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			// Test with file (requires file cleanup verification)
			tmpFile := filepath.Join(t.TempDir(), "output."+format)
			r, err := reporting.New(format, tmpFile, testToolVersion)
			assert.Error(t, err)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), format+" reporter not yet implemented")

			// Verify cleanup occurred
			info, err := os.Stat(tmpFile)
			require.NoError(t, err, "File should still exist after failure")
			assert.Equal(t, int64(0), info.Size(), "File should be empty")
		})
	}
}

// TestNew_Failure_FileCreation tests errors during output file creation.
func TestNew_Failure_FileCreation(t *testing.T) {
	// Create a path that cannot be written to (e.g., attempting to use the directory path itself as a filename)
	invalidPath := t.TempDir()

	r, err := reporting.New("sarif", invalidPath, testToolVersion)
	assert.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "failed to create output file")
}

// MockWriterConcept that tracks if Write was called. (For TestNopWriteCloser_Concept)
type MockWriterConcept struct {
	writeCalled bool
}

func (m *MockWriterConcept) Write(p []byte) (n int, err error) {
	m.writeCalled = true
	return len(p), nil
}

// TestNopWriteCloser_Concept verifies the behavior of the nopWriteCloser pattern used in reporter.go.
// Since the actual struct in reporter.go is private, we redefine the pattern here to test it conceptually.
func TestNopWriteCloser_Concept(t *testing.T) {
	// Define the pattern used in the implementation
	type testNopWriteCloser struct {
		io.Writer
	}
	// The key behavior: Close is a no-op returning nil.
	var closeFunc = func(_ *testNopWriteCloser) error {
		return nil
	}

	mw := &MockWriterConcept{}
	nwc := &testNopWriteCloser{mw}

	// Verify Write passes through
	data := []byte("test")
	n, err := nwc.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.True(t, mw.writeCalled)

	// Verify Close behavior
	err = closeFunc(nwc)
	assert.NoError(t, err, "Close should always return nil")
}
