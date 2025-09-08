package reporting

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// -- Test Cases: Factory Function (New) --

// Verifies that providing a nil logger to the factory function results in an error.
func TestNew_LoggerRequirement(t *testing.T) {
	reporter, err := New("sarif", "stdout", nil)
	assert.Error(t, err)
	assert.Nil(t, reporter)
	assert.Contains(t, err.Error(), "logger cannot be nil")
}

// Verifies the factory correctly creates a SARIFReporter that targets a file.
func TestNew_SupportedFormat_SARIF_File(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test_report.sarif")

	// Execute
	reporter, err := New("sarif", outputPath, logger)
	require.NoError(t, err)
	require.NotNil(t, reporter)

	// Verify the concrete type (White box testing)
	sarifReporter, ok := reporter.(*SARIFReporter)
	assert.True(t, ok, "Factory should return a SARIFReporter instance")

	// White box check: Verify the writer is an actual file handle (*os.File)
	_, ok = sarifReporter.writer.(*os.File)
	assert.True(t, ok, "Writer should be an *os.File when targeting a file path")

	// Ensure the file was created and the reporter closes it correctly
	assert.FileExists(t, outputPath)
	err = reporter.Close()
	assert.NoError(t, err, "Reporter closing should succeed")
}

// Verifies that the reporter can be configured to write to standard output.
func TestNew_Output_Stdout(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tests := []struct {
		name       string
		outputPath string
	}{
		{"Empty Path", ""},
		{"Explicit Stdout", "stdout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter, err := New("sarif", tt.outputPath, logger)
			require.NoError(t, err)

			// White box inspection
			sarifReporter, ok := reporter.(*SARIFReporter)
			require.True(t, ok)

			// Verify the internal writer is the nopWriteCloser wrapping os.Stdout
			nwc, ok := sarifReporter.writer.(*nopWriteCloser)
			require.True(t, ok, "Writer should be a nopWriteCloser when outputting to stdout")
			assert.Equal(t, os.Stdout, nwc.Writer, "The underlying writer should be os.Stdout")

			// Verify that closing the reporter does NOT close os.Stdout.
			err = reporter.Close()
			assert.NoError(t, err)
		})
	}
}

// Verifies error handling and cleanup for formats that are unknown or not yet implemented.
func TestNew_UnsupportedAndUnimplementedFormats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()

	tests := []struct {
		format      string
		expectError string
	}{
		{"json", "json reporter not yet implemented"},
		{"text", "text reporter not yet implemented"},
		{"xml", "unsupported output format: xml"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Format_%s", tt.format), func(t *testing.T) {
			outputPath := filepath.Join(tmpDir, fmt.Sprintf("report_%s.out", tt.format))
			reporter, err := New(tt.format, outputPath, logger)

			assert.Nil(t, reporter)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)

			// Robustness Check: Ensure the factory cleans up the file handle.
			// The file should exist because os.Create runs before the switch statement,
			// but the cleanup() function ensures the handle is closed.
			if info, err := os.Stat(outputPath); err != nil {
				t.Fatalf("File should exist even if reporter creation failed later: %v", err)
			} else {
				assert.Equal(t, int64(0), info.Size(), "File should be empty upon factory error")
			}
		})
	}
}

// Verifies error handling when the output file can't be created.
func TestNew_Failure_FileCreation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	// Scenario: Attempting to write to an invalid path (e.g., using a directory path as a filename)
	tmpDir := t.TempDir()

	reporter, err := New("sarif", tmpDir, logger)

	assert.Nil(t, reporter)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create output file")
}

// -- Test Cases: Utilities --

// Verifies the nopWriteCloser wrapper does its job, which is mostly nothing on Close.
func TestNopWriteCloser(t *testing.T) {
	mockWriter := new(bytes.Buffer)
	nwc := &nopWriteCloser{mockWriter}

	// Test Write functionality (passthrough)
	data := []byte("hello")
	n, err := nwc.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, "hello", mockWriter.String())

	// Test Close functionality (no-op)
	err = nwc.Close()
	assert.NoError(t, err, "Close should always return nil")

	// Verify we can still write after "closing"
	nwc.Write([]byte(" world"))
	assert.Equal(t, "hello world", mockWriter.String())
}
