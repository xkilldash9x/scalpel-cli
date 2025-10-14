// File: cmd/root_test.go
package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRootCmd_VersionFlag tests if the --version flag works correctly.
func TestRootCmd_VersionFlag(t *testing.T) {
	// The user's original `root_test.go` file contained the source code for `root.go`,
	// which causes a "redeclared in this block" error. This file should contain tests.
	//
	// This test provides a basic example for testing the root command.

	// Arrange
	// We use the newPristineRootCmd from main_test.go to get a clean command instance.
	testRootCmd := newPristineRootCmd()
	var out bytes.Buffer
	testRootCmd.SetOut(&out)
	testRootCmd.SetErr(&out)
	testRootCmd.SetArgs([]string{"--version"})

	// Act
	err := testRootCmd.ExecuteContext(context.Background())

	// Assert
	require.NoError(t, err)
	// The default version is "Alpha".
	assert.Contains(t, out.String(), "scalpel-cli version Alpha")
}

// TestRootCmd_NoArgs tests the behavior when no arguments are provided.
func TestRootCmd_NoArgs(t *testing.T) {
	// Arrange
	testRootCmd := newPristineRootCmd()
	var out bytes.Buffer
	testRootCmd.SetOut(&out)
	testRootCmd.SetErr(&out)
	testRootCmd.SetArgs([]string{})

	// Act
	err := testRootCmd.ExecuteContext(context.Background())

	// Assert
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Scalpel is an AI-native security scanner.")
}
