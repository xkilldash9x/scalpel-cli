// File: cmd/helpers_test.go
package cmd

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// newTestConfig creates a fully populated and layered configuration for use in tests.
// It correctly layers defaults, explicit values, and environment variables.
func newTestConfig(t *testing.T) config.Interface {
	t.Helper()

	// 1. Create a single Viper instance that will hold all config layers.
	v := viper.New()

	// 2. Set all the default values from your config package. This is the base layer.
	config.SetDefaults(v)

	// 3. Set any explicit values for the test environment.
	v.Set("browser.debug", true)
	v.Set("autofix.git.author_name", "Kyle McAllister")
	v.Set("autofix.git.author_email", "xkilldash9x@proton.me")
	v.Set("autofix.github.repo_owner", "xkilldash9x")
	v.Set("autofix.github.repo_name", "scalpel-cli")
	v.Set("network.headers.User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 ScalpelV2/1.0")

	// 4. Set environment variables that the test will use.
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://test:test@localhost/testdb")
	// Set a generic Gemini key for testing env var binding
	t.Setenv("GEMINI_API_KEY", "fake-api-key-for-testing")

	// 5. Configure Viper to automatically read environment variables.
	v.SetEnvPrefix("SCALPEL")
	v.AutomaticEnv()

	// 6. Create the final config object from the layered Viper instance.
	cfg, err := config.NewConfigFromViper(v)
	require.NoError(t, err, "Failed to create new test config from viper")

	return cfg
}

// executeCommandNoPreRun is for testing argument and flag validation without
// triggering the config validation in PersistentPreRunE.
func executeCommandNoPreRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// FIX: Use newPristineRootCmd() (defined in main_test.go) to get an accurate command structure.
	testRootCmd := newPristineRootCmd()

	buf := new(bytes.Buffer)
	testRootCmd.PersistentPreRunE = nil // Disable config loading for simple validation tests.
	testRootCmd.SetOut(buf)
	testRootCmd.SetErr(buf)
	testRootCmd.SetArgs(args)
	err := testRootCmd.ExecuteContext(context.Background())
	return buf.String(), err
}

// createTempConfig helper
func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	_, err = tmpfile.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	return tmpfile.Name()
}

// FIX: The flawed newRootCmd function has been entirely removed.
// Tests now rely on newPristineRootCmd defined in cmd/main_test.go.
