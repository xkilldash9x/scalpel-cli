// File: cmd/root_test.go
package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to run the PersistentPreRunE logic for a test.
func runPreRun(t *testing.T, cmd *cobra.Command) error {
	t.Helper()
	return cmd.PersistentPreRunE(cmd, []string{})
}

func TestInitializeConfig(t *testing.T) {

	t.Run("FromFile", func(t *testing.T) {
		resetForTest(t)
		t.Cleanup(func() { resetForTest(t) })

		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "testconfig.yaml")
		configContent := `
logger:
  level: debug
database:
  url: 'file-db-url'` // This URL will satisfy the validation
		err := os.WriteFile(configPath, []byte(configContent), 0600)
		require.NoError(t, err)
		cfgFile = configPath // Set the global flag variable used by initializeConfig

		// Execute the PreRun hook which loads and validates the config
		err = runPreRun(t, rootCmd)
		require.NoError(t, err, "PreRun should succeed with a valid config file")

		// Retrieve the config from the command's context, not a global singleton.
		cfg, err := getConfigFromContext(rootCmd.Context())
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "debug", cfg.Logger().Level)
		assert.Equal(t, "file-db-url", cfg.Database().URL)
	})

	t.Run("EnvironmentVariables", func(t *testing.T) {
		resetForTest(t)
		t.Cleanup(func() { resetForTest(t) })

		t.Setenv("SCALPEL_LOGGER_LEVEL", "error")
		t.Setenv("SCALPEL_DATABASE_URL", "env_db_url") // This satisfies the validation

		err := runPreRun(t, rootCmd)
		require.NoError(t, err)

		cfg, err := getConfigFromContext(rootCmd.Context())
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "error", cfg.Logger().Level)
		assert.Equal(t, "env_db_url", cfg.Database().URL)
	})
}

func TestRootCmd_PersistentPreRunE(t *testing.T) {

	t.Run("Success", func(t *testing.T) {
		resetForTest(t)
		t.Cleanup(func() { resetForTest(t) })

		t.Setenv("SCALPEL_LOGGER_LEVEL", "warn")
		t.Setenv("SCALPEL_DATABASE_URL", "dummy-url-for-validation")

		err := runPreRun(t, rootCmd)
		require.NoError(t, err)

		cfg, err := getConfigFromContext(rootCmd.Context())
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "warn", cfg.Logger().Level)
	})

	t.Run("ValidateFixFlag", func(t *testing.T) {
		resetForTest(t)
		t.Cleanup(func() { resetForTest(t) })

		var exitCode int = -1
		osExit = func(code int) {
			exitCode = code
		}
		defer func() { osExit = os.Exit }()

		t.Setenv("SCALPEL_DATABASE_URL", "dummy-url-for-validation")
		validateFix = true

		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)

		err := runPreRun(t, rootCmd)
		require.NoError(t, err)

		assert.Equal(t, 0, exitCode, "Expected os.Exit(0) to be called")
		assert.Contains(t, buf.String(), "===[ VALIDATION RUN PASSED ]===")
	})
}
