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
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Helper to run the PersistentPreRunE logic for a test.
// It assumes that the test has already called resetForTest and set up its environment.
func runPreRun(t *testing.T, cmd *cobra.Command) error {
	t.Helper()
	return cmd.PersistentPreRunE(cmd, []string{})
}

func TestInitializeConfig(t *testing.T) {

	t.Run("FromFile", func(t *testing.T) {
		// Reset state, then set up the specific conditions for this test.
		resetForTest(t)
		t.Cleanup(func() { resetForTest(t) })

		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "testconfig.yaml")
		configContent := `
logger:
  level: debug
database:
  url: 'file-db-url'`
		err := os.WriteFile(configPath, []byte(configContent), 0600)
		require.NoError(t, err)
		// Set the global cfgFile which will be read by initializeConfig.
		cfgFile = configPath

		// Run the PreRun hook from the now-configured global rootCmd.
		err = runPreRun(t, rootCmd)
		require.NoError(t, err)

		cfg := config.Get()
		require.NotNil(t, cfg)
		assert.Equal(t, "debug", cfg.Logger.Level)
	})

	t.Run("EnvironmentVariables", func(t *testing.T) {
		resetForTest(t)
		t.Cleanup(func() { resetForTest(t) })

		// Set env vars which will be read by initializeConfig.
		t.Setenv("SCALPEL_LOGGER_LEVEL", "error")
		t.Setenv("SCALPEL_DATABASE_URL", "env_db_url")

		err := runPreRun(t, rootCmd)
		require.NoError(t, err)

		cfg := config.Get()
		require.NotNil(t, cfg)
		assert.Equal(t, "error", cfg.Logger.Level)
		assert.Equal(t, "env_db_url", cfg.Database.URL)
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

		cfg := config.Get()
		require.NotNil(t, cfg)
		assert.Equal(t, "warn", cfg.Logger.Level)
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
		// Set the global validateFix which is checked by the PreRun hook.
		validateFix = true

		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)

		err := runPreRun(t, rootCmd)
		require.NoError(t, err)

		assert.Equal(t, 0, exitCode, "Expected os.Exit(0) to be called")
		assert.Contains(t, buf.String(), "===[ VALIDATION RUN PASSED ]===")
	})
}
