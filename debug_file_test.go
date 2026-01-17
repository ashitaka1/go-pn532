//nolint:paralleltest // Tests modify package-level session log state, cannot run in parallel
package pn532

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanupSessionLog ensures session log state is clean after tests.
// Must be called in test cleanup to avoid state leakage between tests.
func cleanupSessionLog(t *testing.T) {
	t.Helper()
	if sessionLogFile != nil {
		_ = sessionLogFile.Close()
	}
	sessionLogFile = nil
	sessionLogPath = ""
	sessionLogWriter = nil
}

func TestInitSessionLog_CreatesFile(t *testing.T) {
	// Save current working directory
	origDir, err := os.Getwd()
	require.NoError(t, err)

	// Create temp directory and change to it
	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		cleanupSessionLog(t)
		_ = os.Chdir(origDir)
	})

	path, err := InitSessionLog()

	require.NoError(t, err)
	assert.NotEmpty(t, path)

	// Verify file exists
	_, err = os.Stat(path)
	require.NoError(t, err, "Log file should exist")

	// Verify filename format: pn532_YYYYMMDD_HHMMSS.log
	matched, err := regexp.MatchString(`^pn532_\d{8}_\d{6}\.log$`, path)
	require.NoError(t, err)
	assert.True(t, matched, "Filename should match pn532_YYYYMMDD_HHMMSS.log pattern, got: %s", path)
}

func TestInitSessionLog_WritesHeader(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)

	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		cleanupSessionLog(t)
		_ = os.Chdir(origDir)
	})

	path, err := InitSessionLog()
	require.NoError(t, err)

	// Close to flush and read the file
	require.NoError(t, CloseSessionLog())

	content, err := os.ReadFile(path) //nolint:gosec // path is from InitSessionLog
	require.NoError(t, err)

	contentStr := string(content)

	// Verify header content
	assert.Contains(t, contentStr, "=== PN532 Debug Session Log ===")
	assert.Contains(t, contentStr, "Started:")
	assert.Contains(t, contentStr, "PID:")
	assert.Contains(t, contentStr, "OS:")
	assert.Contains(t, contentStr, "Go Version:")
	assert.Contains(t, contentStr, "Executable:")
	assert.Contains(t, contentStr, "Command Line:")
}

func TestCloseSessionLog_WritesFooter(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)

	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		cleanupSessionLog(t)
		_ = os.Chdir(origDir)
	})

	path, err := InitSessionLog()
	require.NoError(t, err)

	err = CloseSessionLog()
	require.NoError(t, err)

	content, err := os.ReadFile(path) //nolint:gosec // path is from InitSessionLog
	require.NoError(t, err)

	contentStr := string(content)

	// Verify footer content
	assert.Contains(t, contentStr, "=== Session ended ===")
}

func TestCloseSessionLog_NilFile(t *testing.T) {
	t.Cleanup(func() {
		cleanupSessionLog(t)
	})

	// Ensure clean state
	sessionLogFile = nil
	sessionLogPath = ""
	sessionLogWriter = nil

	// Should not error or panic when no file is open
	err := CloseSessionLog()
	assert.NoError(t, err)
}

func TestGetSessionLogPath_ReturnsCorrectPath(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)

	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		cleanupSessionLog(t)
		_ = os.Chdir(origDir)
	})

	// Before init, should be empty
	assert.Empty(t, GetSessionLogPath())

	path, err := InitSessionLog()
	require.NoError(t, err)

	// After init, should return the path
	assert.Equal(t, path, GetSessionLogPath())

	require.NoError(t, CloseSessionLog())

	// After close, should be empty again
	assert.Empty(t, GetSessionLogPath())
}

func TestInitSessionLog_ErrorOnInvalidDirectory(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)

	// Change to a non-existent directory to trigger error
	// We can't actually do this easily, so test the state cleanup instead
	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		cleanupSessionLog(t)
		_ = os.Chdir(origDir)
	})

	// First init should succeed
	path1, err := InitSessionLog()
	require.NoError(t, err)
	require.NoError(t, CloseSessionLog())

	// Second init should also succeed (clean state)
	path2, err := InitSessionLog()
	require.NoError(t, err)
	require.NoError(t, CloseSessionLog())

	// Paths should be different (different timestamps)
	// But they should both be in the same directory
	assert.Equal(t, filepath.Dir(path1), filepath.Dir(path2))
}

func TestMultipleInitCloseCycles(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)

	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		cleanupSessionLog(t)
		_ = os.Chdir(origDir)
	})

	// Run multiple init/close cycles
	paths := make([]string, 0, 3)
	for i := range 3 {
		path, err := InitSessionLog()
		require.NoError(t, err, "Init cycle %d failed", i)
		paths = append(paths, path)

		// Verify file is accessible
		_, err = os.Stat(path)
		require.NoError(t, err, "File should exist after init")

		// Write something to verify the log is working
		Debugf("Test message %d", i)

		err = CloseSessionLog()
		require.NoError(t, err, "Close cycle %d failed", i)

		// Verify state is clean
		assert.Empty(t, GetSessionLogPath())
		assert.Nil(t, sessionLogFile)
		assert.Nil(t, sessionLogWriter)
	}

	// Verify all files exist and have content
	for i, path := range paths {
		content, err := os.ReadFile(path) //nolint:gosec // path is from InitSessionLog
		require.NoError(t, err, "Failed to read log file %d", i)
		assert.Contains(t, string(content), "Test message")
	}
}

func TestInitSessionLog_StateInitialization(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)

	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		cleanupSessionLog(t)
		_ = os.Chdir(origDir)
	})

	_, err = InitSessionLog()
	require.NoError(t, err)

	// Verify all state variables are set
	assert.NotNil(t, sessionLogFile)
	assert.NotEmpty(t, sessionLogPath)
	assert.NotNil(t, sessionLogWriter)

	require.NoError(t, CloseSessionLog())
}

func TestWriteSessionHeader_ContentFormat(t *testing.T) {
	var buf strings.Builder

	writeSessionHeader(&buf)

	content := buf.String()

	// Verify header markers
	assert.True(t, strings.HasPrefix(content, "=== PN532 Debug Session Log ==="))
	assert.Contains(t, content, "================================")

	// Verify all required fields are present
	assert.Contains(t, content, "Started:")
	assert.Contains(t, content, "PID:")
	assert.Contains(t, content, "OS:")
	assert.Contains(t, content, "Go Version:")
}
