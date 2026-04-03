package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestLogger creates a logger in a temp dir and ensures the singleton is
// reset before the temp dir is removed (LIFO cleanup order on Windows).
func newTestLogger(t *testing.T, level string, verbose bool) (*Logger, string) {
	t.Helper()
	ResetForTest()
	dir := t.TempDir()             // TempDir cleanup registered first
	t.Cleanup(ResetForTest)        // ResetForTest runs first (LIFO) → closes file before dir removal
	return NewLogger(dir, level, verbose), dir
}

func TestNewLogger_CreatesLogFile(t *testing.T) {
	l, dir := newTestLogger(t, "INFO", false)
	l.Infof("hello test")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Error("expected a log file to be created in logDir")
	}
}

func TestNewLogger_Singleton(t *testing.T) {
	ResetForTest()
	dir := t.TempDir()
	t.Cleanup(ResetForTest)

	l1 := NewLogger(dir, "INFO", false)
	l2 := NewLogger(dir, "DEBUG", true)
	if l1 != l2 {
		t.Error("NewLogger should return the same instance on subsequent calls")
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	l, dir := newTestLogger(t, "WARN", false)

	l.Infof("should not appear")
	l.Debugf("should not appear")
	l.Warnf("warn message")
	l.Errorf("error message")

	logFile := findLogFile(t, dir)
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	s := string(content)
	if strings.Contains(s, "should not appear") {
		t.Error("INFO/DEBUG messages should be filtered at WARN level")
	}
	if !strings.Contains(s, "warn message") {
		t.Error("WARN message should be present")
	}
	if !strings.Contains(s, "error message") {
		t.Error("ERROR message should be present")
	}
}

func TestLogger_Close(t *testing.T) {
	l, _ := newTestLogger(t, "INFO", false)
	l.Infof("before close")
	l.Close()
	// Closing again must not panic
	l.Close()
}

func TestResetForTest_AllowsReinit(t *testing.T) {
	ResetForTest()

	dir1 := t.TempDir()
	l1 := NewLogger(dir1, "INFO", false)
	l1.Infof("first logger")
	ResetForTest() // closes file in dir1

	dir2 := t.TempDir()
	t.Cleanup(ResetForTest)
	l2 := NewLogger(dir2, "INFO", false)
	l2.Infof("second logger")

	if l1 == l2 {
		t.Error("after reset, NewLogger should return a fresh instance")
	}
	if findLogFile(t, dir2) == "" {
		t.Error("second logger should write to dir2")
	}
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	data := map[string]string{"key": "value"}
	if err := WriteJSON(data, dir); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Error("WriteJSON should create a JSON file")
	}
}

func findLogFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}
