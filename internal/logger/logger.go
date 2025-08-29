package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Logger is a simple logger with console + JSON file
type Logger struct {
	logDir string
}

// NewLogger initializes the logger
func NewLogger(logDir string) *Logger {
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0755)
	}
	return &Logger{logDir: logDir}
}

// Infof prints info messages
func (l *Logger) Infof(format string, a ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", a...)
}

// Errorf prints error messages
func (l *Logger) Errorf(format string, a ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", a...)
}

// WriteJSON writes payload to a timestamped JSON file
func WriteJSON(data interface{}, logDir string) error {
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0755)
	}
	filename := filepath.Join(logDir, fmt.Sprintf("certsync_%s.json", time.Now().Format("20060102_150405")))
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, bytes, 0644)
}
