package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Logger handles console + file logging
type Logger struct {
	logDir    string
	logFile   *os.File
	writeFile bool
}

// NewLogger initializes the logger
func NewLogger(logDir string) *Logger {
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0755)
	}

	// Open a daily rotating log file
	logFilePath := filepath.Join(logDir, fmt.Sprintf("agent_%s.log", time.Now().Format("20060102")))
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	writeFile := (err == nil)

	return &Logger{logDir: logDir, logFile: f, writeFile: writeFile}
}

// log is the shared logging function
func (l *Logger) log(level string, format string, a ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, a...)
	line := fmt.Sprintf("%s [%s] %s\n", timestamp, level, msg)

	// Print to console
	fmt.Print(line)

	// Also write to file if available
	if l.writeFile && l.logFile != nil {
		l.logFile.WriteString(line)
	}
}

// Infof logs an info-level message
func (l *Logger) Infof(format string, a ...interface{}) {
	l.log("INFO", format, a...)
}

// Errorf logs an error-level message
func (l *Logger) Errorf(format string, a ...interface{}) {
	l.log("ERROR", format, a...)
}

// WriteJSON writes structured payloads to JSON files
func WriteJSON(data interface{}, logDir string) error {
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0755)
	}
	filename := filepath.Join(logDir, fmt.Sprintf("certsync_%s.json", time.Now().Format("20060102")))
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, bytes, 0644)
}
