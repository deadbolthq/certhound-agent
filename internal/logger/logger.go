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
	level     string
	verbose   bool
}

// Colors for terminal output/logs
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
)

// Singleton instance
var globalLogger *Logger

// Close flushes and closes the underlying log file. Safe to call multiple times.
func (l *Logger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
		l.logFile = nil
	}
}

// ResetForTest tears down the global logger so tests can reinitialise it cleanly.
// Must not be called in production code.
func ResetForTest() {
	if globalLogger != nil {
		globalLogger.Close()
		globalLogger = nil
	}
}

// NewLogger initializes the logger
func NewLogger(logDir string, level string, verbose bool) *Logger {
	if globalLogger != nil {
		return globalLogger
	}
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0755)
	}

	// Open a daily rotating log file
	logFilePath := filepath.Join(logDir, fmt.Sprintf("agent_%s.log", time.Now().Format("20060102")))
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	writeFile := (err == nil)

	globalLogger = &Logger{logDir: logDir, logFile: f, writeFile: writeFile, level: level, verbose: verbose}
	return globalLogger
}

// log is the shared logging function
func (l *Logger) log(level string, format string, a ...interface{}) {
	// Only log if message level >= configured level
	levelPriority := map[string]int{"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
	cfgLevel := l.level
	if cfgLevel == "" {
		cfgLevel = "INFO"
	}
	if levelPriority[level] < levelPriority[cfgLevel] {
		return
	}
	if level == "DEBUG" && !l.verbose {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, a...)
	line := fmt.Sprintf("%s [%s] %s\n", timestamp, level, msg)

	var colored string
	switch level {
	case "INFO":
		colored = ColorGreen + line + ColorReset
	case "ERROR":
		colored = ColorRed + line + ColorReset
	case "DEBUG":
		colored = ColorBlue + line + ColorReset
	case "WARN":
		colored = ColorYellow + line + ColorReset
	default:
		colored = line
	}

	// Print to console
	fmt.Print(colored)

	// Also write to file if available (in plain color text)
	if l.writeFile && l.logFile != nil {
		l.logFile.WriteString(line)
	}
}

// Instance-level helpers
func (l *Logger) Infof(format string, a ...interface{})  { l.log("INFO", format, a...) }
func (l *Logger) Errorf(format string, a ...interface{}) { l.log("ERROR", format, a...) }
func (l *Logger) Warnf(format string, a ...interface{})  { l.log("WARN", format, a...) }
func (l *Logger) Debugf(format string, a ...interface{}) { l.log("DEBUG", format, a...) }

// Package-level helpers (delegate to globalLogger)
func Infof(format string, a ...interface{}) {
	if globalLogger != nil {
		globalLogger.Infof(format, a...)
	}
}
func Errorf(format string, a ...interface{}) {
	if globalLogger != nil {
		globalLogger.Errorf(format, a...)
	}
}
func Warnf(format string, a ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warnf(format, a...)
	}
}
func Debugf(format string, a ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debugf(format, a...)
	}
}

// WriteJSON writes structured payloads to JSON files
func WriteJSON(data interface{}, logDir string) error {
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0755)
	}
	filename := filepath.Join(logDir, fmt.Sprintf("certhound_%s.json", time.Now().Format("20060102")))
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, bytes, 0644)
}
