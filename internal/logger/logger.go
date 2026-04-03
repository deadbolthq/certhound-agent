package logger

import (
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

	// Print to console (plain — ANSI codes pollute service logs)
	fmt.Print(line)

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

